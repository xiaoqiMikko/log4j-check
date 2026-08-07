package dev.mikko.log4jcheck;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 扫描构建产物,找出实际装了哪些 log4j 模块及其版本。
 *
 * <p>🔴 <b>为什么必须逐模块扫,而不是只扫 log4j-core</b> —— 本批 7 条散布在
 * <b>4 个模块</b>上,而这四个模块的版本<b>可以不一致</b>:
 * {@code log4j-api} 通常靠 {@code log4j-core} 传递进来,但只要有人在
 * {@code dependencyManagement} 里单独钉过 {@code log4j-api} 的版本、
 * 或某个第三方 BOM 覆盖了它,两者就会错开。此时「我升了 log4j-core 到 2.25.4」
 * 完全不代表 {@code log4j-api} 也到了 2.25.5 —— 而 {@code CVE-2026-49844} 挂在后者上。
 *
 * <p>🔴 <b>为什么必须扫产物而不是读 pom</b> —— shade / uber jar 会把 log4j 的类
 * 直接打进自己的 jar,依赖坐标层面完全看不见,但 {@code maven-shade-plugin}
 * 默认保留 {@code META-INF/maven/**},所以扫实物能把这层看穿,读 pom 不能。
 *
 * <p>另外会顺手认出 <b>log4j 1.x</b>({@code log4j:log4j})并给一句告警:
 * 它是另一套东西,本工具不覆盖 —— 不说的话,用户看到「没发现问题」会以为把它也查过了。
 */
public final class Scanner {

    /** log4j 1.x 的坐标。本工具不覆盖它,但要认出来并说清楚。 */
    private static final String LEGACY_COORD = "log4j:log4j";

    private static final Pattern NAME_VER = Pattern.compile(
            "^(log4j-(?:api|core|1\\.2-api|layout-template-json))-(\\d[\\w.\\-]*)\\.jar$",
            Pattern.CASE_INSENSITIVE);

    /**
     * 扫到的一份 log4j 模块。
     *
     * @param path    它在哪(归档内的用 {@code !/} 分隔)
     * @param module  artifactId,如 {@code log4j-core}
     * @param version 版本
     * @param source  版本取自哪里:pom.properties / MANIFEST / 文件名
     */
    public record Artifact(String path, String module, Log4jVersion version, String source) {
        public String coord() {
            return CveTable.GROUP + ":" + module;
        }
    }

    private final List<Artifact> found = new ArrayList<>();
    private final List<String> warnings = new ArrayList<>();

    public List<Artifact> artifacts() {
        return found;
    }

    public List<String> warnings() {
        return warnings;
    }

    public void scan(Path target) throws IOException {
        if (!Files.exists(target)) {
            warnings.add("路径不存在:" + target);
            return;
        }
        if (Files.isDirectory(target)) {
            Files.walkFileTree(target, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path f, BasicFileAttributes a) {
                    String n = f.getFileName().toString().toLowerCase(Locale.ROOT);
                    if (n.endsWith(".jar") || n.endsWith(".war") || n.endsWith(".ear")) {
                        scanFile(f);
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path f, IOException e) {
                    warnings.add("无法访问 " + f + ":" + e.getMessage());
                    return FileVisitResult.CONTINUE;
                }
            });
        } else {
            scanFile(target);
        }
    }

    private void scanFile(Path f) {
        byte[] bytes;
        try {
            bytes = Files.readAllBytes(f);
        } catch (IOException e) {
            warnings.add("读取失败 " + f + ":" + e.getMessage()
                    + "(🔴 这不等于「里面没有 log4j」)");
            return;
        }
        // 归档自身也可能就是一个 log4j 模块的 jar,所以先按它自己的路径认一次
        identify(f.toString(), bytes);
        int entries = Archives.walk(f.toString(), bytes, Archives.DEFAULT_DEPTH,
                (path, data) -> {
                    String lower = path.toLowerCase(Locale.ROOT);
                    if (lower.endsWith("/pom.properties")) {
                        fromPomProperties(path, data);
                    } else if (lower.endsWith(".jar")) {
                        identify(path, data);
                    }
                },
                warnings::add);
        // 🔴 不是有效 zip 的文件会解出 0 个条目且**不抛异常** —— 实测确认过。
        //    不报出来的话,「这个 jar 坏了」会表现成「这个 jar 里没有 log4j」。
        Archives.warnIfEmpty(f.toString(), entries, warnings::add);
    }

    /**
     * 认一个 jar 是不是 log4j 模块。
     *
     * <p>来源优先级:{@code META-INF/maven/**\/pom.properties}(坐标和版本都是直接读到的,
     * 最可靠)&gt; MANIFEST 的 {@code Bundle-SymbolicName} / {@code Implementation-Version}
     * &gt; 文件名。前两者在 jar 被改名时依然正确,文件名会骗人。
     */
    private void identify(String path, byte[] bytes) {
        final boolean[] gotCoord = {false};
        final String[] mf = new String[2];         // [SymbolicName, Version]
        Archives.walk(path, bytes, 0, (p, data) -> {
            String lower = p.toLowerCase(Locale.ROOT);
            if (lower.endsWith("/pom.properties")) {
                if (fromPomProperties(p, data)) {
                    gotCoord[0] = true;
                }
            } else if (lower.endsWith("meta-inf/manifest.mf")) {
                String[] r = readManifest(data);
                mf[0] = r[0];
                mf[1] = r[1];
            }
        }, warnings::add);
        if (gotCoord[0]) {
            return;
        }
        // 没有 pom.properties(被重打包过或极老的构建)—— 退回 MANIFEST
        if (mf[0] != null) {
            for (String m : CveTable.MODULES) {
                if (mf[0].equals(CveTable.GROUP + "." + m) || mf[0].equals(m)) {
                    Log4jVersion v = Log4jVersion.parse(mf[1]);
                    if (v == null) {
                        v = versionFromName(path);
                    }
                    if (v == null) {
                        warnings.add("识别出 " + CveTable.GROUP + ":" + m + " 但取不到版本号:"
                                + path + "(🔴 这不等于「没有漏洞」,请手工确认版本)");
                        return;
                    }
                    add(new Artifact(path, m, v, "MANIFEST"));
                    return;
                }
            }
        }
        // 最后退回文件名
        String base = path.substring(Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\')) + 1);
        Matcher nm = NAME_VER.matcher(base);
        if (nm.matches()) {
            Log4jVersion v = Log4jVersion.parse(nm.group(2));
            if (v == null) {
                warnings.add("文件名像 " + nm.group(1) + " 但版本号无法解析:" + base
                        + "(🔴 这不等于「没有漏洞」,请手工确认版本)");
                return;
            }
            add(new Artifact(path, nm.group(1).toLowerCase(Locale.ROOT), v, "文件名"));
            return;
        }
        if (base.toLowerCase(Locale.ROOT).matches("^log4j-1\\.2\\.\\d+\\.jar$")
                || base.toLowerCase(Locale.ROOT).matches("^log4j-1\\.\\d+(\\.\\d+)?\\.jar$")) {
            warnings.add("扫到 log4j 1.x(" + base + ")—— **本工具不覆盖 log4j 1.x**,"
                    + "它是另一套代码,请另行处理(1.x 早已 EOL)");
        }
    }

    /** @return true = 这个 pom.properties 是我们关心的 log4j 模块 */
    private boolean fromPomProperties(String path, byte[] data) {
        Properties p = new Properties();
        try {
            p.load(new ByteArrayInputStream(data));
        } catch (IOException | IllegalArgumentException e) {
            return false;
        }
        String g = p.getProperty("groupId");
        String a = p.getProperty("artifactId");
        String v = p.getProperty("version");
        if (g == null || a == null) {
            return false;
        }
        if (LEGACY_COORD.equals(g + ":" + a)) {
            warnings.add("扫到 log4j 1.x(" + g + ":" + a + ":" + v + ")—— "
                    + "**本工具不覆盖 log4j 1.x**,它是另一套代码,请另行处理(1.x 早已 EOL)");
            return false;
        }
        if (!CveTable.GROUP.equals(g) || !CveTable.MODULES.contains(a)) {
            return false;
        }
        Log4jVersion ver = Log4jVersion.parse(v);
        if (ver == null) {
            warnings.add("在 " + path + " 里读到 " + g + ":" + a
                    + " 但版本号无法解析:" + v
                    + "(🔴 这不等于「没有漏洞」,请手工确认版本)");
            return true;                  // 认出来了,只是版本读不出 —— 别再退回文件名去猜
        }
        // 归档路径形如 xxx.jar!/META-INF/maven/g/a/pom.properties —— 证据指到那个 jar 更有用
        int bang = path.indexOf("!/META-INF/");
        add(new Artifact(bang > 0 ? path.substring(0, bang) : path, a, ver, "pom.properties"));
        return true;
    }

    /**
     * 只读 MANIFEST 主属性段。
     *
     * <p>⚠️ 第 4 注(bc-check)踩过:签名 jar 的 MANIFEST 可以上兆(每个类一个条目),
     * 整段遍历会撑破缓冲。{@link Manifest} 读主属性即可,不要遍历 entries。
     */
    private static String[] readManifest(byte[] data) {
        try {
            Attributes a = new Manifest(new ByteArrayInputStream(data)).getMainAttributes();
            String sym = a.getValue("Bundle-SymbolicName");
            if (sym != null) {
                int semi = sym.indexOf(';');            // "a.b.c;singleton:=true"
                sym = (semi > 0 ? sym.substring(0, semi) : sym).trim();
            }
            String ver = a.getValue("Implementation-Version");
            if (ver == null) {
                ver = a.getValue("Bundle-Version");
            }
            return new String[]{sym, ver};
        } catch (IOException e) {
            return new String[]{null, null};
        }
    }

    private static Log4jVersion versionFromName(String path) {
        String base = path.substring(Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\')) + 1);
        Matcher m = NAME_VER.matcher(base);
        return m.matches() ? Log4jVersion.parse(m.group(2)) : null;
    }

    /** 同一路径 + 同一模块只记一条(重复上报会让人以为有两个问题 —— 第 5 注教训)。 */
    private void add(Artifact a) {
        for (Artifact x : found) {
            if (x.path().equals(a.path()) && x.module().equals(a.module())) {
                return;
            }
        }
        found.add(a);
    }
}
