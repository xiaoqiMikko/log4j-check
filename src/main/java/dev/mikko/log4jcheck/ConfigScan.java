package dev.mikko.log4jcheck;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * 扫 log4j2 <b>配置</b>与源码里的触发条件,给本批 7 条做 applicability 降噪。
 *
 * <p>这是本工具与「按版本匹配 advisory」的实质差别。Dependabot 只看版本,
 * 装了受影响版本就把 7 条全报;而这 7 条<b>每一条</b>都要求你用了某个特定的
 * layout 或 appender(XmlLayout / Rfc5424Layout / SocketAppender+TLS / JsonTemplateLayout……),
 * 而这些东西恰好都写在配置文件里 —— <b>能读,而且能读准</b>。
 *
 * <p>🔴 <b>比第 9 注前进的一步:降噪不再依赖有没有源码。</b>
 * jackson 的触发条件在注解里,只能扫 {@code .java};log4j 的触发条件在
 * {@code log4j2.xml} 里,而它<b>就打在构件内部</b>({@code BOOT-INF/classes/log4j2.xml}、
 * {@code WEB-INF/classes/log4j2.xml})。所以只丢一个 fat jar 给本工具,降噪也做得成。
 *
 * <h2>两种可靠程度不同的解析,报告里必须分开说</h2>
 * <ul>
 *   <li><b>结构化</b>({@code .xml} / {@code .properties})—— 元素名和属性归属都是**读出来**的。
 *       只有这一档能回答「{@code verifyHostName} 到底挂在 {@code <Ssl>} 上还是挂在 {@code <Http>} 上」,
 *       而这两者<b>分属完全相反的结论</b>:前者中 CVE-2026-34477,后者官方原文写明不受影响。
 *   <li><b>文本匹配</b>({@code .yaml} / {@code .yml} / {@code .json} / {@code .java})——
 *       JDK 里没有 YAML 解析器,而本工具坚持零运行时依赖,所以这几种只能按词匹配。
 *       此时属性名<b>归属不明</b>,记成 {@code ?@属性名},报告里如实标出。
 * </ul>
 *
 * <p>🔴 <b>匹配不到 ≠ 安全。</b>四种情况会让「没找到」变成假的安心:
 * <ol>
 *   <li>配置是**代码里构建**的({@code ConfigurationBuilder}、{@code Configurator.initialize}),
 *       配置文件里根本没有那个元素;
 *   <li>配置在运行时才注入(容器环境变量指向别处的 {@code log4j2.configurationFile});
 *   <li>你依赖的第三方库自带一份 log4j2 配置,而它没被扫到;
 *   <li>你压根没把配置或源码传进来。
 * </ol>
 * 所以「未命中」在报告里的措辞永远是「未在你的配置/源码里找到触发条件」,
 * 而不是「你不受影响」。
 */
public final class ConfigScan {

    /** 构建产物与依赖目录:里面是副本或第三方的东西,扫了会重复计数且不属于「你的配置」。 */
    private static final Set<String> SKIP_DIRS =
            Set.of("target", "build", "out", "bin", ".git", ".idea", "node_modules", ".mvn");

    /** 每个命中最多留几条证据。报告要能读,同时防止超大代码库把内存撑爆。 */
    private static final int MAX_EVIDENCE = 5;

    /** 单个文件大小上限,超过就跳过并告警。 */
    private static final long MAX_FILE_BYTES = 8L * 1024 * 1024;

    /**
     * log4j2 配置文件名。
     *
     * <p>🔴 名字必须按 log4j2 的真实查找规则来,不能只认 {@code log4j2.xml}:
     * 官方支持 {@code log4j2-test.*}(测试优先)、{@code log4j2.*},
     * 以及 {@code log4j2.component.properties};而 Spring Boot 生态里
     * {@code log4j2-spring.xml} 极常见 —— 漏掉它就等于对一大批 Spring Boot 项目
     * 「没扫到配置」,而没扫到和不受影响长得一模一样。
     * 另外 {@code log4j.xml} / {@code log4j.properties}(不带 2)也要认:
     * CVE-2026-34479 的第二种触发方式正是「log4j 1 配置兼容层」。
     *
     * <p>🔴 <b>但 {@code log4j-<后缀>} 这种形式必须排除</b> —— 真实构件复验抓到的:
     * {@code log4j-api} 的 jar 里自带一个 {@code Log4j-charsets.properties},
     * 而第一版正则把它当成了用户的 log4j2 配置。后果不是多打一行日志:
     * 它让 {@link #sawAnyConfig()} 变成 true,于是<b>「本次没看到配置」被翻译成
     * 「看过了,没找到触发条件」</b> —— 两句话该导致完全不同的动作,
     * 而只要 classpath 上有 log4j-api(也就是所有人),这个翻译就一直在发生。
     * 单测用的是自造的假 jar,压根没有那个文件,所以测不出来。
     */
    private static final Pattern CONFIG_NAME = Pattern.compile(
            "^log4j(?:2(?:-[\\w.]+)?)?\\.(xml|properties|ya?ml|json|jsn)$",
            Pattern.CASE_INSENSITIVE);

    /**
     * 🔴 log4j 自己模块 jar 内部的资源一律不算「你的配置」。
     *
     * <p>与上面的名字收紧是**两道独立的闸门**:名字规则挡的是已知的那个文件名,
     * 这一条挡的是「log4j 以后又往自己 jar 里加了个叫 log4j2-什么.properties 的内部资源」——
     * 那种情况名字规则拦不住,而它会以完全相同的方式把结论翻反。
     */
    private static boolean insideLog4jModuleJar(String path) {
        for (String m : CveTable.MODULES) {
            if (path.contains("/" + m + "-") && path.contains(".jar!/")) {
                return true;
            }
            if (path.contains("\\" + m + "-") && path.contains(".jar!/")) {
                return true;
            }
        }
        return false;
    }

    /** 解析模式。 */
    public enum Mode {
        /** XML / properties:元素名与属性归属都是读出来的。 */
        STRUCTURAL,
        /** YAML / JSON / .java:只能按词匹配,属性归属不明。 */
        TEXT
    }

    /**
     * 一处命中。
     *
     * @param file 文件路径(归档内的用 {@code !/} 分隔)
     * @param line 行号(从 1 开始;结构化解析拿不到行号时为 0)
     * @param text 证据文本
     * @param mode 这条证据是哪种解析得出的
     */
    public record Evidence(String file, int line, String text, Mode mode) {
        @Override
        public String toString() {
            return file + (line > 0 ? ":" + line : "") + "  " + text;
        }
    }

    private final Set<String> elements = new LinkedHashSet<>();
    /**
     * 其中<b>由结构化解析读出来</b>的那些元素。
     *
     * <p>🔴 真实构件复验抓到的:第一版把所有 {@code E:} 命中一律当成结构化依据,
     * 于是一份纯 YAML 配置的命中被印成「<b>结构化解析,依据最硬</b>」——
     * 而那份配置从头到尾没有被结构化解析过一次。
     * <b>报告声称了一种从未发生过的解析方式</b>,这比不说更糟:
     * 「依据最硬」这句话本来就是让人决定要不要停下来核对的。
     */
    private final Set<String> elementsStructural = new LinkedHashSet<>();
    /** 结构化读到的属性归属,形如 {@code Ssl@verifyHostName}。 */
    private final Set<String> attrs = new LinkedHashSet<>();
    /** 文本匹配到的属性名,归属不明,形如 {@code ?@verifyHostName}。 */
    private final Set<String> looseAttrs = new LinkedHashSet<>();
    private final Set<String> marks = new LinkedHashSet<>();
    private final Map<String, List<Evidence>> hits = new LinkedHashMap<>();
    private final Map<String, Integer> counts = new LinkedHashMap<>();
    private final List<String> warnings = new ArrayList<>();
    private final List<String> configFiles = new ArrayList<>();
    private int structuredFiles;
    private int textConfigFiles;
    private int sourceFiles;

    public Set<String> elements() {
        return elements;
    }

    public Set<String> attrs() {
        return attrs;
    }

    public Set<String> looseAttrs() {
        return looseAttrs;
    }

    public Set<String> marks() {
        return marks;
    }

    public Map<String, List<Evidence>> hits() {
        return hits;
    }

    public Map<String, Integer> counts() {
        return counts;
    }

    public List<String> warnings() {
        return warnings;
    }

    /** 扫到的 log4j2 配置文件路径。 */
    public List<String> configFiles() {
        return configFiles;
    }

    public int structuredFiles() {
        return structuredFiles;
    }

    public int textConfigFiles() {
        return textConfigFiles;
    }

    public int sourceFiles() {
        return sourceFiles;
    }

    /** 这一轮到底看到过任何 log4j2 配置吗 —— 没有的话降噪结论一律不成立。 */
    public boolean sawAnyConfig() {
        return structuredFiles + textConfigFiles > 0;
    }

    /**
     * 扫到的配置像 log4j2 配置(有 Configuration / Appenders / rootLogger 之类)。
     *
     * <p>用来区分两种完全不同的情况:文件在但不是 log4j2 配置(说明不了任何事)
     * vs 是 log4j2 配置但没用到这批 layout/appender(这才是降噪)。
     */
    public boolean looksLikeLog4j2() {
        return elements.contains(Triggers.ANCHOR);
    }

    public boolean hasElement(String name) {
        return elements.contains(name);
    }

    /** 这个元素是**结构化解析**读出来的(而不是在 YAML/JSON/源码里按词匹到的)。 */
    public boolean hasElementStructural(String name) {
        return elementsStructural.contains(name);
    }

    /** 结构化读到的「这个元素上带这个属性」。只有这一档是准的。 */
    public boolean hasAttr(String elemAtAttr) {
        return attrs.contains(elemAtAttr);
    }

    /** 文本匹配到属性名但归属不明。 */
    public boolean hasLooseAttr(String attr) {
        return looseAttrs.contains("?@" + attr);
    }

    public boolean hasMark(String name) {
        return marks.contains(name);
    }

    // ────────────────────────── 遍历 ──────────────────────────

    public void scan(Path target) throws IOException {
        if (!Files.exists(target)) {
            warnings.add("路径不存在:" + target);
            return;
        }
        if (Files.isRegularFile(target)) {
            String n = target.getFileName().toString().toLowerCase(Locale.ROOT);
            if (n.endsWith(".jar") || n.endsWith(".war") || n.endsWith(".ear")) {
                scanArchive(target);
            } else {
                offerFile(target.toString(), read(target));
            }
            return;
        }
        try {
            Files.walkFileTree(target, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path d, BasicFileAttributes a) {
                    return SKIP_DIRS.contains(d.getFileName().toString().toLowerCase(Locale.ROOT))
                            ? FileVisitResult.SKIP_SUBTREE : FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path f, BasicFileAttributes a) {
                    String n = f.getFileName().toString().toLowerCase(Locale.ROOT);
                    if (n.endsWith(".jar") || n.endsWith(".war") || n.endsWith(".ear")) {
                        scanArchive(f);
                    } else if (n.endsWith(".java") || CONFIG_NAME.matcher(n).matches()) {
                        byte[] b = read(f);
                        if (b != null) {
                            offerFile(f.toString(), b);
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path f, IOException e) {
                    warnings.add("无法访问 " + f + ":" + e.getMessage()
                            + "(🔴 这不等于「它里面没有触发条件」)");
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (UncheckedIOException e) {
            throw e.getCause();
        }
    }

    private byte[] read(Path f) {
        try {
            if (Files.size(f) > MAX_FILE_BYTES) {
                warnings.add("跳过超大文件(> " + (MAX_FILE_BYTES / 1024 / 1024) + "MB):" + f
                        + "(🔴 这不等于「它里面没有触发条件」)");
                return null;
            }
            return Files.readAllBytes(f);
        } catch (IOException e) {
            warnings.add("读取失败 " + f + ":" + e.getMessage()
                    + "(🔴 这不等于「它里面没有触发条件」)");
            return null;
        }
    }

    /**
     * 从归档里找 log4j2 配置。
     *
     * <p>🔴 这是本工具能「只给一个 fat jar 也做得成降噪」的原因:配置就打在
     * {@code BOOT-INF/classes/log4j2.xml} / {@code WEB-INF/classes/log4j2.xml} 里。
     * 归档内的 {@code .java} 一般不存在,所以源码层的标记在这条路径上仍可能缺 ——
     * 报告要分开说,别把「配置扫到了」当成「源码也看过了」。
     */
    private void scanArchive(Path archive) {
        byte[] bytes = read(archive);
        if (bytes == null) {
            return;
        }
        int entries = Archives.walk(archive.toString(), bytes, Archives.DEFAULT_DEPTH,
                (path, data) -> {
                    String base = path.substring(path.lastIndexOf('/') + 1)
                            .toLowerCase(Locale.ROOT);
                    if (CONFIG_NAME.matcher(base).matches() && !insideLog4jModuleJar(path)) {
                        offerFile(path, data);
                    }
                }, warnings::add);
        Archives.warnIfEmpty(archive.toString(), entries, warnings::add);
    }

    /** 按扩展名分派。这是唯一决定「走结构化还是走文本」的地方。 */
    private void offerFile(String path, byte[] data) {
        String lower = path.toLowerCase(Locale.ROOT);
        if (lower.endsWith(".java")) {
            sourceFiles++;
            textScan(path, decode(data), Mode.TEXT, false);
            return;
        }
        String base = path.substring(Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\')) + 1)
                .toLowerCase(Locale.ROOT);
        if (!CONFIG_NAME.matcher(base).matches()) {
            return;
        }
        configFiles.add(path);
        String text = decode(data);
        if (lower.endsWith(".xml")) {
            if (xmlScan(path, data)) {
                structuredFiles++;
            } else {
                // XML 解析失败(不合法 XML、含无法解析的实体……)→ 退回文本匹配。
                // 🔴 必须退回而不是跳过:跳过的话「解析失败」会表现为「没有触发条件」。
                textConfigFiles++;
                textScan(path, text, Mode.TEXT, true);
            }
            return;
        }
        if (lower.endsWith(".properties")) {
            if (propsScan(path, data, text)) {
                structuredFiles++;
            } else {
                textConfigFiles++;
                textScan(path, text, Mode.TEXT, true);
            }
            return;
        }
        // YAML / JSON:JDK 没有解析器,而本工具坚持零运行时依赖 → 文本匹配,并如实标注
        textConfigFiles++;
        textScan(path, text, Mode.TEXT, true);
    }

    /**
     * 🔴 用 UTF-8 且**不抛异常**:配置或注释里的 GBK 字节会让严格解码整个文件失败,
     * 而「一个文件解码失败」不该变成「这个项目没有触发条件」。
     */
    private static String decode(byte[] data) {
        return new String(data, StandardCharsets.UTF_8);
    }

    // ────────────────────────── 结构化:XML ──────────────────────────

    /**
     * DOM 解析 log4j2 的 XML 配置,读出元素名与「元素@属性」。
     *
     * <p>🔴 <b>必须关掉外部实体(XXE)</b>:我们解析的是**别人给的**配置文件,
     * 一个排查安全问题的工具自己被 XXE 打穿会很难看。
     *
     * <p>🔴 <b>strict 模式也要认</b>:log4j2 的 XML 配置有两种写法 ——
     * 简洁式 {@code <Socket .../>} 和严格式 {@code <Appender type="Socket" .../>}。
     * 只认元素名会把严格式的配置整份读成「什么 appender 都没用」。
     *
     * @return true = 解析成功(走结构化);false = 解析失败,调用方需退回文本匹配
     */
    private boolean xmlScan(String path, byte[] data) {
        Element root;
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setExpandEntityReferences(false);
            f.setNamespaceAware(false);
            DocumentBuilder b = f.newDocumentBuilder();
            b.setErrorHandler(null);
            root = b.parse(new ByteArrayInputStream(data)).getDocumentElement();
        } catch (ParserConfigurationException | org.xml.sax.SAXException | IOException e) {
            warnings.add("XML 解析失败,已退回文本匹配 " + path + ":" + e.getMessage()
                    + "(🔴 文本匹配分不清 <Ssl verifyHostName> 和 <Http verifyHostname>)");
            return false;
        }
        if (root == null) {
            return false;
        }
        walkXml(root, path);
        return true;
    }

    private void walkXml(Element e, String path) {
        String name = e.getTagName();
        int colon = name.indexOf(':');
        if (colon >= 0) {
            name = name.substring(colon + 1);          // 去掉命名空间前缀
        }
        noteElement(name, path, 0, "<" + name + ">", Mode.STRUCTURAL);

        NamedNodeMap as = e.getAttributes();
        // strict 模式:<Appender type="Socket"> —— type 的**值**才是插件名
        for (int i = 0; i < as.getLength(); i++) {
            Node a = as.item(i);
            if ("type".equalsIgnoreCase(a.getNodeName())) {
                String v = a.getNodeValue();
                if (v != null && !v.isBlank()) {
                    noteElement(v.trim(), path, 0,
                            "<" + name + " type=\"" + v.trim() + "\">", Mode.STRUCTURAL);
                }
            }
        }
        // 属性归属:元素名可能是简洁式(Ssl)也可能是严格式(type="Ssl"),
        // 所以属性要同时挂到「标签名」和「type 值」上,否则严格式配置的属性会归属不到。
        List<String> owners = new ArrayList<>();
        owners.add(name);
        for (int i = 0; i < as.getLength(); i++) {
            Node a = as.item(i);
            if ("type".equalsIgnoreCase(a.getNodeName()) && a.getNodeValue() != null) {
                owners.add(a.getNodeValue().trim());
            }
        }
        for (int i = 0; i < as.getLength(); i++) {
            Node a = as.item(i);
            String an = a.getNodeName();
            if (!Triggers.attrs().containsKey(an)) {
                continue;
            }
            for (String owner : owners) {
                noteAttr(owner + "@" + an, path, 0,
                        "<" + name + " " + an + "=\"" + a.getNodeValue() + "\">", Mode.STRUCTURAL);
            }
        }

        NodeList kids = e.getChildNodes();
        for (int i = 0; i < kids.getLength(); i++) {
            if (kids.item(i) instanceof Element child) {
                walkXml(child, path);
            }
        }
    }

    // ────────────────────────── 结构化:properties ──────────────────────────

    /**
     * 解析 log4j2 的 properties 配置。
     *
     * <p>规则来自 log4j2 的 properties 格式本身:
     * <ul>
     *   <li>任何 {@code xxx.type = Foo} 的**值**是插件名,{@code xxx} 是它的前缀;
     *   <li>{@code xxx.someAttr = v} 里 {@code someAttr} 是前缀 {@code xxx} 那个插件的属性。
     * </ul>
     * 所以先收集「前缀 → 插件名」,再把属性挂回去 —— 这样才能区分
     * {@code appender.sock.ssl.verifyHostName}(挂在 Ssl 上)和
     * {@code appender.http.verifyHostname}(挂在 Http 上)。
     *
     * @return true = 解析成功
     */
    private boolean propsScan(String path, byte[] data, String text) {
        Properties p = new Properties();
        try {
            p.load(new ByteArrayInputStream(data));
        } catch (IOException | IllegalArgumentException e) {
            warnings.add("properties 解析失败,已退回文本匹配 " + path + ":" + e.getMessage());
            return false;
        }
        Map<String, String> typeOf = new LinkedHashMap<>();
        for (String k : p.stringPropertyNames()) {
            int dot = k.lastIndexOf('.');
            String leaf = dot < 0 ? k : k.substring(dot + 1);
            if ("type".equals(leaf)) {
                String v = p.getProperty(k);
                if (v != null && !v.isBlank()) {
                    typeOf.put(dot < 0 ? "" : k.substring(0, dot), v.trim());
                    noteElement(v.trim(), path, lineOf(text, k), k + " = " + v.trim(),
                            Mode.STRUCTURAL);
                }
            }
        }
        // 上锚:properties 格式里没有 <Configuration> 元素,靠这些顶层键判断它是 log4j2 配置
        for (String k : p.stringPropertyNames()) {
            if (k.startsWith("rootLogger") || k.startsWith("appender")
                    || k.startsWith("appenders") || k.equals("status")) {
                noteElement(Triggers.ANCHOR, path, lineOf(text, k), k, Mode.STRUCTURAL);
                break;
            }
        }
        for (String k : p.stringPropertyNames()) {
            int dot = k.lastIndexOf('.');
            String leaf = dot < 0 ? k : k.substring(dot + 1);
            if (!Triggers.attrs().containsKey(leaf)) {
                continue;
            }
            String prefix = dot < 0 ? "" : k.substring(0, dot);
            String owner = typeOf.get(prefix);
            if (owner == null) {
                // 前缀上没有 type 声明 —— 归属不明,如实记成 ?@属性名 而不是猜一个
                noteLooseAttr(leaf, path, lineOf(text, k), k + " = " + p.getProperty(k), Mode.TEXT);
            } else {
                noteAttr(owner + "@" + leaf, path, lineOf(text, k),
                        k + " = " + p.getProperty(k), Mode.STRUCTURAL);
            }
        }
        return true;
    }

    private static int lineOf(String text, String key) {
        String[] lines = text.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String t = lines[i].trim();
            if (t.startsWith(key) && !t.startsWith("#") && !t.startsWith("!")) {
                return i + 1;
            }
        }
        return 0;
    }

    // ────────────────────────── 文本匹配 ──────────────────────────

    /**
     * 文本匹配。用于 YAML / JSON / {@code .java},以及结构化解析失败时的兜底。
     *
     * @param configLike true = 这是配置文件(要找元素名和属性名);false = 源码(元素名也找,
     *                   因为程序化配置里会直接 new 那些 layout)
     */
    private void textScan(String path, String src, Mode mode, boolean configLike) {
        String[] raw = src.split("\n", -1);
        String[] lines = path.toLowerCase(Locale.ROOT).endsWith(".java")
                ? stripJavaComments(src).split("\n", -1) : raw;

        for (Map.Entry<String, List<Pattern>> e : Triggers.elements().entrySet()) {
            for (Pattern p : e.getValue()) {
                Matcher m = p.matcher("");
                for (int i = 0; i < lines.length; i++) {
                    m.reset(lines[i]);
                    if (m.find()) {
                        noteElement(e.getKey(), path, i + 1, snippet(raw, i, lines, i), mode);
                    }
                }
            }
        }
        for (Map.Entry<String, Pattern> e : Triggers.markers().entrySet()) {
            Matcher m = e.getValue().matcher("");
            for (int i = 0; i < lines.length; i++) {
                m.reset(lines[i]);
                if (m.find()) {
                    noteMark(e.getKey(), path, i + 1, snippet(raw, i, lines, i), mode);
                }
            }
        }
        if (!configLike) {
            return;
        }
        // 属性名:文本层只知道它出现过,不知道挂在谁身上。
        // 🔴 大小写必须敏感 —— verifyHostName(<Ssl>,中招)与 verifyHostname(HTTP appender,
        //    官方原文写明不受影响)只差一个字母。
        for (String attr : Triggers.attrs().keySet()) {
            Pattern p = Pattern.compile("(?<![A-Za-z])" + Pattern.quote(attr) + "(?![A-Za-z])");
            Matcher m = p.matcher("");
            for (int i = 0; i < lines.length; i++) {
                m.reset(lines[i]);
                if (m.find()) {
                    noteLooseAttr(attr, path, i + 1, snippet(raw, i, lines, i), mode);
                }
            }
        }
    }

    private static String snippet(String[] raw, int i, String[] lines, int j) {
        String t = (i < raw.length ? raw[i] : lines[j]).trim();
        return t.length() > 120 ? t.substring(0, 117) + "…" : t;
    }

    /**
     * 把 Java 注释内容换成空格,<b>保留所有换行</b> —— 行号不变,证据才指得准。
     *
     * <p>🔴 <b>为什么非剥注释不可</b>:示例注释和 Javadoc 里几乎必然出现这些名字
     * ({@code // 例如 new Rfc5424Layout(...)}),不剥就是稳定的误报源,
     * 而误报会让「7 条里你真中几条」这个数字失去意义 —— 那正是本工具唯一的卖点。
     *
     * <p>🔴 <b>为什么必须认字符串</b>:URL 里的 {@code "https://…"} 带着 {@code //},
     * 不认字符串就会把那行剩下的部分当注释抹掉 —— 这是**漏报**方向的错,比误报更糟。
     */
    static String stripJavaComments(String src) {
        boolean[] state = new boolean[2];          // [在块注释里, 在文本块里]
        String[] lines = src.split("\n", -1);
        StringBuilder out = new StringBuilder(src.length());
        for (int i = 0; i < lines.length; i++) {
            if (i > 0) {
                out.append('\n');
            }
            out.append(scrubLine(lines[i], state));
        }
        return out.toString();
    }

    private static String scrubLine(String line, boolean[] state) {
        StringBuilder sb = new StringBuilder(line.length());
        int i = 0;
        boolean inStr = false;
        boolean inChar = false;
        while (i < line.length()) {
            char c = line.charAt(i);
            char next = i + 1 < line.length() ? line.charAt(i + 1) : '\0';

            if (state[0]) {                                   // 块注释里
                if (c == '*' && next == '/') {
                    state[0] = false;
                    sb.append("  ");
                    i += 2;
                } else {
                    sb.append(' ');
                    i++;
                }
                continue;
            }
            if (state[1]) {                                   // 文本块里
                if (c == '"' && next == '"' && i + 2 < line.length() && line.charAt(i + 2) == '"') {
                    state[1] = false;
                    sb.append("   ");
                    i += 3;
                } else {
                    sb.append(' ');
                    i++;
                }
                continue;
            }
            if (inStr) {
                sb.append(c);
                if (c == '\\') {
                    if (next != '\0') {
                        sb.append(next);
                        i++;
                    }
                } else if (c == '"') {
                    inStr = false;
                }
                i++;
                continue;
            }
            if (inChar) {
                sb.append(c);
                if (c == '\\') {
                    if (next != '\0') {
                        sb.append(next);
                        i++;
                    }
                } else if (c == '\'') {
                    inChar = false;
                }
                i++;
                continue;
            }
            if (c == '/' && next == '/') {
                while (i < line.length()) {
                    sb.append(' ');
                    i++;
                }
                continue;
            }
            if (c == '/' && next == '*') {
                state[0] = true;
                sb.append("  ");
                i += 2;
                continue;
            }
            if (c == '"' && next == '"' && i + 2 < line.length() && line.charAt(i + 2) == '"') {
                state[1] = true;
                sb.append("   ");
                i += 3;
                continue;
            }
            if (c == '"') {
                inStr = true;
            } else if (c == '\'') {
                inChar = true;
            }
            sb.append(c);
            i++;
        }
        return sb.toString();
    }

    // ────────────────────────── 记账 ──────────────────────────

    private void noteElement(String name, String path, int line, String text, Mode mode) {
        if (!Triggers.elements().containsKey(name)) {
            return;                       // 不是我们关心的插件,正常跳过
        }
        elements.add(name);
        if (mode == Mode.STRUCTURAL) {
            elementsStructural.add(name);
        }
        note("E:" + name, path, line, text, mode);
    }

    private void noteAttr(String elemAtAttr, String path, int line, String text, Mode mode) {
        attrs.add(elemAtAttr);
        note("A:" + elemAtAttr, path, line, text, mode);
    }

    private void noteLooseAttr(String attr, String path, int line, String text, Mode mode) {
        looseAttrs.add("?@" + attr);
        note("A:?@" + attr, path, line, text, mode);
    }

    private void noteMark(String name, String path, int line, String text, Mode mode) {
        marks.add(name);
        note("S:" + name, path, line, text, mode);
    }

    private void note(String key, String path, int line, String text, Mode mode) {
        counts.merge(key, 1, Integer::sum);
        List<Evidence> ev = hits.computeIfAbsent(key, k -> new ArrayList<>());
        if (ev.size() < MAX_EVIDENCE) {
            ev.add(new Evidence(path, line, text, mode));
        }
    }
}
