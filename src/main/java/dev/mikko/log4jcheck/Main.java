package dev.mikko.log4jcheck;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 命令行入口。
 *
 * <p>用法:{@code java -jar log4j-check.jar <路径...> [选项]}
 *
 * <p>路径可以是 jar / war / 目录。**只给一个 fat jar 也能做完整判定** ——
 * log4j 的触发条件写在 {@code log4j2.xml} 里,而它就打在
 * {@code BOOT-INF/classes/} / {@code WEB-INF/classes/} 下面。
 */
public final class Main {

    private static final String VERSION = "0.1.0";

    /** 退出码:0 = 没有版本命中;2 = 版本命中但配置里没找到触发条件;3 = 触发条件也成立。 */
    private static final int EXIT_CLEAN = 0;
    private static final int EXIT_VERSION_ONLY = 2;
    private static final int EXIT_TRIGGERED = 3;

    public static void main(String[] args) throws IOException {
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);

        List<Path> targets = new ArrayList<>();
        List<Path> extraSrc = new ArrayList<>();
        boolean scanConfig = true;
        boolean showAll = false;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-h", "--help" -> {
                    usage(out);
                    return;
                }
                case "-v", "--version" -> {
                    out.println("log4j-check " + VERSION);
                    return;
                }
                case "--no-config" -> scanConfig = false;
                case "--all" -> showAll = true;
                case "--src" -> {
                    if (++i >= args.length) {
                        out.println("🔴 --src 后面要跟一个路径");
                        System.exit(1);
                    }
                    extraSrc.add(Paths.get(args[i]));
                }
                default -> {
                    if (args[i].startsWith("-")) {
                        out.println("🔴 未知选项:" + args[i]);
                        usage(out);
                        System.exit(1);
                    }
                    targets.add(Paths.get(args[i]));
                }
            }
        }
        if (targets.isEmpty() && extraSrc.isEmpty()) {
            usage(out);
            System.exit(1);
        }

        Scanner scanner = new Scanner();
        for (Path t : targets) {
            scanner.scan(t);
        }

        ConfigScan scan = null;
        if (scanConfig) {
            scan = new ConfigScan();
            for (Path t : targets) {
                scan.scan(t);
            }
            for (Path t : extraSrc) {
                scan.scan(t);
            }
        }

        report(out, scanner, scan, showAll);

        int code = EXIT_CLEAN;
        for (Cve c : CveTable.all()) {
            Applicability.Verdict v = Applicability.judge(c, scanner.artifacts(), scan);
            if (v.triggered()) {
                code = EXIT_TRIGGERED;
                break;
            }
            if (v.versionHit()) {
                code = EXIT_VERSION_ONLY;
            }
        }
        System.exit(code);
    }

    private static void usage(PrintStream out) {
        out.println("""
                log4j-check %s —— log4j 2025/2026 年 %d 条「配置静默失效」公告自查

                ⚠️ 这批全是 medium,**没有 RCE**,不是 Log4Shell 那种。
                   它们的共同点是「配置在没有任何报错的情况下失效了」,
                   所以光看版本号看不出来,要读配置。

                用法:java -jar log4j-check.jar <路径...> [选项]

                  <路径>        jar / war / 目录。会同时找:
                                  · log4j 模块构件(定版本,4 个模块分别判)
                                  · log4j2 配置(log4j2*.xml / .properties / .yaml / .json,含归档内部)
                                  · .java 源码(程序化配置与 MapMessage 之类)
                  --src <路径>  额外指定源码/配置目录
                  --no-config   不看配置(只按版本判,粒度等同 Dependabot)
                  --all         把未命中的条目也列出来
                  -v, --version 版本号
                  -h, --help    本帮助

                退出码:0 = 版本没中;2 = 版本中但配置里没找到触发条件;3 = 触发条件也成立

                例:
                  java -jar log4j-check.jar app.jar            # fat jar 里带配置,一步到位
                  java -jar log4j-check.jar ./target ./src
                  java -jar log4j-check.jar ~/.m2/repository --no-config
                """.formatted(VERSION, CveTable.OFFICIAL_TOTAL));
    }

    /**
     * 渲染报告。
     *
     * <p>🔴 <b>包级可见是为了让它能被单测直接调</b> —— 第 9 注真实构件复验抓到的 5 个问题里
     * 有 2 个出在报告的**归并与渲染层**(按条目归并会安静丢掉一半信息;没扫源码却印成
     * 「触发条件部分成立」),而当时的单测测的是 {@code judge()} 的返回值,
     * <b>渲染那一层原本没有任何测试</b>。这一注把它补上。
     */
    static void report(PrintStream out, Scanner scanner, ConfigScan scan, boolean showAll) {
        List<Scanner.Artifact> arts = scanner.artifacts();

        out.println("=".repeat(78));
        out.println("log4j-check " + VERSION + " —— log4j 2025/2026 年 "
                + CveTable.OFFICIAL_TOTAL + " 条「配置静默失效」公告自查");
        out.println("判定表来源:" + CveTable.GENERATED_FROM);
        out.println("口径:本批 " + CveTable.OFFICIAL_TOTAL + " 条**全部 medium,没有 RCE** —— "
                + "价值是排查「配置静默失效」,不是又一个 Log4Shell");
        out.println("=".repeat(78));

        // ── 一、扫到了什么 ──
        out.println();
        out.println("【一】扫到的 log4j 模块(判定粒度是 CVE × 模块,共 "
                + CveTable.MODULES.size() + " 个模块)");
        if (arts.isEmpty()) {
            out.println("  未扫到任何 log4j 模块构件。");
            out.println("  ⚠️ 这可能是因为你传的路径里没有构建产物 —— 先跑一次构建,再扫 target/ 或 jar 本身。");
        } else {
            Map<String, Set<String>> versionsOf = new LinkedHashMap<>();
            for (Scanner.Artifact a : arts) {
                out.printf("  %-30s %-14s (版本来源:%s)%n", a.module(), a.version(), a.source());
                out.println("      " + a.path());
                versionsOf.computeIfAbsent(a.module(), k -> new LinkedHashSet<>())
                        .add(a.version().toString());
            }
            for (Map.Entry<String, Set<String>> e : versionsOf.entrySet()) {
                if (e.getValue().size() > 1) {
                    out.println("  ⚠️ " + e.getKey() + " 同时扫到多个版本:"
                            + String.join("、", e.getValue())
                            + " —— 本工具按「任一份命中即命中」判,但这本身通常是依赖冲突,建议先统一。");
                }
            }
            Set<String> presentModules = versionsOf.keySet();
            List<String> absent = new ArrayList<>();
            for (String m : CveTable.MODULES) {
                if (!presentModules.contains(m)) {
                    absent.add(m);
                }
            }
            if (!absent.isEmpty()) {
                out.println("  ℹ️ 未扫到的模块(它们上面的条目自然不适用):" + String.join("、", absent));
            }
            // 🔴 模块之间版本不一致 —— 这正是「我把 log4j 升到 2.25.4 了」不够用的机制
            Set<String> allVers = new LinkedHashSet<>();
            versionsOf.values().forEach(allVers::addAll);
            if (allVers.size() > 1) {
                out.println("  🔴 各模块版本不一致:" + versionsOf);
                out.println("     四个模块的正确目标版本本来就**不一样**(见【四】),"
                        + "版本又各自不同的话,更不能只看一个数字下结论。");
            }
        }

        // ── 二、配置里的触发条件 ──
        out.println();
        out.println("【二】log4j2 配置里的触发条件");
        if (scan == null) {
            out.println("  用了 --no-config,本次不看配置。");
            out.println("  🔴 没有这一步就没有降噪 —— 下面会把版本命中的条目全部列出,粒度等同 Dependabot。");
        } else if (!scan.sawAnyConfig()) {
            out.println("  没找到任何 log4j2 配置文件(log4j2*.xml / .properties / .yaml / .json)。");
            out.println("  🔴 降噪这一步**没做**,不是「做了但没找到」。下面那些条目会标成"
                    + "「本次没看到配置」,而不是「不适用」—— 这两句话该导致不同的动作。");
            if (scan.sourceFiles() > 0) {
                out.printf("  (扫了 %d 个 .java,但源码不能替代配置:layout / appender 的选择在配置里)%n",
                        scan.sourceFiles());
            }
        } else {
            out.printf("  配置文件 %d 个(结构化解析 %d 个,文本匹配 %d 个);源码 %d 个 .java%n",
                    scan.configFiles().size(), scan.structuredFiles(),
                    scan.textConfigFiles(), scan.sourceFiles());
            for (String f : scan.configFiles()) {
                out.println("      " + f);
            }
            if (scan.textConfigFiles() > 0) {
                out.println("  ⚠️ 其中有配置只能**文本匹配**(YAML / JSON,或 XML 解析失败)——");
                out.println("     文本匹配分不清 <Ssl verifyHostName> 和 <Http verifyHostname>"
                        + "(后者官方写明不受影响),所以那几条的结论标为「文本依据」。");
            }
            if (!scan.looksLikeLog4j2()) {
                out.println("  ⚠️ 扫到的配置里没有 log4j2 的常见骨架"
                        + "(Configuration / Appenders / rootLogger)——");
                out.println("     它可能不是 log4j2 的配置,那么下面的「未找到触发条件」说明不了什么。");
            }
            List<String> shown = new ArrayList<>();
            for (Map.Entry<String, Integer> e : scan.counts().entrySet()) {
                if (e.getKey().equals("E:" + Triggers.ANCHOR)) {
                    continue;
                }
                shown.add(String.format("  %-14s %-46s %d 处", e.getKey(),
                        Triggers.label(nameOf(e.getKey())), e.getValue()));
            }
            if (shown.isEmpty()) {
                out.println("  配置和源码里没找到本批任何一条的触发条件"
                        + "(比如全用默认的 PatternLayout + 文件/控制台 appender)。");
            } else {
                shown.forEach(out::println);
                out.println("  证据(每类最多 5 条):");
                scan.hits().forEach((k, v) -> {
                    if (!k.equals("E:" + Triggers.ANCHOR)) {
                        // 标上是哪个标记的证据、以及是哪种解析得出的 —— 同一行可能同时命中多个标记
                        v.forEach(ev -> out.printf("    [%s|%s] %s%n", k, ev.mode(), ev));
                    }
                });
            }
        }

        // ── 三、逐条判定 ──
        // 🔴 归并粒度是「CVE × 模块」而不是「CVE」。
        //    第 9 注真实构件复验抓到:按 CVE 归并会在同一条 CVE 命中两个坐标时
        //    **安静地丢掉一半信息**,而用户看到的版本号是另一个坐标的。
        Map<String, Applicability.Verdict> best = new LinkedHashMap<>();
        Map<String, Cve> repr = new LinkedHashMap<>();
        List<Cve> versionHitRules = new ArrayList<>();
        for (Cve c : CveTable.all()) {
            Applicability.Verdict v = Applicability.judge(c, arts, scan);
            if (v.versionHit()) {
                versionHitRules.add(c);
            }
            String key = c.cveId() + "|" + c.module();
            Applicability.Verdict cur = best.get(key);
            if (cur == null || rank(v.kind()) > rank(cur.kind())) {
                best.put(key, v);
                repr.put(key, c);
            }
        }
        // 但**计数**要按 CVE 去重 —— 「你中了几条」问的是漏洞数,不是规则数。
        // 🔴 「全部成立」和「部分成立」必须分成两个数字。
        //    真实构件复验抓到:第一版只印一个标着「触发条件成立的:N 条」的数字,
        //    而它把 HIT_PARTIAL 也算进去了 —— 于是一条「定义性特征在、其余要你自己确认」
        //    的条目,在那个数字里和一条铁定成立的条目**完全无法区分**。
        //    而这个数字就是本工具唯一的卖点,含糊它等于把卖点做虚。
        Set<String> fullIds = new LinkedHashSet<>();
        Set<String> partialIds = new LinkedHashSet<>();
        Set<String> versionHitIds = new LinkedHashSet<>();
        Set<String> blindHitIds = new LinkedHashSet<>();
        best.forEach((k, v) -> {
            Cve c = repr.get(k);
            if (v.kind() == Applicability.Kind.HIT || v.kind() == Applicability.Kind.HIT_TEXT) {
                fullIds.add(c.cveId());
            } else if (v.kind() == Applicability.Kind.HIT_PARTIAL) {
                partialIds.add(c.cveId());
            }
            if (v.versionHit()) {
                versionHitIds.add(c.cveId());
                if (c.dependabotBlind()) {
                    blindHitIds.add(c.cveId());
                }
            }
        });

        out.println();
        out.println("【三】判定结果");
        out.println("  " + "-".repeat(74));
        out.printf("  版本落在受影响区间的:      %d 条%n", versionHitIds.size());
        out.printf("    其中 Dependabot 报得出的:%d 条%n",
                versionHitIds.size() - blindHitIds.size());
        if (!blindHitIds.isEmpty()) {
            out.printf("    🔴 Dependabot **结构性报不出**的:%d 条(%s)%n",
                    blindHitIds.size(), String.join("、", blindHitIds));
        }
        if (scan != null && scan.sawAnyConfig()) {
            out.printf("  配置里触发条件**全部**成立:%d 条  ← 这才是你真正要先处理的%n",
                    fullIds.size());
            out.printf("  只有**部分**要求成立:      %d 条  ← 定义性特征在,其余要你自己确认%n",
                    partialIds.size());
        }
        out.println("  " + "-".repeat(74));

        for (Applicability.Kind k : new Applicability.Kind[]{
                Applicability.Kind.HIT, Applicability.Kind.HIT_TEXT,
                Applicability.Kind.HIT_PARTIAL, Applicability.Kind.NO_CONFIG_SEEN,
                Applicability.Kind.NOT_APPLICABLE, Applicability.Kind.VERSION_HIT_NO_TRIGGER,
                Applicability.Kind.VERSION_SAFE, Applicability.Kind.NOT_PRESENT}) {
            List<String> ids = best.entrySet().stream()
                    .filter(e -> e.getValue().kind() == k).map(Map.Entry::getKey).toList();
            if (ids.isEmpty()) {
                continue;
            }
            boolean detail = showAll
                    || (k != Applicability.Kind.VERSION_SAFE && k != Applicability.Kind.NOT_PRESENT);
            out.println();
            out.println("  " + kindLabel(k) + "(" + ids.size() + " 条)");
            for (String id : ids) {
                Cve c = repr.get(id);
                Applicability.Verdict v = best.get(id);
                out.printf("    %-16s %-12s %s%n", c.cveId(),
                        c.severity() + (c.cvss() > 0 ? " " + c.cvss() : ""), c.title());
                if (!detail) {
                    continue;
                }
                out.println("        模块   " + c.coord() + " · 你的版本 " + v.version()
                        + " · 受影响 " + c.rangeText() + " · 版本线 " + c.line());
                wrapped(out, "        原文   ", c.desc());
                wrapped(out, "        条件   ", c.condText());
                if (!v.met().isEmpty()) {
                    out.println("        命中   " + String.join("、", v.met()));
                }
                if (!v.unmet().isEmpty()) {
                    out.println("        未满足 " + String.join("、", v.unmet()));
                }
                if (!v.reason().isEmpty()) {
                    out.println("        说明   " + v.reason());
                }
                if (c.fixedIn().isEmpty()) {
                    out.println("        🔴 官方**没有给这条版本线的修复版**"
                            + (c.line().startsWith("3") ? "(3.x 仍是 beta,补丁未回合)" : ""));
                } else if (!c.fixedAvailable()) {
                    out.println("        🔴 修复版 " + c.fixedIn()
                            + " 在 Maven Central 上拿不到(HTTP 404)—— 别照它去升,升不动");
                }
                if (c.isPatchGap()) {
                    out.println("        🔥 这条是 " + c.gapAfter() + " 的**补丁缺口**:"
                            + "官方原文写明那次修复(" + c.gapAfterFix() + ")不完整,"
                            + "本条要 " + c.fixedIn());
                }
                if (c.dependabotBlind()) {
                    out.println("        🔴 **你这条版本线,Dependabot 报不出来**:它的 GitHub advisory"
                            + (c.ghsaId().isEmpty() ? "" : "(" + c.ghsaId() + ")")
                            + "没有覆盖 " + c.line() + " 这条线的版本区间,"
                            + "拿不到可比对的数据");
                }
            }
        }

        // ── 四、升级建议(按模块逐条求交集)──
        out.println();
        out.println("【四】该升到哪个版本(按模块逐条求交集,不是照抄某一条 advisory)");
        List<Remediation.Plan> plans = Remediation.plan(versionHitRules, arts);
        if (plans.isEmpty()) {
            out.println("  没有需要升级的模块。");
        } else {
            for (Remediation.Plan p : plans) {
                out.printf("  %s%n", CveTable.GROUP + ":" + p.module());
                if (p.target().isEmpty()) {
                    out.printf("      现在 %s  →  🔴 官方没有给这条版本线的修复版%n",
                            p.current() == null ? "(未知)" : p.current());
                    out.println("      盖住 " + p.covers().size() + " 条:"
                            + String.join("、", p.covers()));
                    continue;
                }
                out.printf("      现在 %s  →  升到 %s%s%n",
                        p.current() == null ? "(未知)" : p.current(), p.target(),
                        p.available() ? "" : "  🔴 这个版本在 Maven Central 上拿不到");
                out.println("      盖住 " + p.covers().size() + " 条;把目标顶到这么高的是 "
                        + p.drivenBy()
                        + (p.blindDriven() ? "(而这一条 Dependabot 报不出来)" : ""));
                if (p.crossBranch() && p.current() != null) {
                    out.println("      ⚠️ 跨次版本分支升级(" + p.current().branch() + " → "
                            + Log4jVersion.parse(p.target()).branch() + "),改动比补丁版大,先跑回归");
                }
            }
            Set<String> distinct = Remediation.distinctTargets(plans);
            if (distinct.size() > 1) {
                out.println();
                out.println("  🔥 注意:各模块的目标版本**不是同一个数字** —— " + distinct);
                out.println("     所以「我把 log4j 升到 " + CveTable.POPULAR_FIX
                        + " 了」这句话本身就不足以收尾。");
            }
            List<Cve> beyond = Remediation.beyondPopularFix(versionHitRules);
            if (!beyond.isEmpty()) {
                Set<String> ids = new LinkedHashSet<>();
                beyond.forEach(c -> ids.add(c.cveId() + "(" + c.module() + " → "
                        + c.fixedIn() + ")"));
                out.println();
                out.println("  🔥 这批 advisory 里出现最多的修复版是 " + CveTable.POPULAR_FIX
                        + ",但升到它以下 " + ids.size() + " 条仍然中:");
                out.println("     " + String.join("、", ids));
                out.println("     这就是为什么要逐条求交集 —— 单看任何一条 advisory 都得不出上面那个目标版本。");
            }
            Map<Cve, String> gaps = Remediation.patchGaps(versionHitRules, arts);
            if (!gaps.isEmpty()) {
                out.println();
                out.println("  🔥🔥 补丁缺口特判 —— 你可能属于「已经升过级、主观上认为修完了」的那批人:");
                gaps.forEach((c, why) -> {
                    out.println("     " + c.cveId() + ":" + why);
                    if (c.dependabotBlind()) {
                        out.println("        🔴 而你这条版本线 Dependabot 结构性报不出来,"
                                + "不会有任何自动告警提醒你。");
                    }
                });
            }
        }

        // ── 五、Dependabot 盲区从哪来 ──
        out.println();
        out.println("【五】为什么 Dependabot 不够(两个原因,程度不同)");
        out.println("  ① **多模块**:本批 " + CveTable.OFFICIAL_TOTAL + " 条散布在 "
                + CveTable.MODULES.size() + " 个模块上,而按 log4j-core 这一个坐标反查只查得到 "
                + CveTable.VISIBLE_BY_CORE_COORD + " 条。");
        out.println("     绝大多数项目的 pom 里只写 log4j-core,另外三个模块是传递进来或按需引入的。");
        out.println("     → 这一条**不是 Dependabot 的错**:它会按你实际的依赖树逐个模块告警。"
                + "会漏的是「我只关心 log4j-core 版本」这个人为习惯。");
        if (CveTable.dependabotBlind() > 0) {
            out.println("  ② **结构性盲区**:有 " + CveTable.dependabotBlind()
                    + " 条**版本线**的区间在 GitHub advisory 里根本没有对应条目,");
            out.println("     Dependabot 拿不到任何可比对的数据 —— 跑在这条线上的人不会收到告警。");
        } else {
            out.println("  ② 结构性盲区:本次实测为 0 条 —— 这是查了两个源之后的结论,不是默认值。");
        }
        out.println();
        out.println("  📌 **这两个数字都会随时间变,而且不会有人通知你**:");
        out.println("     " + CveTable.FORMERLY_BLIND_NOTE);
        out.println("     🔑 **「当时扫过了」和「现在是安全的」是两件事** —— "
                + "advisory 的形态会被上游补齐,");
        out.println("     而你上一次扫描的结论**不会自己更新**。定期重扫,别信旧报告。");

        // ── 六、边界(不许暗示「扫过就没事」)──
        out.println();
        out.println("【六】🔴 这个报告不能证明什么");
        out.println("  两个方向都要说清楚 —— 只说一边就是在误导。");
        out.println();
        out.println("  ① 「未找到触发条件」**不等于安全**,至少四种情况会让它变成假的安心:");
        out.println("     1. 配置是**代码里构建**的(ConfigurationBuilder / Configurator.initialize),");
        out.println("        配置文件里根本没有那个元素;");
        out.println("     2. 配置在运行时才注入(log4j2.configurationFile 指向别处、容器里挂进来);");
        out.println("     3. 你依赖的第三方库自带一份 log4j2 配置,而它没被扫到;");
        out.println("     4. 你压根没把配置或源码传进来 —— 这种情况会单独标成「本次没看到配置」。");
        out.println();
        out.println("  ② 「触发条件全部成立」**也不等于确认中招**:");
        out.println("     多数条目还要求「攻击者能控制被记进日志的那个值」,这一点工具判不了。");
        out.println("     所以本工具的结论只够用来**排优先级**,不够用来宣布事故。");
        out.println();
        out.println("  ③ 结构化解析(XML / properties)与文本匹配(YAML / JSON / .java)可靠性不同。");
        out.println("     只有前者能区分 <Ssl verifyHostName>(中 CVE-2026-34477)和"
                + " <Http verifyHostname>(官方写明不受影响)——");
        out.println("     这两个名字只差一个字母的大小写,而结论完全相反。"
                + "走文本匹配的条目已在上面标了「文本依据」。");
        out.println();
        out.println("  ④ 本批 " + CveTable.OFFICIAL_TOTAL + " 条**全部 medium,一条 RCE 都没有**。");
        out.println("     它们的价值在于「你的某个安全/日志配置在没有报错的情况下失效了」,"
                + "不是「log4j 又出大洞」。");
        out.println("     🔴 任何把这批说成 Log4Shell 同级的文章都在夸大,包括讲这批的文章。");

        List<String> warns = new ArrayList<>(scanner.warnings());
        if (scan != null) {
            warns.addAll(scan.warnings());
        }
        if (!warns.isEmpty()) {
            out.println();
            out.println("【七】扫描过程中的告警(" + warns.size() + " 条)");
            warns.forEach(w -> out.println("  ⚠️ " + w));
        }
        out.println();
    }

    /** 报告正文宽度上限。终端一般 80~120,留到 110 兼顾可读与不换行。 */
    private static final int WRAP_WIDTH = 110;

    /**
     * 带缩进续行地印一段长文本。
     *
     * <p>🔴 <b>为什么是折行而不是再截短</b>:这里印的是**官方描述原文**,
     * 它是「不接受聚合文章转述」这条工作方式的落点 —— 截掉一半就等于把承重论据砍了。
     * 而不折行的话最长那条会印出 230+ 字撑破排版(渲染层测试抓到的)。
     * 截断只用在标题上(那是给人扫一眼的),原文一律折行保全。
     */
    private static void wrapped(PrintStream out, String prefix, String text) {
        String indent = " ".repeat(prefix.length());
        int width = Math.max(20, WRAP_WIDTH - prefix.length());
        String rest = text == null ? "" : text;
        boolean first = true;
        while (!rest.isEmpty()) {
            if (rest.length() <= width) {
                out.println((first ? prefix : indent) + rest);
                return;
            }
            int cut = rest.lastIndexOf(' ', width);
            if (cut <= width / 2) {
                cut = width;               // 没有可断的空格(如中文长句)就硬断
            }
            out.println((first ? prefix : indent) + rest.substring(0, cut).stripTrailing());
            rest = rest.substring(cut).stripLeading();
            first = false;
        }
        if (first) {
            out.println(prefix);
        }
    }

    /** 把 "E:Socket" / "A:Ssl@verifyHostName" / "S:MapMessage" 还原成用于查 label 的名字。 */
    private static String nameOf(String key) {
        String n = key.length() > 2 ? key.substring(2) : key;
        int at = n.indexOf('@');
        return at < 0 ? n : n.substring(at + 1);
    }

    private static int rank(Applicability.Kind k) {
        return switch (k) {
            case HIT -> 8;
            case HIT_TEXT -> 7;
            case HIT_PARTIAL -> 6;
            case NO_CONFIG_SEEN -> 5;
            case VERSION_HIT_NO_TRIGGER -> 4;
            case NOT_APPLICABLE -> 3;
            case VERSION_SAFE -> 2;
            case NOT_PRESENT -> 1;
        };
    }

    private static String kindLabel(Applicability.Kind k) {
        return switch (k) {
            case HIT -> "🔴 版本中 + 触发条件全部成立(结构化解析,依据最硬)";
            case HIT_TEXT -> "🔴 版本中 + 触发条件全部成立(**文本依据**,可靠性低一档)";
            case HIT_PARTIAL -> "🟠 版本中 + 触发条件部分成立";
            case NO_CONFIG_SEEN -> "🟠 版本中(本次没看到 log4j2 配置,降噪没做 —— 粒度等同 Dependabot)";
            case VERSION_HIT_NO_TRIGGER -> "🟡 版本中,但配置/源码里没找到触发条件(≠ 安全,见【六】)";
            case NOT_APPLICABLE -> "🟢 版本中,但**官方原文写明你这种用法不受影响**";
            case VERSION_SAFE -> "🟢 版本不在受影响区间内";
            case NOT_PRESENT -> "⚪ 没扫到这条针对的模块";
        };
    }

    private Main() {
    }
}
