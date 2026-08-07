package dev.mikko.log4jcheck;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * 报告**渲染层**的测试。
 *
 * <p>🔴 <b>这个文件的存在本身就是第 9 注的教训。</b>那一注真实构件复验抓到 5 个单测测不出的问题,
 * 其中 2 个出在报告的归并与渲染层 —— 而当时的单测测的是 {@code judge()} 的返回值,
 * <b>渲染那一层原本没有任何测试</b>:
 * <ul>
 *   <li>按条目(而非条目 × 坐标)归并 → <b>安静地丢掉一半信息</b>;
 *   <li>没扫源码却印成「触发条件部分成立」→ <b>把「没做判断」说成「判断结果是一半」</b>。
 * </ul>
 * 所以这里断言的是**印出来的字**,不是内部返回值。
 */
class ReportTest {

    private static byte[] moduleJar(String module, String version) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(bos)) {
            z.putNextEntry(new ZipEntry("META-INF/maven/org.apache.logging.log4j/"
                    + module + "/pom.properties"));
            z.write(("groupId=org.apache.logging.log4j\nartifactId=" + module
                    + "\nversion=" + version + "\n").getBytes(StandardCharsets.UTF_8));
            z.closeEntry();
        }
        return bos.toByteArray();
    }

    /** 造一个 Spring Boot 形状的 fat jar:四个模块 + 内嵌 log4j2.xml。 */
    private static Path fatJar(Path dir, String name, String version, String config)
            throws IOException {
        Path app = dir.resolve(name);
        try (ZipOutputStream z = new ZipOutputStream(Files.newOutputStream(app))) {
            for (String m : CveTable.MODULES) {
                z.putNextEntry(new ZipEntry("BOOT-INF/lib/" + m + "-" + version + ".jar"));
                z.write(moduleJar(m, version));
                z.closeEntry();
            }
            if (config != null) {
                z.putNextEntry(new ZipEntry("BOOT-INF/classes/log4j2.xml"));
                z.write(config.getBytes(StandardCharsets.UTF_8));
                z.closeEntry();
            }
        }
        return app;
    }

    private static String render(Path target, boolean withConfig, boolean showAll)
            throws IOException {
        Scanner sc = new Scanner();
        sc.scan(target);
        ConfigScan cs = null;
        if (withConfig) {
            cs = new ConfigScan();
            cs.scan(target);
        }
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (PrintStream ps = new PrintStream(bos, true, StandardCharsets.UTF_8)) {
            Main.report(ps, sc, cs, showAll);
        }
        return bos.toString(StandardCharsets.UTF_8);
    }

    private static final String RICH_CONFIG = """
            <Configuration status="WARN">
              <Appenders>
                <Socket name="sock" host="logs" port="6514">
                  <Ssl verifyHostName="true"><TrustStore location="ts.p12"/></Ssl>
                  <Rfc5424Layout appName="app"/>
                </Socket>
                <File name="x" fileName="a.xml"><XmlLayout/></File>
              </Appenders>
              <Loggers><Root level="info"><AppenderRef ref="sock"/></Root></Loggers>
            </Configuration>
            """;

    private static final String PLAIN_CONFIG = """
            <Configuration status="WARN">
              <Appenders>
                <Console name="C"><PatternLayout pattern="%d %p %m%n"/></Console>
              </Appenders>
              <Loggers><Root level="info"><AppenderRef ref="C"/></Root></Loggers>
            </Configuration>
            """;

    // ══════════════════ 口径红线(每次渲染都要印出来)══════════════════

    @Test
    @DisplayName("🔴 口径红线:报告必须自己说清「全部 medium、没有 RCE」")
    void reportStatesSeverityCaveat(@TempDir Path dir) throws IOException {
        String r = render(fatJar(dir, "app.jar", "2.24.0", RICH_CONFIG), true, false);
        assertTrue(r.contains("medium"), "评级要印出来");
        assertTrue(r.contains("没有 RCE") || r.contains("一条 RCE 都没有"),
                "🔴 不印这句话,读者会自己把它当成 Log4Shell 那一档");
        assertTrue(r.contains("Log4Shell"),
                "要主动把「这不是 Log4Shell」说出来,而不是等读者误会");
        // 反向:报告里不许出现夸大的说法。
        //
        // 🔴 **判据必须读得出立场** —— 这是第 9 注发文时栽三次的同一个病,而这个测试
        //    第一版就照样栽了一次:头部那句「价值是排查配置静默失效,**不是**又一个 Log4Shell」
        //    含有子串「又一个 Log4Shell」,被朴素的 contains() 判成踩线。
        //    照那个判据去改文案,就会亲手删掉报告里唯一在防止说过头的那句话。
        //    所以判据要求的是:该短语出现时,前面必须紧跟一个否定词。
        for (String bad : new String[]{"又一个 Log4Shell", "又出大洞", "严重漏洞", "紧急修复"}) {
            assertNoUnnegated(r, bad);
        }
    }

    /** 断言 {@code phrase} 要么不出现,要么每次出现都被前面的否定词否掉。 */
    private static void assertNoUnnegated(String text, String phrase) {
        int i = text.indexOf(phrase);
        while (i >= 0) {
            String before = text.substring(Math.max(0, i - 12), i);
            boolean negated = before.contains("不是") || before.contains("不许")
                    || before.contains("没有") || before.contains("绝不") || before.contains("不该");
            assertTrue(negated,
                    "🔴 口径红线:「" + phrase + "」出现在没有否定词的上下文里:…"
                            + text.substring(Math.max(0, i - 40),
                                    Math.min(text.length(), i + phrase.length() + 10)) + "…");
            i = text.indexOf(phrase, i + 1);
        }
    }

    @Test
    @DisplayName("🔴 双向自测:上面那个「读得出立场」的判据本身要能抓到真的踩线")
    void negationAwareCheckActuallyCatchesViolations() {
        // 正例:被否定的说法应放行
        assertNoUnnegated("价值是排查配置静默失效,不是又一个 Log4Shell", "又一个 Log4Shell");
        // 反例:真的踩线必须被抓到 —— 否则这个判据是个永远为真的空断言,
        //       而空断言比没有断言更糟(它看起来像有防线)
        AssertionError err = org.junit.jupiter.api.Assertions.assertThrows(AssertionError.class,
                () -> assertNoUnnegated("log4j 又出大洞了,赶紧升级", "又出大洞"));
        assertTrue(err.getMessage().contains("口径红线"));
    }

    // ══════════════════ 「没看到配置」≠「部分成立」 ══════════════════

    @Test
    @DisplayName("🔴 回归(第 9 注同型):没看到配置时,报告里不许出现「部分成立」")
    void noConfigMustNotRenderAsPartial(@TempDir Path dir) throws IOException {
        // 一个不带 log4j2.xml 的 fat jar —— 降噪这一步**没做**。
        String r = render(fatJar(dir, "noconf.jar", "2.24.0", null), true, false);
        assertTrue(r.contains("没找到任何 log4j2 配置文件"), "要说清没看到配置");
        assertTrue(r.contains("降噪这一步**没做**") || r.contains("降噪这一步"),
                "要说清降噪没做");
        assertTrue(r.contains("本次没看到 log4j2 配置"), "条目要归到这一档");
        assertFalse(r.contains("触发条件部分成立"),
                "🔴 这是第 9 注抓到的那个 bug:把「没做判断」印成「判断结果是一半」");
        assertFalse(r.contains("配置里触发条件"),
                "🔴 没看过配置时不许印那个「你真中几条」的数字 —— 它没有依据");
        assertTrue(r.contains("版本落在受影响区间的"), "但版本层的数字要照印");
    }

    @Test
    @DisplayName("🔴 回归:真 log4j-api jar 自带的 Log4j-charsets.properties 不算「你的配置」")
    void log4jOwnInternalResourceIsNotUserConfig(@TempDir Path dir) throws IOException {
        // 真实构件复验抓到的:log4j-api 的 jar 里有 Log4j-charsets.properties,
        // 第一版的配置名正则把它当成用户配置 → sawAnyConfig() 变 true →
        // 「本次没看到配置」被翻译成「看过了,没找到触发条件」。
        // 而只要 classpath 上有 log4j-api(也就是所有人),这个翻译就一直在发生。
        Path app = dir.resolve("withinternal.jar");
        try (ZipOutputStream z = new ZipOutputStream(Files.newOutputStream(app))) {
            ByteArrayOutputStream inner = new ByteArrayOutputStream();
            try (ZipOutputStream iz = new ZipOutputStream(inner)) {
                iz.putNextEntry(new ZipEntry(
                        "META-INF/maven/org.apache.logging.log4j/log4j-api/pom.properties"));
                iz.write(("groupId=org.apache.logging.log4j\nartifactId=log4j-api\n"
                        + "version=2.24.0\n").getBytes(StandardCharsets.UTF_8));
                iz.closeEntry();
                iz.putNextEntry(new ZipEntry("Log4j-charsets.properties"));
                iz.write("windows-1252 = cp1252\n".getBytes(StandardCharsets.UTF_8));
                iz.closeEntry();
            }
            z.putNextEntry(new ZipEntry("BOOT-INF/lib/log4j-api-2.24.0.jar"));
            z.write(inner.toByteArray());
            z.closeEntry();
        }
        Scanner sc = new Scanner();
        sc.scan(app);
        ConfigScan cs = new ConfigScan();
        cs.scan(app);
        assertFalse(cs.sawAnyConfig(),
                "🔴 log4j 自己 jar 里的资源不算配置,实际扫到:" + cs.configFiles());
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (PrintStream ps = new PrintStream(bos, true, StandardCharsets.UTF_8)) {
            Main.report(ps, sc, cs, false);
        }
        String r = bos.toString(StandardCharsets.UTF_8);
        assertTrue(r.contains("没找到任何 log4j2 配置文件"), "\n" + r);
        assertTrue(r.contains("本次没看到 log4j2 配置"), "条目要归到「没做判断」那一档");
    }

    @Test
    @DisplayName("双向自测:log4j2-spring.xml 与 log4j.xml 仍要被认成配置(收紧不能收过头)")
    void tighteningDidNotBreakRealConfigNames(@TempDir Path dir) throws IOException {
        // log4j.xml(不带 2)必须留着:CVE-2026-34479 的第二种触发方式是
        // 「log4j 1 配置兼容层 + org.apache.log4j.xml.XMLLayout」。
        for (String name : new String[]{"log4j2-spring.xml", "log4j2-test.xml", "log4j.xml",
                                        "log4j.properties", "log4j2.yaml", "log4j2.json"}) {
            Path d = dir.resolve(name.replace('.', '_'));
            Files.createDirectories(d);
            Files.writeString(d.resolve(name), name.endsWith(".xml")
                    ? "<Configuration><Appenders><File name=\"f\"><XmlLayout/></File>"
                      + "</Appenders><Loggers><Root level=\"info\"/></Loggers></Configuration>"
                    : "rootLogger.level = info\n");
            ConfigScan cs = new ConfigScan();
            cs.scan(d);
            assertTrue(cs.sawAnyConfig(), name + " 必须被认成 log4j 配置");
        }
        // 反例:log4j 自己的内部资源命名形式
        for (String name : new String[]{"Log4j-charsets.properties", "log4j-config.xml",
                                        "log4j-events.json"}) {
            Path d = dir.resolve("neg_" + name.replace('.', '_'));
            Files.createDirectories(d);
            Files.writeString(d.resolve(name), "rootLogger.level = info\n");
            ConfigScan cs = new ConfigScan();
            cs.scan(d);
            assertFalse(cs.sawAnyConfig(), name + " 不该被认成 log4j 配置");
        }
    }

    @Test
    @DisplayName("--no-config 时同样不许印「你真中几条」")
    void noConfigFlagHidesTriggeredCount(@TempDir Path dir) throws IOException {
        String r = render(fatJar(dir, "app.jar", "2.24.0", RICH_CONFIG), false, false);
        assertTrue(r.contains("--no-config"));
        assertFalse(r.contains("配置里触发条件成立的"));
        assertTrue(r.contains("粒度等同 Dependabot"));
    }

    // ══════════════════ 归并粒度:不许安静丢信息 ══════════════════

    @Test
    @DisplayName("🔴 回归(第 9 注同型):四个模块都命中时,四个模块都要出现在报告里")
    void allModulesAppearInReport(@TempDir Path dir) throws IOException {
        String r = render(fatJar(dir, "app.jar", "2.20.0", RICH_CONFIG), true, false);
        for (String m : CveTable.MODULES) {
            assertTrue(r.contains(m), "🔴 " + m + " 必须出现 —— 按 CVE 归并会安静丢掉一半信息");
        }
        // 七条 CVE 编号一条都不能少
        for (Cve c : CveTable.all()) {
            assertTrue(r.contains(c.cveId()), c.cveId() + " 不能从报告里消失");
        }
    }

    @Test
    @DisplayName("每条命中条目都要带上它自己的模块坐标与版本,不许张冠李戴")
    void eachEntryCarriesItsOwnCoordinate(@TempDir Path dir) throws IOException {
        // 让四个模块版本各不相同 —— 如果渲染时拿错了模块,版本号会对不上
        Path app = dir.resolve("mixed.jar");
        try (ZipOutputStream z = new ZipOutputStream(Files.newOutputStream(app))) {
            z.putNextEntry(new ZipEntry("BOOT-INF/lib/log4j-core-2.20.0.jar"));
            z.write(moduleJar("log4j-core", "2.20.0"));
            z.closeEntry();
            z.putNextEntry(new ZipEntry("BOOT-INF/lib/log4j-api-2.21.0.jar"));
            z.write(moduleJar("log4j-api", "2.21.0"));
            z.closeEntry();
            z.putNextEntry(new ZipEntry("BOOT-INF/classes/log4j2.xml"));
            z.write(RICH_CONFIG.getBytes(StandardCharsets.UTF_8));
            z.closeEntry();
        }
        String r = render(app, true, false);
        assertTrue(r.contains("log4j-core · 你的版本 2.20.0"),
                "log4j-core 的条目要配 2.20.0:\n" + r);
        assertTrue(r.contains("log4j-api · 你的版本 2.21.0"),
                "log4j-api 的条目要配 2.21.0");
        assertFalse(r.contains("log4j-api · 你的版本 2.20.0"), "🔴 不许把 core 的版本安到 api 头上");
        assertTrue(r.contains("各模块版本不一致"), "版本不一致本身要提示出来");
    }

    // ══════════════════ 承重结论必须印出来 ══════════════════

    @Test
    @DisplayName("⭐ 承重:装 2.25.4 的人必须看到「你以为修完了,还差一条」")
    void the225_4TrapIsRendered(@TempDir Path dir) throws IOException {
        String r = render(fatJar(dir, "app.jar", "2.25.4",
                """
                <Configuration>
                  <Appenders><Console name="C">
                    <JsonTemplateLayout eventTemplateUri="classpath:EcsLayout.json"/>
                  </Console></Appenders>
                  <Loggers><Root level="info"><AppenderRef ref="C"/></Root></Loggers>
                </Configuration>
                """), true, false);
        assertTrue(r.contains("补丁缺口特判"), "这一段是本注的落点:\n" + r);
        assertTrue(r.contains("CVE-2026-49844"));
        assertTrue(r.contains("2.25.5"), "要给出真正的目标版本");
        assertTrue(r.contains("CVE-2026-34481"), "要说清是照哪一条升的");
        assertTrue(r.contains("Dependabot") && r.contains("报不出"),
                "要说清没有自动告警会提醒他");
    }

    @Test
    @DisplayName("⭐ 承重:各模块目标版本不一致这件事必须印出来")
    void distinctTargetsAreRendered(@TempDir Path dir) throws IOException {
        String r = render(fatJar(dir, "app.jar", "2.24.0", PLAIN_CONFIG), true, false);
        assertTrue(r.contains("不是同一个数字"), "\n" + r);
        assertTrue(r.contains("2.25.4") && r.contains("2.25.5"),
                "两个目标版本都要出现");
        assertTrue(r.contains("把目标顶到这么高的是 CVE-2026-49844"),
                "要指名道姓是哪条把目标顶高的");
    }

    @Test
    @DisplayName("⭐ 承重:Dependabot 两个不足(多模块 / 结构性盲区)都要讲,且要分清程度")
    void bothDependabotLimitationsExplained(@TempDir Path dir) throws IOException {
        String r = render(fatJar(dir, "app.jar", "2.24.0", PLAIN_CONFIG), true, false);
        assertTrue(r.contains("多模块"));
        assertTrue(r.contains("结构性盲区"));
        assertTrue(r.contains("unreviewed"), "要给出结构性盲区的可复核依据");
        // 🔴 诚实:多模块那一条**不是 Dependabot 的错**,不许含糊过去当成它的缺陷
        assertTrue(r.contains("不是 Dependabot 的错"),
                "🔴 把人为习惯说成工具缺陷就是夸大:\n" + r);
    }

    @Test
    @DisplayName("⭐ 止损线:默认配置下报告要同时印出「报 7 条」和「真中 0 条」")
    void noiseFloorIsRendered(@TempDir Path dir) throws IOException {
        String r = render(fatJar(dir, "app.jar", "2.24.0", PLAIN_CONFIG), true, false);
        assertTrue(r.contains("版本落在受影响区间的:      7 条"), "\n" + r);
        assertTrue(r.contains("配置里触发条件**全部**成立:0 条"),
                "🔴 降噪必须在报告里看得见 —— 这是本工具唯一的卖点");
        // 🔴 「全部成立」和「部分成立」必须是两个数字(真实构件复验抓到的:
        //    第一版只印一个标着「成立」的数字,却把「部分成立」也算进去了)。
        assertTrue(r.contains("只有**部分**要求成立:      0 条"),
                "两个数字都要印,不许合并成一个含糊的「成立」");
        assertTrue(r.contains("这不等于安全"), "同时必须挡住「0 条 = 我很安全」这个读法");
    }

    @Test
    @DisplayName("🔴 回归:「全部成立」的数字里不许混进「部分成立」的条目")
    void fullAndPartialCountsAreSeparate(@TempDir Path dir) throws IOException {
        // 装到 2.25.4 + JsonTemplateLayout,但没有 MapMessage 源码 →
        // CVE-2026-49844 是「定义性特征在,其余要你自己确认」,即部分成立。
        String r = render(fatJar(dir, "app.jar", "2.25.4", """
                <Configuration>
                  <Appenders><Console name="C">
                    <JsonTemplateLayout eventTemplateUri="classpath:EcsLayout.json"/>
                  </Console></Appenders>
                  <Loggers><Root level="info"><AppenderRef ref="C"/></Root></Loggers>
                </Configuration>
                """), true, false);
        assertTrue(r.contains("配置里触发条件**全部**成立:0 条"),
                "🔴 它不是「全部成立」:\n" + r);
        assertTrue(r.contains("只有**部分**要求成立:      1 条"), "它是「部分成立」");
    }

    @Test
    @DisplayName("🔴 回归:YAML 配置的命中不许被印成「结构化解析,依据最硬」")
    void yamlHitIsNotLabelledStructural(@TempDir Path dir) throws IOException {
        // 真实构件复验抓到的:E: token 一律返回 STRUCTURAL,导致一份纯 YAML 配置的命中
        // 被印成「结构化解析,依据最硬」—— 那份配置从头到尾没被结构化解析过一次。
        Path app = dir.resolve("yamlonly.jar");
        try (ZipOutputStream z = new ZipOutputStream(Files.newOutputStream(app))) {
            z.putNextEntry(new ZipEntry("BOOT-INF/lib/log4j-core-2.24.0.jar"));
            z.write(moduleJar("log4j-core", "2.24.0"));
            z.closeEntry();
            z.putNextEntry(new ZipEntry("BOOT-INF/classes/log4j2.yaml"));
            z.write("""
                    Configuration:
                      Appenders:
                        Socket:
                          name: sock
                          Ssl:
                            verifyHostName: true
                          Rfc5424Layout:
                            appName: app
                    """.getBytes(StandardCharsets.UTF_8));
            z.closeEntry();
        }
        String r = render(app, true, false);
        assertFalse(r.contains("结构化解析,依据最硬"),
                "🔴 这份配置里一个 XML/properties 都没有,不许声称结构化解析:\n" + r);
        assertTrue(r.contains("文本依据"), "该标成文本依据");
        assertTrue(r.contains("结构化解析 0 个"), "配置统计也要如实说明");
    }

    // ══════════════════ 负判据要说出来 ══════════════════

    @Test
    @DisplayName("官方原文写明不受影响的那几条,要单独成档并给出原文依据")
    void notApplicableIsItsOwnBucket(@TempDir Path dir) throws IOException {
        String r = render(fatJar(dir, "app.jar", "2.24.0", """
                <Configuration>
                  <Appenders>
                    <Http name="h" url="https://c/logs" verifyHostname="true"/>
                    <Syslog name="s" host="h" port="514" protocol="TCP" format="RFC5424"/>
                  </Appenders>
                  <Loggers><Root level="info"><AppenderRef ref="s"/></Root></Loggers>
                </Configuration>
                """), true, false);
        assertTrue(r.contains("官方原文写明你这种用法不受影响"), "\n" + r);
        assertTrue(r.contains("does not affect users of the HTTP appender")
                        || r.contains("HTTP appender"),
                "34477 的负判据说明要印出来");
        assertTrue(r.contains("Users of the SyslogAppender are not affected")
                        || r.contains("SyslogAppender"),
                "34478 的负判据说明要印出来");
    }

    // ══════════════════ 排版与边界 ══════════════════

    @Test
    @DisplayName("没有一行印得太长(标题截断规则要真的生效)")
    void noOverlongLines(@TempDir Path dir) throws IOException {
        String r = render(fatJar(dir, "app.jar", "2.24.0", RICH_CONFIG), true, true);
        for (String line : r.split("\n")) {
            assertTrue(line.length() <= 200,
                    "这一行 " + line.length() + " 字,会撑破终端排版:" + line);
        }
    }

    @Test
    @DisplayName("每条 CVE 都要带上 CVSS 分数,不许印出空分数")
    void everyEntryHasScore(@TempDir Path dir) throws IOException {
        // 由来:第 9 注 ASSERT12 —— 一个源的 cvss.score 是 null,报告里那行印成
        // 「medium」后面空着,读者会读成「这条不严重」。本批 GitHub 的 v3 字段全为 null。
        String r = render(fatJar(dir, "app.jar", "2.24.0", RICH_CONFIG), true, true);
        assertFalse(r.contains("medium  "), "「medium」后面不该是空的:\n" + r);
        for (Cve c : CveTable.all()) {
            assertTrue(r.contains("medium " + c.cvss()),
                    c.cveId() + " 的分数 " + c.cvss() + " 要印出来");
        }
    }

    @Test
    @DisplayName("完全没扫到 log4j 时要给出可操作的下一步,而不是一句「没发现问题」")
    void emptyScanIsActionable(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("readme.txt"), "nothing here");
        String r = render(dir, true, false);
        assertTrue(r.contains("未扫到任何 log4j 模块构件"));
        assertTrue(r.contains("先跑一次构建"), "要告诉他下一步干什么");
        assertFalse(r.contains("配置里触发条件成立的"), "什么都没扫到时不许印那个数字");
    }

    @Test
    @DisplayName("YAML 配置命中时报告要标明「文本依据」,并解释它弱在哪")
    void textEvidenceIsFlagged(@TempDir Path dir) throws IOException {
        Path app = dir.resolve("yamlapp.jar");
        try (ZipOutputStream z = new ZipOutputStream(Files.newOutputStream(app))) {
            z.putNextEntry(new ZipEntry("BOOT-INF/lib/log4j-core-2.24.0.jar"));
            z.write(moduleJar("log4j-core", "2.24.0"));
            z.closeEntry();
            z.putNextEntry(new ZipEntry("BOOT-INF/classes/log4j2.yaml"));
            z.write("""
                    Configuration:
                      Appenders:
                        Socket:
                          name: sock
                          Ssl:
                            verifyHostName: true
                    """.getBytes(StandardCharsets.UTF_8));
            z.closeEntry();
        }
        String r = render(app, true, false);
        assertTrue(r.contains("**文本依据**") || r.contains("文本依据"), "\n" + r);
        assertTrue(r.contains("verifyHostname"),
                "要解释文本匹配分不清哪两个东西");
    }

    @Test
    @DisplayName("扫到的告警要汇总出来,不能只写在日志里")
    void warningsAreSurfaced(@TempDir Path dir) throws IOException {
        Files.write(dir.resolve("broken.jar"), "not a zip".getBytes(StandardCharsets.UTF_8));
        String r = render(dir, true, false);
        assertTrue(r.contains("扫描过程中的告警"), "\n" + r);
        assertTrue(r.contains("一个条目都解不出来"));
    }
}
