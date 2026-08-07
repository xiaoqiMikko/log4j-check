package dev.mikko.log4jcheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ApplicabilityTest {

    private static Scanner.Artifact art(String module, String version) {
        return new Scanner.Artifact("/fake/" + module + "-" + version + ".jar", module,
                Log4jVersion.parse(version), "测试");
    }

    private static ConfigScan cfg(Path dir, String name, String content) throws IOException {
        Path f = dir.resolve(name);
        Files.writeString(f, content, StandardCharsets.UTF_8);
        ConfigScan s = new ConfigScan();
        s.scan(f);
        return s;
    }

    /** 判定全表,返回 CVE → 最高档判定(和 Main 里的归并规则一致)。 */
    private static Map<String, Applicability.Kind> judgeAll(
            List<Scanner.Artifact> arts, ConfigScan scan) {
        Map<String, Applicability.Kind> out = new LinkedHashMap<>();
        for (Cve c : CveTable.all()) {
            Applicability.Verdict v = Applicability.judge(c, arts, scan);
            Applicability.Kind cur = out.get(c.cveId());
            if (cur == null || rank(v.kind()) > rank(cur)) {
                out.put(c.cveId(), v.kind());
            }
        }
        return out;
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

    private static long countTriggered(List<Scanner.Artifact> arts, ConfigScan scan) {
        Set<String> ids = new LinkedHashSet<>();
        for (Cve c : CveTable.all()) {
            if (Applicability.judge(c, arts, scan).triggered()) {
                ids.add(c.cveId());
            }
        }
        return ids.size();
    }

    private static long countVersionHit(List<Scanner.Artifact> arts, ConfigScan scan) {
        Set<String> ids = new LinkedHashSet<>();
        for (Cve c : CveTable.all()) {
            if (Applicability.judge(c, arts, scan).versionHit()) {
                ids.add(c.cveId());
            }
        }
        return ids.size();
    }

    // ══════════════════ 降噪的止损线 ══════════════════

    @Test
    @DisplayName("⭐ 止损线:默认 PatternLayout 配置 —— 版本报一堆,真中 0 条")
    void defaultConfigNoiseFloor(@TempDir Path dir) throws IOException {
        // 装了受影响版本的全部四个模块,但配置是最常见的那种(控制台 + 滚动文件 + PatternLayout)
        List<Scanner.Artifact> arts = List.of(
                art("log4j-core", "2.24.0"), art("log4j-api", "2.24.0"),
                art("log4j-1.2-api", "2.24.0"), art("log4j-layout-template-json", "2.24.0"));
        ConfigScan scan = cfg(dir, "log4j2.xml", """
                <Configuration status="WARN">
                  <Appenders>
                    <Console name="C"><PatternLayout pattern="%d %p %m%n"/></Console>
                    <RollingFile name="F" fileName="a.log" filePattern="a-%i.log">
                      <PatternLayout pattern="%m%n"/>
                    </RollingFile>
                  </Appenders>
                  <Loggers><Root level="info"><AppenderRef ref="C"/></Root></Loggers>
                </Configuration>
                """);
        assertEquals(7, countVersionHit(arts, scan), "Dependabot 粒度:7 条全报");
        assertEquals(0, countTriggered(arts, scan),
                "🔴 降噪必须真的降下来 —— 这一条不成立,整个工具就退化成版本检测器");
        judgeAll(arts, scan).forEach((cve, kind) ->
                assertEquals(Applicability.Kind.VERSION_HIT_NO_TRIGGER, kind,
                        cve + " 应为「版本中但没找到触发条件」"));
    }

    @Test
    @DisplayName("⭐ 富特性配置:该中的中,该降的降")
    void richConfigHitsExactly(@TempDir Path dir) throws IOException {
        List<Scanner.Artifact> arts = List.of(
                art("log4j-core", "2.24.0"), art("log4j-api", "2.24.0"),
                art("log4j-1.2-api", "2.24.0"), art("log4j-layout-template-json", "2.24.0"));
        ConfigScan scan = cfg(dir, "log4j2.xml", """
                <Configuration status="WARN">
                  <Appenders>
                    <Socket name="sock" host="logs" port="6514">
                      <Ssl verifyHostName="true"><TrustStore location="ts.p12"/></Ssl>
                      <Rfc5424Layout appName="app" newLineEscape="\\n"/>
                    </Socket>
                    <File name="x" fileName="a.xml"><XmlLayout/></File>
                  </Appenders>
                  <Loggers><Root level="info"><AppenderRef ref="sock"/></Root></Loggers>
                </Configuration>
                """);
        Map<String, Applicability.Kind> k = judgeAll(arts, scan);
        assertEquals(Applicability.Kind.HIT, k.get("CVE-2026-34477"),
                "<Ssl verifyHostName> + Socket appender → 结构化命中");
        assertEquals(Applicability.Kind.HIT, k.get("CVE-2025-68161"),
                "Socket + Ssl → 命中");
        assertEquals(Applicability.Kind.HIT, k.get("CVE-2026-34478"),
                "直接配 Rfc5424Layout → 命中");
        assertEquals(Applicability.Kind.HIT, k.get("CVE-2026-34480"),
                "XmlLayout → 命中");
        assertEquals(Applicability.Kind.VERSION_HIT_NO_TRIGGER, k.get("CVE-2026-34479"),
                "没用 Log4j1XmlLayout → 不该命中");
        assertEquals(Applicability.Kind.VERSION_HIT_NO_TRIGGER, k.get("CVE-2026-34481"),
                "没用 JsonTemplateLayout → 不该命中");
        assertEquals(Applicability.Kind.VERSION_HIT_NO_TRIGGER, k.get("CVE-2026-49844"),
                "既没 JsonTemplateLayout 也没 MapMessage → 不该命中");
        assertEquals(4, countTriggered(arts, scan));
    }

    // ══════════════════ 负判据(官方原文写明不受影响)══════════════════

    @Test
    @DisplayName("🔴 承重:只用 HTTP appender 的 verifyHostname → CVE-2026-34477 判「不适用」,不是「没找到」")
    void httpAppenderIsNotApplicable(@TempDir Path dir) throws IOException {
        List<Scanner.Artifact> arts = List.of(art("log4j-core", "2.24.0"));
        ConfigScan scan = cfg(dir, "log4j2.xml", """
                <Configuration>
                  <Appenders>
                    <Http name="h" url="https://collector/logs" verifyHostname="true">
                      <Ssl><TrustStore location="ts.p12"/></Ssl>
                    </Http>
                  </Appenders>
                  <Loggers><Root level="info"><AppenderRef ref="h"/></Root></Loggers>
                </Configuration>
                """);
        Applicability.Kind k = judgeAll(arts, scan).get("CVE-2026-34477");
        // 🔴 这一档和「没找到」的可靠程度完全不同:这里有官方原文背书
        //    (does not affect users of the HTTP appender),那里只是我们没看见。
        assertEquals(Applicability.Kind.NOT_APPLICABLE, k);
        assertFalse(countTriggered(arts, scan) > 0, "HTTP appender 不该被算成中招");
    }

    @Test
    @DisplayName("🔴 承重:用 SyslogAppender 而不是直接配 Rfc5424Layout → CVE-2026-34478 判「不适用」")
    void syslogAppenderIsNotApplicable(@TempDir Path dir) throws IOException {
        List<Scanner.Artifact> arts = List.of(art("log4j-core", "2.24.0"));
        ConfigScan scan = cfg(dir, "log4j2.xml", """
                <Configuration>
                  <Appenders>
                    <Syslog name="sys" host="logs" port="514" protocol="TCP" format="RFC5424"/>
                  </Appenders>
                  <Loggers><Root level="info"><AppenderRef ref="sys"/></Root></Loggers>
                </Configuration>
                """);
        // 官方原文:Users of the SyslogAppender are not affected.
        assertEquals(Applicability.Kind.NOT_APPLICABLE,
                judgeAll(arts, scan).get("CVE-2026-34478"));
    }

    // ══════════════════ 「没做判断」≠「判断结果是一半」 ══════════════════

    @Test
    @DisplayName("🔴 承重:完全没看到配置 → NO_CONFIG_SEEN,不许印成「部分成立」")
    void noConfigIsNotPartial() {
        // 由来:第 9 注真实构件复验抓到 —— 扫一个不含源码的 fat jar 会把命中条目
        // 全印成「触发条件部分成立」,而那句话是**假的**,我们根本没看过任何依据。
        List<Scanner.Artifact> arts = List.of(art("log4j-core", "2.24.0"));
        ConfigScan emptyScan = new ConfigScan();       // 什么都没扫到
        judgeAll(arts, emptyScan).forEach((cve, kind) -> {
            if (kind != Applicability.Kind.NOT_PRESENT) {
                assertEquals(Applicability.Kind.NO_CONFIG_SEEN, kind, cve);
            }
        });
        assertEquals(0, countTriggered(arts, emptyScan),
                "🔴 没看过配置时不许说任何一条「触发了」");
        assertEquals(4, countVersionHit(arts, emptyScan),
                "但版本命中的条目一条都不能消失(只有 log4j-core 那 4 条)");
        // scan == null(用了 --no-config)也走同一档
        assertEquals(0, countTriggered(arts, null));
        assertEquals(4, countVersionHit(arts, null));
    }

    @Test
    @DisplayName("只扫了 .java、没有配置 → 仍然算「没看到配置」")
    void javaOnlyIsStillNoConfig(@TempDir Path dir) throws IOException {
        Path f = dir.resolve("A.java");
        Files.writeString(f, "class A { MapMessage m; }");
        ConfigScan scan = new ConfigScan();
        scan.scan(f);
        List<Scanner.Artifact> arts = List.of(art("log4j-api", "2.24.0"));
        // 🔴 layout / appender 的选择在配置里,源码替代不了它。
        assertEquals(Applicability.Kind.NO_CONFIG_SEEN,
                judgeAll(arts, scan).get("CVE-2026-49844"));
    }

    // ══════════════════ 文本依据 vs 结构化依据 ══════════════════

    @Test
    @DisplayName("YAML 配置命中要标成 HIT_TEXT,不能冒充结构化结论")
    void yamlHitIsMarkedAsTextEvidence(@TempDir Path dir) throws IOException {
        List<Scanner.Artifact> arts = List.of(art("log4j-core", "2.24.0"));
        ConfigScan scan = cfg(dir, "log4j2.yaml", """
                Configuration:
                  Appenders:
                    Socket:
                      name: sock
                      Ssl:
                        verifyHostName: true
                """);
        assertEquals(Applicability.Kind.HIT_TEXT, judgeAll(arts, scan).get("CVE-2026-34477"),
                "🔴 YAML 判不出属性归属,结论必须降一档并在报告里标注");
        assertTrue(Applicability.judge(
                        CveTable.all().stream()
                                .filter(c -> c.cveId().equals("CVE-2026-34477")
                                        && c.line().startsWith("2."))
                                .findFirst().orElseThrow(),
                        arts, scan).triggered(),
                "降一档但仍然算触发 —— 不能因为依据弱就把它藏起来");
    }

    // ══════════════════ 版本层的边界 ══════════════════

    @Test
    @DisplayName("升到各模块目标版本后,版本命中必须归零")
    void fullyPatchedIsClean(@TempDir Path dir) throws IOException {
        // log4j-core / 1.2-api / layout-template-json → 2.25.4;log4j-api → 2.25.5
        List<Scanner.Artifact> arts = List.of(
                art("log4j-core", "2.25.4"), art("log4j-api", "2.25.5"),
                art("log4j-1.2-api", "2.25.4"), art("log4j-layout-template-json", "2.25.4"));
        ConfigScan scan = cfg(dir, "log4j2.xml", """
                <Configuration>
                  <Appenders>
                    <Socket name="s" host="h" port="6514"><Ssl verifyHostName="true"/>
                      <Rfc5424Layout appName="a"/></Socket>
                    <File name="x" fileName="a.xml"><XmlLayout/></File>
                  </Appenders>
                  <Loggers><Root level="info"/></Loggers>
                </Configuration>
                """);
        assertEquals(0, countVersionHit(arts, scan),
                "全部升到位后,即使配置里全是触发条件也不该有任何命中");
    }

    @Test
    @DisplayName("🔥 承重:全部升到 2.25.4 —— log4j-core 干净了,log4j-api 上的 49844 还在")
    void the225_4TrapIsCaught(@TempDir Path dir) throws IOException {
        // 这是本注最核心的那个场景:照 6 条 advisory 都写的 2.25.4 升级,以为修完了。
        List<Scanner.Artifact> arts = List.of(
                art("log4j-core", "2.25.4"), art("log4j-api", "2.25.4"),
                art("log4j-1.2-api", "2.25.4"), art("log4j-layout-template-json", "2.25.4"));
        ConfigScan scan = cfg(dir, "log4j2.xml", """
                <Configuration>
                  <Appenders>
                    <Console name="C"><JsonTemplateLayout eventTemplateUri="classpath:Ecs.json"/></Console>
                  </Appenders>
                  <Loggers><Root level="info"><AppenderRef ref="C"/></Root></Loggers>
                </Configuration>
                """);
        Map<String, Applicability.Kind> k = judgeAll(arts, scan);
        assertEquals(1, countVersionHit(arts, scan), "只剩一条,就是那条 Dependabot 报不出来的");
        assertTrue(k.get("CVE-2026-49844") == Applicability.Kind.VERSION_HIT_NO_TRIGGER
                        || k.get("CVE-2026-49844") == Applicability.Kind.HIT_PARTIAL,
                "CVE-2026-49844 必须仍然版本命中,实得:" + k.get("CVE-2026-49844"));
        assertEquals(Applicability.Kind.VERSION_SAFE, k.get("CVE-2026-34481"),
                "34481 已被 2.25.4 盖住 —— 正是这一点让人以为全修好了");
        assertEquals(Applicability.Kind.VERSION_SAFE, k.get("CVE-2026-34477"));
    }

    @Test
    @DisplayName("2.26.0 是最新大版本,但它中 49844 —— 装最新的人最容易漏")
    void the226_0IsAffected() {
        List<Scanner.Artifact> arts = List.of(
                art("log4j-core", "2.26.0"), art("log4j-api", "2.26.0"));
        assertEquals(1, countVersionHit(arts, null));
        List<Cve> hit = new ArrayList<>();
        for (Cve c : CveTable.all()) {
            if (Applicability.judge(c, arts, null).versionHit()) {
                hit.add(c);
            }
        }
        assertEquals(1, hit.size());
        assertEquals("CVE-2026-49844", hit.get(0).cveId());
        assertEquals("2.26.1", hit.get(0).fixedIn(),
                "🔴 2.26 线的答案是 2.26.1,不是 2.25.5 —— 不许把人推去降级或跨线");
    }

    @Test
    @DisplayName("任一份命中即命中:老 WAR 里塞着两代 jar 时不能拿新的那份判成安全")
    void anyCopyHits() {
        List<Scanner.Artifact> arts = List.of(
                new Scanner.Artifact("app.war!/WEB-INF/lib/log4j-core-2.25.4.jar",
                        "log4j-core", Log4jVersion.parse("2.25.4"), "文件名"),
                new Scanner.Artifact("app.war!/WEB-INF/lib/legacy/log4j-core-2.17.1.jar",
                        "log4j-core", Log4jVersion.parse("2.17.1"), "文件名"));
        assertTrue(countVersionHit(arts, null) > 0, "🔴 老的那份明明中,不许被新的那份掩盖");
    }

    @Test
    @DisplayName("没装的模块要判 NOT_PRESENT,不能算成安全或命中")
    void absentModule() {
        List<Scanner.Artifact> arts = List.of(art("log4j-core", "2.24.0"));
        Map<String, Applicability.Kind> k = judgeAll(arts, null);
        assertEquals(Applicability.Kind.NOT_PRESENT, k.get("CVE-2026-49844"),
                "没装 log4j-api");
        assertEquals(Applicability.Kind.NOT_PRESENT, k.get("CVE-2026-34479"),
                "没装 log4j-1.2-api");
        assertEquals(Applicability.Kind.NOT_PRESENT, k.get("CVE-2026-34481"),
                "没装 log4j-layout-template-json");
    }

    @Test
    @DisplayName("3.x beta 用户也要判得出来,且要说清官方没给修复版")
    void threeXBeta() {
        List<Scanner.Artifact> arts = List.of(
                art("log4j-core", "3.0.0-beta3"), art("log4j-api", "3.0.0-beta2"));
        List<Cve> hits = new ArrayList<>();
        for (Cve c : CveTable.all()) {
            if (Applicability.judge(c, arts, null).versionHit()) {
                hits.add(c);
            }
        }
        assertFalse(hits.isEmpty(), "3.x beta 也在受影响区间里");
        hits.forEach(c -> {
            assertEquals("3.x", c.line());
            assertTrue(c.fixedIn().isEmpty(), "3.x 官方没给修复版,不许糊上一个 2.x 的版本号");
        });
    }
}
