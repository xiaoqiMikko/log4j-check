package dev.mikko.log4jcheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConfigScanTest {

    private static ConfigScan scanText(Path dir, String fileName, String content)
            throws IOException {
        Path f = dir.resolve(fileName);
        Files.writeString(f, content, StandardCharsets.UTF_8);
        ConfigScan s = new ConfigScan();
        s.scan(f);
        return s;
    }

    // ══════════════════ 结构化:XML ══════════════════

    @Test
    @DisplayName("XML 结构化解析:读出元素名与「元素@属性」")
    void xmlStructural(@TempDir Path dir) throws IOException {
        ConfigScan s = scanText(dir, "log4j2.xml", """
                <?xml version="1.0" encoding="UTF-8"?>
                <Configuration status="WARN">
                  <Appenders>
                    <Socket name="sock" host="logs.internal" port="6514">
                      <Ssl verifyHostName="true">
                        <TrustStore location="ts.p12"/>
                      </Ssl>
                      <Rfc5424Layout appName="app" newLineEscape="\\n"/>
                    </Socket>
                  </Appenders>
                  <Loggers><Root level="info"><AppenderRef ref="sock"/></Root></Loggers>
                </Configuration>
                """);
        assertEquals(1, s.structuredFiles(), "应该走结构化解析");
        assertEquals(0, s.textConfigFiles());
        assertTrue(s.hasElement("Socket"));
        assertTrue(s.hasElement("Ssl"));
        assertTrue(s.hasElement("Rfc5424Layout"));
        assertTrue(s.looksLikeLog4j2());
        assertTrue(s.hasAttr("Ssl@verifyHostName"), "属性必须归属到 Ssl 元素上");
        assertFalse(s.hasAttr("Http@verifyHostname"));
    }

    @Test
    @DisplayName("🔴 承重:<Http verifyHostname>(小写 n)绝不能被读成 <Ssl verifyHostName>")
    void httpVerifyHostnameIsNotSslVerifyHostName(@TempDir Path dir) throws IOException {
        // 官方原文:This issue does not affect users of the HTTP appender, which uses a
        // separate `verifyHostname` attribute。两个名字只差一个字母的大小写,而结论完全相反。
        ConfigScan s = scanText(dir, "log4j2.xml", """
                <Configuration>
                  <Appenders>
                    <Http name="h" url="https://collector/logs" verifyHostname="true">
                      <Ssl><TrustStore location="ts.p12"/></Ssl>
                    </Http>
                  </Appenders>
                  <Loggers><Root level="info"/></Loggers>
                </Configuration>
                """);
        assertTrue(s.hasAttr("Http@verifyHostname"), "应读出 HTTP appender 的那个属性");
        assertFalse(s.hasAttr("Ssl@verifyHostName"),
                "🔴 <Ssl> 上没有 verifyHostName,不许凭「附近有个 Ssl」就归属过去");
        assertFalse(s.hasLooseAttr("verifyHostName"),
                "🔴 大小写敏感:verifyHostname 不算 verifyHostName 出现过");
        assertFalse(s.hasMark("verifyHostName"),
                "🔴 词标记也必须大小写敏感,否则 34477 会在 HTTP appender 上误报");
    }

    @Test
    @DisplayName("🔴 承重:XmlLayout 不能被 Log4j1XmlLayout 冒充(34480 vs 34479)")
    void xmlLayoutIsNotLog4j1XmlLayout(@TempDir Path dir) throws IOException {
        ConfigScan bridge = scanText(dir, "log4j2.xml", """
                <Configuration>
                  <Appenders>
                    <File name="f" fileName="a.log"><Log4j1XmlLayout locationInfo="true"/></File>
                  </Appenders>
                  <Loggers><Root level="info"/></Loggers>
                </Configuration>
                """);
        assertTrue(bridge.hasElement("Log4j1XmlLayout"));
        assertFalse(bridge.hasElement("XmlLayout"),
                "🔴 只用桥的项目不该额外背上 CVE-2026-34480");

        Path d2 = dir.resolve("core");
        Files.createDirectories(d2);
        ConfigScan core = scanText(d2, "log4j2.xml", """
                <Configuration>
                  <Appenders>
                    <File name="f" fileName="a.log"><XmlLayout compact="true"/></File>
                  </Appenders>
                  <Loggers><Root level="info"/></Loggers>
                </Configuration>
                """);
        assertTrue(core.hasElement("XmlLayout"));
        assertFalse(core.hasElement("Log4j1XmlLayout"));
    }

    @Test
    @DisplayName("XML strict 模式(<Appender type=\"Socket\">)也要认,否则整份配置读成空")
    void xmlStrictMode(@TempDir Path dir) throws IOException {
        ConfigScan s = scanText(dir, "log4j2.xml", """
                <Configuration status="WARN" strict="true">
                  <Appenders>
                    <Appender type="Socket" name="sock" host="h" port="6514">
                      <Ssl type="Ssl" verifyHostName="true"/>
                    </Appender>
                  </Appenders>
                  <Loggers><Root level="info"/></Loggers>
                </Configuration>
                """);
        assertTrue(s.hasElement("Socket"), "type 属性的值才是插件名");
        assertTrue(s.hasAttr("Ssl@verifyHostName"));
    }

    @Test
    @DisplayName("XML 解析失败要退回文本匹配,不能静默跳过")
    void brokenXmlFallsBackToText(@TempDir Path dir) throws IOException {
        ConfigScan s = scanText(dir, "log4j2.xml",
                "<Configuration><Appenders><Socket name=\"s\"><XmlLayout/></Appenders>");
        assertEquals(0, s.structuredFiles());
        assertEquals(1, s.textConfigFiles(), "🔴 必须退回文本匹配 —— 跳过的话「解析失败」会表现为「没有触发条件」");
        assertTrue(s.hasElement("XmlLayout"), "文本兜底仍要找到元素名");
        assertTrue(s.warnings().stream().anyMatch(w -> w.contains("XML 解析失败")),
                "必须告警,否则用户不知道这份配置降级了");
    }

    @Test
    @DisplayName("外部实体(XXE)必须被关掉 —— 我们解析的是别人给的文件")
    void xxeIsDisabled(@TempDir Path dir) throws IOException {
        Path secret = dir.resolve("secret.txt");
        Files.writeString(secret, "XmlLayout-from-external-entity");
        String xml = "<?xml version=\"1.0\"?>\n"
                + "<!DOCTYPE c [ <!ENTITY x SYSTEM \"" + secret.toUri() + "\"> ]>\n"
                + "<Configuration><Appenders><File name=\"f\">&x;</File></Appenders></Configuration>";
        ConfigScan s = scanText(dir, "log4j2.xml", xml);
        // doctype 被禁 → 解析失败 → 退回文本匹配。关键是**没有**去读那个外部文件。
        assertEquals(0, s.structuredFiles(), "带 DOCTYPE 的应被拒绝解析");
        assertFalse(s.hits().values().stream().flatMap(java.util.List::stream)
                        .anyMatch(e -> e.text().contains("from-external-entity")),
                "🔴 外部实体的内容绝不能进到报告里");
    }

    // ══════════════════ 结构化:properties ══════════════════

    @Test
    @DisplayName("properties 结构化解析:属性按 type 声明归属到插件上")
    void propertiesStructural(@TempDir Path dir) throws IOException {
        ConfigScan s = scanText(dir, "log4j2.properties", """
                status = warn
                appender.sock.type = Socket
                appender.sock.name = sock
                appender.sock.host = logs.internal
                appender.sock.ssl.type = Ssl
                appender.sock.ssl.verifyHostName = true
                appender.sock.layout.type = Rfc5424Layout
                rootLogger.level = info
                rootLogger.appenderRef.sock.ref = sock
                """);
        assertEquals(1, s.structuredFiles());
        assertTrue(s.hasElement("Socket"));
        assertTrue(s.hasElement("Ssl"));
        assertTrue(s.hasElement("Rfc5424Layout"));
        assertTrue(s.looksLikeLog4j2(), "properties 里没有 <Configuration>,靠 rootLogger/appender 判");
        assertTrue(s.hasAttr("Ssl@verifyHostName"), "属性要挂到前缀上声明的那个 type");
    }

    @Test
    @DisplayName("🔴 properties 里 HTTP appender 的 verifyHostname 同样不能算成 Ssl 的")
    void propertiesHttpNotSsl(@TempDir Path dir) throws IOException {
        ConfigScan s = scanText(dir, "log4j2.properties", """
                appender.h.type = Http
                appender.h.name = h
                appender.h.verifyHostname = true
                rootLogger.level = info
                """);
        assertTrue(s.hasAttr("Http@verifyHostname"));
        assertFalse(s.hasAttr("Ssl@verifyHostName"));
    }

    @Test
    @DisplayName("properties 里前缀上没有 type 声明时,属性归属不明 —— 如实记成 ?@,不许猜")
    void propertiesUnattributedAttr(@TempDir Path dir) throws IOException {
        ConfigScan s = scanText(dir, "log4j2.properties", """
                rootLogger.level = info
                appender.sock.verifyHostName = true
                """);
        assertFalse(s.hasAttr("Ssl@verifyHostName"), "没有 type 声明就不许归属");
        assertTrue(s.hasLooseAttr("verifyHostName"), "但要记下「这个属性名出现过」");
    }

    // ══════════════════ 文本层:YAML / JSON / java ══════════════════

    @Test
    @DisplayName("YAML 只能文本匹配,且必须如实计入 textConfigFiles")
    void yamlIsTextOnly(@TempDir Path dir) throws IOException {
        ConfigScan s = scanText(dir, "log4j2.yaml", """
                Configuration:
                  Appenders:
                    Socket:
                      name: sock
                      Ssl:
                        verifyHostName: true
                      Rfc5424Layout:
                        appName: app
                """);
        assertEquals(0, s.structuredFiles());
        assertEquals(1, s.textConfigFiles());
        assertTrue(s.hasElement("Socket"));
        assertTrue(s.hasElement("Ssl"));
        assertFalse(s.hasAttr("Ssl@verifyHostName"),
                "🔴 YAML 判不出属性归属,不许伪装成结构化结论");
        assertTrue(s.hasLooseAttr("verifyHostName"), "但知道这个属性名出现过");
    }

    @Test
    @DisplayName("Spring Boot 的 log4j2-spring.xml 必须被认成配置文件")
    void springProfileConfigName(@TempDir Path dir) throws IOException {
        ConfigScan s = scanText(dir, "log4j2-spring.xml", """
                <Configuration>
                  <Appenders><File name="f" fileName="a.log"><XmlLayout/></File></Appenders>
                  <Loggers><Root level="info"/></Loggers>
                </Configuration>
                """);
        // 🔴 漏掉这个名字就等于对一大批 Spring Boot 项目「没扫到配置」,
        //    而没扫到和不受影响长得一模一样。
        assertTrue(s.sawAnyConfig());
        assertTrue(s.hasElement("XmlLayout"));
    }

    @Test
    @DisplayName("Java 源码里的注释与字符串:剥注释但不许剥掉 URL 后面的代码")
    void javaCommentStripping() {
        String src = """
                class A {
                    // 例如 new Rfc5424Layout() 这样写
                    /* MapMessage 也在注释里 */
                    String doc = "https://example.com/x"; XmlLayout real;
                }
                """;
        String clean = ConfigScan.stripJavaComments(src);
        assertFalse(clean.contains("Rfc5424Layout"), "行注释里的必须剥掉");
        assertFalse(clean.contains("MapMessage"), "块注释里的必须剥掉");
        // 🔴 不认字符串会把 "https://…" 里的 // 当注释,抹掉那行剩下的 XmlLayout ——
        //    那是**漏报**方向的错,比误报更糟。
        assertTrue(clean.contains("XmlLayout"), "URL 后面的代码不能被当注释抹掉");
        assertEquals(src.split("\n", -1).length, clean.split("\n", -1).length,
                "行数必须不变,证据行号才指得准");
    }

    @Test
    @DisplayName("Java 源码里的 MapMessage / asJson 要当词标记扫出来")
    void javaSourceMarkers(@TempDir Path dir) throws IOException {
        Path f = dir.resolve("Svc.java");
        Files.writeString(f, """
                import org.apache.logging.log4j.message.MapMessage;
                class Svc {
                    void go(double d) {
                        MapMessage<?, Object> m = new MapMessage<>();
                        m.with("v", d);
                        log.info(m.asJson());
                    }
                }
                """);
        ConfigScan s = new ConfigScan();
        s.scan(f);
        assertEquals(1, s.sourceFiles());
        assertTrue(s.hasMark("MapMessage"));
        assertTrue(s.hasMark("asJson"));
        assertFalse(s.sawAnyConfig(), "🔴 只有 .java 不等于看到了配置 —— 降噪结论要另算");
    }

    // ══════════════════ 归档内部的配置 ══════════════════

    @Test
    @DisplayName("⭐ fat jar 内部的 log4j2.xml 要扫得到 —— 这是「只给一个 jar 也能降噪」的前提")
    void configInsideFatJar(@TempDir Path dir) throws IOException {
        Path jar = dir.resolve("app.jar");
        try (ZipOutputStream z = new ZipOutputStream(Files.newOutputStream(jar))) {
            z.putNextEntry(new ZipEntry("BOOT-INF/classes/log4j2.xml"));
            z.write("""
                    <Configuration>
                      <Appenders>
                        <Socket name="s" host="h" port="6514">
                          <Ssl verifyHostName="true"/>
                        </Socket>
                      </Appenders>
                      <Loggers><Root level="info"/></Loggers>
                    </Configuration>
                    """.getBytes(StandardCharsets.UTF_8));
            z.closeEntry();
        }
        ConfigScan s = new ConfigScan();
        s.scan(jar);
        assertTrue(s.sawAnyConfig());
        assertEquals(1, s.structuredFiles(), "归档里的 XML 也要走结构化解析");
        assertTrue(s.hasAttr("Ssl@verifyHostName"));
        assertTrue(s.configFiles().get(0).contains("!/"), "证据路径要标明它在哪个归档里");
    }

    @Test
    @DisplayName("归档条目名用反斜杠写的也要认(PowerShell Compress-Archive 会这么干)")
    void backslashEntryNames(@TempDir Path dir) throws IOException {
        Path jar = dir.resolve("weird.jar");
        try (ZipOutputStream z = new ZipOutputStream(Files.newOutputStream(jar))) {
            z.putNextEntry(new ZipEntry("WEB-INF\\classes\\log4j2.xml"));
            z.write(("<Configuration><Appenders><File name=\"f\"><XmlLayout/></File></Appenders>"
                    + "<Loggers><Root level=\"info\"/></Loggers></Configuration>")
                    .getBytes(StandardCharsets.UTF_8));
            z.closeEntry();
        }
        ConfigScan s = new ConfigScan();
        s.scan(jar);
        // 🔴 只认 '/' 的话这类归档一条都扫不出来,而「没扫到」看起来和「你很安全」一模一样。
        assertTrue(s.sawAnyConfig(), "反斜杠条目名也必须认");
        assertTrue(s.hasElement("XmlLayout"));
    }

    @Test
    @DisplayName("target/ 之类的目录要跳过,免得把构建副本重复计数")
    void skipsBuildDirs(@TempDir Path dir) throws IOException {
        Path t = dir.resolve("target/classes");
        Files.createDirectories(t);
        Files.writeString(t.resolve("log4j2.xml"),
                "<Configuration><Appenders><File name=\"f\"><XmlLayout/></File></Appenders>"
                        + "<Loggers><Root level=\"info\"/></Loggers></Configuration>");
        ConfigScan s = new ConfigScan();
        s.scan(dir);
        assertFalse(s.sawAnyConfig(), "target/ 下的副本不算「你的配置」");
    }

    @Test
    @DisplayName("默认 PatternLayout 配置:一条触发条件都不该命中 —— 降噪的止损线")
    void plainDefaultConfigTriggersNothing(@TempDir Path dir) throws IOException {
        ConfigScan s = scanText(dir, "log4j2.xml", """
                <Configuration status="WARN">
                  <Appenders>
                    <Console name="C" target="SYSTEM_OUT">
                      <PatternLayout pattern="%d %p %c{1} - %m%n"/>
                    </Console>
                    <RollingFile name="F" fileName="a.log" filePattern="a-%i.log">
                      <PatternLayout pattern="%m%n"/>
                      <SizeBasedTriggeringPolicy size="10MB"/>
                    </RollingFile>
                  </Appenders>
                  <Loggers><Root level="info">
                    <AppenderRef ref="C"/><AppenderRef ref="F"/>
                  </Root></Loggers>
                </Configuration>
                """);
        assertTrue(s.sawAnyConfig());
        assertTrue(s.looksLikeLog4j2());
        assertTrue(s.hasElement("PatternLayout"));
        for (String e : new String[]{"Ssl", "Socket", "Syslog", "SMTP", "Rfc5424Layout",
                                    "XmlLayout", "Log4j1XmlLayout", "JsonTemplateLayout"}) {
            assertFalse(s.hasElement(e), "默认配置不该命中 " + e);
        }
        assertTrue(s.attrs().isEmpty() && s.looseAttrs().isEmpty(), "也不该有任何属性命中");
    }
}
