package dev.mikko.log4jcheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConditionsTest {

    private static ConfigScan cfg(Path dir, String name, String content) throws IOException {
        Path f = dir.resolve(name);
        Files.writeString(f, content, StandardCharsets.UTF_8);
        ConfigScan s = new ConfigScan();
        s.scan(f);
        return s;
    }

    @Test
    @DisplayName("表达式解析:分号是 AND,竖线是 OR")
    void parsing() {
        List<List<String>> r = Conditions.parse("A:Ssl@verifyHostName | S:verifyHostName ; E:Socket | E:Syslog");
        assertEquals(2, r.size());
        assertEquals(List.of("A:Ssl@verifyHostName", "S:verifyHostName"), r.get(0));
        assertEquals(List.of("E:Socket", "E:Syslog"), r.get(1));
    }

    @Test
    @DisplayName("🔴 回归:首要要求不成立时不许报「部分成立」")
    void anchorRequirementGatesPartial(@TempDir Path dir) throws IOException {
        // 建造时实测踩到的:一份只有 HTTP appender 的配置里有 <Ssl> 元素,
        // 于是 CVE-2025-68161(E:Socket ; E:Ssl | S:sslVerifyHostName)的第二个要求成立,
        // 而它连 SocketAppender 都没有 —— 按 anyFound 会印成「部分成立」,把数字虚高。
        ConfigScan httpOnly = cfg(dir, "log4j2.xml", """
                <Configuration>
                  <Appenders>
                    <Http name="h" url="https://c/logs"><Ssl><TrustStore location="t"/></Ssl></Http>
                  </Appenders>
                  <Loggers><Root level="info"/></Loggers>
                </Configuration>
                """);
        Conditions.Result r = Conditions.eval("E:Socket ; E:Ssl | S:sslVerifyHostName", httpOnly);
        assertFalse(r.satisfied());
        assertTrue(r.anyFound(), "第二个要求确实成立");
        assertFalse(r.anchorMet(), "但首要要求 E:Socket 不成立");
        assertFalse(r.partial(), "🔴 所以不许算「部分成立」");
    }

    @Test
    @DisplayName("首要要求成立、其余不成立 → 才是真正的「部分成立」")
    void realPartial(@TempDir Path dir) throws IOException {
        ConfigScan socketNoSsl = cfg(dir, "log4j2.xml", """
                <Configuration>
                  <Appenders><Socket name="s" host="h" port="601"/></Appenders>
                  <Loggers><Root level="info"/></Loggers>
                </Configuration>
                """);
        Conditions.Result r = Conditions.eval("E:Socket ; E:Ssl | S:sslVerifyHostName", socketNoSsl);
        assertFalse(r.satisfied());
        assertTrue(r.anchorMet(), "有 SocketAppender —— 定义性特征在");
        assertTrue(r.partial(), "没配 TLS,但这条值得人看一眼");
    }

    @Test
    @DisplayName("结构化依据优先于文本依据 —— 同一个要求有两种备选时不该退化")
    void structuralPreferredOverText(@TempDir Path dir) throws IOException {
        ConfigScan xml = cfg(dir, "log4j2.xml", """
                <Configuration>
                  <Appenders><Socket name="s" host="h" port="6514">
                    <Ssl verifyHostName="true"/></Socket></Appenders>
                  <Loggers><Root level="info"/></Loggers>
                </Configuration>
                """);
        Conditions.Result r = Conditions.eval(
                "A:Ssl@verifyHostName | S:verifyHostName ; E:Socket", xml);
        assertTrue(r.satisfied());
        assertFalse(r.textOnly(), "🔴 XML 走结构化,不该被标成文本依据");
        assertEquals("A:Ssl@verifyHostName", r.met().get(0));
    }

    @Test
    @DisplayName("未知 token 前缀要抛异常,不能静默永不命中")
    void unknownTokenPrefixThrows() {
        // 🔴 静默永不命中长得和「你不受影响」一模一样。gen_rules.py 的 ASSERT12
        //    在生成期挡住这种情况,这里保证真出现时是响的。
        assertThrows(IllegalArgumentException.class,
                () -> Conditions.evalToken("X:Whatever", new ConfigScan()));
    }

    @Test
    @DisplayName("空扫描结果下,7 条表达式一条都不成立(且不抛异常)")
    void emptyScanSatisfiesNothing() {
        ConfigScan empty = new ConfigScan();
        for (Cve c : CveTable.all()) {
            Conditions.Result r = Conditions.eval(c.condExpr(), empty);
            assertFalse(r.satisfied(), c.cveId());
            assertFalse(r.partial(), c.cveId());
        }
    }
}
