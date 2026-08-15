package dev.mikko.log4jcheck;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 由 tools/gen_rules.py 从**两个一手源**生成,请勿手工编辑。
 *
 * <p>源 A:Apache 官方 CycloneDX VDR(https://logging.apache.org/cyclonedx/vdr.xml)
 *        —— 条目全集 + 逐模块精确区间 + 描述原文。
 *        🔴 注意 /repos/apache/logging-log4j2/security-advisories <b>实测返回 0 条</b>,
 *        Apache 不走 GitHub Security Advisories,只查那里会得到「log4j 很太平」且不报错。
 * <p>源 B:/advisories?ecosystem=maven&amp;affects=&lt;坐标&gt;(Dependabot 实际用的坐标索引)
 *
 * <p>粒度是 <b>CVE × 模块 × 版本区间</b>:本批 7 条散布在 4 个 Maven 模块上,
 * 而只在 pom 里写 log4j-core 的人按坐标只查得到 4 条。
 */
public final class CveTable {
    private CveTable() {}

    public static final String GENERATED_FROM = "Apache CycloneDX VDR (logging.apache.org/cyclonedx/vdr.xml) + GitHub Advisory API";

    /** 四个模块共用的 groupId。 */
    public static final String GROUP = "org.apache.logging.log4j";

    /** 本批涉及的模块(artifactId),判定粒度是 CVE × 模块。 */
    public static final List<String> MODULES = List.of("log4j-1.2-api", "log4j-api", "log4j-core", "log4j-layout-template-json");

    /** 官方(源 A)本批 Java 条目总数。 */
    public static final int OFFICIAL_TOTAL = 7;

    /**
     * 只在 pom 里写 log4j-core 的人,按坐标反查能看到的条数。
     *
     * <p>🔴 与 {@link #OFFICIAL_TOTAL} 的差就是「只盯 log4j-core 会漏几条」。
     * 这是量出来的,gen_rules.py 的 ASSERT2 每次重跑都重新核实。
     */
    public static final int VISIBLE_BY_CORE_COORD = 4;

    /**
     * 四个模块坐标全查也查不到的**版本线**条数 —— 即 Dependabot <b>结构性</b>报不出来的。
     *
     * <p>🔴 <b>2026-08-16:这个数字曾经是硬编码的 {@code 1},而它同时也由表里的
     * {@code dependabotBlind} 标志决定 —— 两处状态,改一处不会带动另一处。</b>
     * 08-13 上游补齐 {@code GHSA-qv9r-c865-cp47} 之后,表改了而这个常量不会跟着改,
     * 报告就会印出与表自相矛盾的数字。**现在改为从表算,它不可能再漂移。**
     *
     * <p>⚠️ 单位是<b>版本线</b>不是 CVE 条数:同一条 CVE 的不同版本线可能一条可见、一条不可见
     * (49844 就是:2.25/2.26 两条线 08-13 已被 advisory 覆盖,而 <b>3.x 预览线至今没有</b>)。
     *
     * <p>⚠️ 这里<b>故意做成方法而不是常量</b>:{@code static final} 字段按源码顺序初始化,
     * 而它要数的 {@code ALL} 在下面的 static 块里才填充 —— 写成字段会恒为 0 且不报错。
     */
    public static int dependabotBlind() {
        return (int) ALL.stream().filter(Cve::dependabotBlind).count();
    }

    /**
     * 曾经是盲区、后来被上游补齐的版本线 —— 保留它是因为
     * <b>「当时扫过了」和「现在是安全的」是两件事</b>:在补齐之前扫过的人,那次扫描漏了它,
     * 而没有任何东西会通知他重扫一遍。
     */
    public static final String FORMERLY_BLIND_NOTE =
            "CVE-2026-49844(GHSA-qv9r-c865-cp47)的 2.25 / 2.26 两条线,"
            + "在 2026-08-13 之前 advisory 是 unreviewed 且无包数据,那段时间 Dependabot 报不出来;"
            + "08-13 已补齐,现在报得出来。3.x 预览线至今仍未被覆盖。";

    /** 这批 advisory 里出现最多的修复版 —— 也就是大多数人照抄的那个。 */
    public static final String POPULAR_FIX = "2.25.4";

    private static final List<Cve> ALL = new ArrayList<>();

    static {
        add("CVE-2026-49844", "GHSA-qv9r-c865-cp47", "log4j-api", "medium", 6.3, "2.25", "2.13.1", true, "2.25.5", false, "2.25.5", true, false, "CVE-2026-34481", "2.25.4", "MAP_MESSAGE_AS_JSON", "仅当用 JsonTemplateLayout 的 message resolver,或代码里直接调 MapMessage.asJson() / getFormattedMessage(new String[]{\"JSON\"}),且 MapMessage 里带浮点值", "E:JsonTemplateLayout | S:asJson | S:getFormattedMessage ; S:MapMessage", "", "Improper encoding of non-finite floating-point values during MapMessage JSON serialization in…", "Improper encoding of non-finite floating-point values during MapMessage JSON serialization in Apache Log4j API produces output that is not valid JSON.");
        add("CVE-2026-49844", "GHSA-qv9r-c865-cp47", "log4j-api", "medium", 6.3, "2.26", "2.26.0", true, "2.26.1", false, "2.26.1", true, false, "CVE-2026-34481", "2.25.4", "MAP_MESSAGE_AS_JSON", "仅当用 JsonTemplateLayout 的 message resolver,或代码里直接调 MapMessage.asJson() / getFormattedMessage(new String[]{\"JSON\"}),且 MapMessage 里带浮点值", "E:JsonTemplateLayout | S:asJson | S:getFormattedMessage ; S:MapMessage", "", "Improper encoding of non-finite floating-point values during MapMessage JSON serialization in…", "Improper encoding of non-finite floating-point values during MapMessage JSON serialization in Apache Log4j API produces output that is not valid JSON.");
        add("CVE-2026-49844", "GHSA-qv9r-c865-cp47", "log4j-api", "medium", 6.3, "3.x", "3.0.0-alpha1", true, "3.0.0-beta2", true, "", false, true, "CVE-2026-34481", "2.25.4", "MAP_MESSAGE_AS_JSON", "仅当用 JsonTemplateLayout 的 message resolver,或代码里直接调 MapMessage.asJson() / getFormattedMessage(new String[]{\"JSON\"}),且 MapMessage 里带浮点值", "E:JsonTemplateLayout | S:asJson | S:getFormattedMessage ; S:MapMessage", "", "Improper encoding of non-finite floating-point values during MapMessage JSON serialization in…", "Improper encoding of non-finite floating-point values during MapMessage JSON serialization in Apache Log4j API produces output that is not valid JSON.");
        add("CVE-2026-34481", "GHSA-w35j-pv5h-q9q9", "log4j-layout-template-json", "medium", 6.3, "2.25", "2.14.0", true, "2.25.4", false, "2.25.4", true, false, "", "", "JSON_TEMPLATE_LAYOUT", "仅当用 JsonTemplateLayout,且记的日志里带 MapMessage / ObjectMessage (含直接 log 一个对象)里的浮点值", "E:JsonTemplateLayout ; S:MapMessage | S:ObjectMessage", "", "Apache Log4j JSON Template Layout: Improper serialization of non-finite floating-point values in…", "Apache Log4j's JsonTemplateLayout, in versions up to and including 2.25.3, produces invalid JSON output when log events contain non-finite floating-point values (NaN, Infinity, or -Infinity), which are prohibited by RFC…");
        add("CVE-2026-34481", "GHSA-w35j-pv5h-q9q9", "log4j-layout-template-json", "medium", 6.3, "3.x", "3.0.0-alpha1", true, "3.0.0-beta3", true, "", false, false, "", "", "JSON_TEMPLATE_LAYOUT", "仅当用 JsonTemplateLayout,且记的日志里带 MapMessage / ObjectMessage (含直接 log 一个对象)里的浮点值", "E:JsonTemplateLayout ; S:MapMessage | S:ObjectMessage", "", "Apache Log4j JSON Template Layout: Improper serialization of non-finite floating-point values in…", "Apache Log4j's JsonTemplateLayout, in versions up to and including 2.25.3, produces invalid JSON output when log events contain non-finite floating-point values (NaN, Infinity, or -Infinity), which are prohibited by RFC…");
        add("CVE-2026-34480", "GHSA-3pxv-7cmr-fjr4", "log4j-core", "medium", 6.9, "2.25", "2.0-alpha1", true, "2.25.4", false, "2.25.4", true, false, "", "", "XML_LAYOUT", "仅当用 log4j-core 的 XmlLayout(注意:不是 log4j-1.2-api 桥的 Log4j1XmlLayout,那是 CVE-2026-34479)", "E:XmlLayout", "", "Apache Log4j Core: Silent log event loss in XmlLayout due to unescaped XML 1.0 forbidden characters", "Apache Log4j Core's XmlLayout, in versions up to and including 2.25.3, fails to sanitize characters forbidden by the XML 1.0 specification producing invalid XML output whenever a log message or MDC value contains such c…");
        add("CVE-2026-34480", "GHSA-3pxv-7cmr-fjr4", "log4j-core", "medium", 6.9, "3.x", "3.0.0-alpha1", true, "3.0.0-beta3", true, "", false, false, "", "", "XML_LAYOUT", "仅当用 log4j-core 的 XmlLayout(注意:不是 log4j-1.2-api 桥的 Log4j1XmlLayout,那是 CVE-2026-34479)", "E:XmlLayout", "", "Apache Log4j Core: Silent log event loss in XmlLayout due to unescaped XML 1.0 forbidden characters", "Apache Log4j Core's XmlLayout, in versions up to and including 2.25.3, fails to sanitize characters forbidden by the XML 1.0 specification producing invalid XML output whenever a log message or MDC value contains such c…");
        add("CVE-2026-34479", "GHSA-h383-gmxw-35v2", "log4j-1.2-api", "medium", 6.9, "2.25", "2.7", true, "2.25.4", false, "2.25.4", true, false, "", "", "LOG4J1_XML_LAYOUT", "仅当用 log4j-1.2-api 桥的 Log4j1XmlLayout,或用 log4j 1 配置兼容层并把 layout 类写成 org.apache.log4j.xml.XMLLayout", "E:Log4j1XmlLayout | S:org.apache.log4j.xml.XMLLayout", "", "Apache Log4j 1 to Log4j 2 bridge: silent log event loss in Log4j1XmlLayout due to unescaped XML 1.0…", "The Log4j1XmlLayout from the Apache Log4j 1-to-Log4j 2 bridge fails to escape characters forbidden by the XML 1.0 standard, producing malformed XML output.");
        add("CVE-2026-34479", "GHSA-h383-gmxw-35v2", "log4j-1.2-api", "medium", 6.9, "3.x", "3.0.0-alpha1", true, "3.0.0-beta2", true, "", false, false, "", "", "LOG4J1_XML_LAYOUT", "仅当用 log4j-1.2-api 桥的 Log4j1XmlLayout,或用 log4j 1 配置兼容层并把 layout 类写成 org.apache.log4j.xml.XMLLayout", "E:Log4j1XmlLayout | S:org.apache.log4j.xml.XMLLayout", "", "Apache Log4j 1 to Log4j 2 bridge: silent log event loss in Log4j1XmlLayout due to unescaped XML 1.0…", "The Log4j1XmlLayout from the Apache Log4j 1-to-Log4j 2 bridge fails to escape characters forbidden by the XML 1.0 standard, producing malformed XML output.");
        add("CVE-2026-34478", "GHSA-445c-vh5m-36rj", "log4j-core", "medium", 6.9, "2.25", "2.21.0", true, "2.25.4", false, "2.25.4", true, false, "", "", "RFC5424_LAYOUT_DIRECT", "仅当**直接**配置 Rfc5424Layout(用 SyslogAppender 的不受影响),且走 TCP(RFC 6587)或 TLS(RFC 5425)framing", "E:Rfc5424Layout", "E:Syslog||你用的是 SyslogAppender 而不是直接配 Rfc5424Layout —— 官方原文写明「Users of the SyslogAppender are not affected」,本条不适用", "Apache Log4j Core: log injection in `Rfc5424Layout` due to silent configuration incompatibility", "Apache Log4j Core's Rfc5424Layout, in versions 2.21.0 through 2.25.3, is vulnerable to log injection via CRLF sequences due to undocumented renames of security-relevant configuration attributes.");
        add("CVE-2026-34478", "GHSA-445c-vh5m-36rj", "log4j-core", "medium", 6.9, "3.x", "3.0.0-beta1", true, "3.0.0-beta3", true, "", false, false, "", "", "RFC5424_LAYOUT_DIRECT", "仅当**直接**配置 Rfc5424Layout(用 SyslogAppender 的不受影响),且走 TCP(RFC 6587)或 TLS(RFC 5425)framing", "E:Rfc5424Layout", "E:Syslog||你用的是 SyslogAppender 而不是直接配 Rfc5424Layout —— 官方原文写明「Users of the SyslogAppender are not affected」,本条不适用", "Apache Log4j Core: log injection in `Rfc5424Layout` due to silent configuration incompatibility", "Apache Log4j Core's Rfc5424Layout, in versions 2.21.0 through 2.25.3, is vulnerable to log injection via CRLF sequences due to undocumented renames of security-relevant configuration attributes.");
        add("CVE-2026-34477", "GHSA-6hg6-v5c8-fphq", "log4j-core", "medium", 6.3, "2.25", "2.12.0", true, "2.25.4", false, "2.25.4", true, false, "CVE-2025-68161", "2.25.3", "SSL_VERIFY_HOST_NAME_ATTR", "仅当用 <Ssl> 元素的 verifyHostName **属性**配 TLS 主机名校验,且挂在 Socket / Syslog / SMTP appender 上(HTTP appender 用的是另一个属性,不受影响)", "A:Ssl@verifyHostName | S:verifyHostName ; E:Socket | E:Syslog | E:SMTP | E:Smtp", "A:Http@verifyHostname||你的配置里只有 HTTP appender 的 verifyHostname(小写 n)—— 官方原文写明「This issue does not affect users of the HTTP appender」,本条不适用", "Apache Log4j Core: `verifyHostName` attribute silently ignored in TLS configuration", "The fix for CVE-2025-68161 was incomplete: it addressed hostname verification only when enabled via the log4j2.sslVerifyHostName system property, but not when configured through the verifyHostName attribute of the <Ssl>…");
        add("CVE-2026-34477", "GHSA-6hg6-v5c8-fphq", "log4j-core", "medium", 6.3, "3.x", "3.0.0-alpha1", true, "3.0.0-beta3", true, "", false, false, "CVE-2025-68161", "2.25.3", "SSL_VERIFY_HOST_NAME_ATTR", "仅当用 <Ssl> 元素的 verifyHostName **属性**配 TLS 主机名校验,且挂在 Socket / Syslog / SMTP appender 上(HTTP appender 用的是另一个属性,不受影响)", "A:Ssl@verifyHostName | S:verifyHostName ; E:Socket | E:Syslog | E:SMTP | E:Smtp", "A:Http@verifyHostname||你的配置里只有 HTTP appender 的 verifyHostname(小写 n)—— 官方原文写明「This issue does not affect users of the HTTP appender」,本条不适用", "Apache Log4j Core: `verifyHostName` attribute silently ignored in TLS configuration", "The fix for CVE-2025-68161 was incomplete: it addressed hostname verification only when enabled via the log4j2.sslVerifyHostName system property, but not when configured through the verifyHostName attribute of the <Ssl>…");
        add("CVE-2025-68161", "GHSA-vc5p-v9hr-52mj", "log4j-core", "medium", 6.3, "2.25", "2.0-beta9", true, "2.25.3", false, "2.25.3", true, false, "", "", "SOCKET_APPENDER_TLS", "仅当用 SocketAppender 且为它配了 TLS(<Ssl> 元素或 log4j2.sslVerifyHostName 系统属性)", "E:Socket ; E:Ssl | S:sslVerifyHostName", "", "Apache Log4j does not verify the TLS hostname in its Socket Appender", "The Socket Appender in Log4j Core versions 2.0-beta9 through 2.25.2 does not perform TLS hostname verification of the peer certificate, even when the verifyHostName configuration attribute or the log4j2.sslVerifyHostNam…");
    }

    private static void add(String cveId, String ghsaId, String module, String severity,
                            double cvss, String line,
                            String low, boolean lowIncl, String high, boolean highIncl,
                            String fixedIn, boolean fixedAvailable, boolean dependabotBlind,
                            String gapAfter, String gapAfterFix,
                            String condKind, String condText, String condExpr, String negHint,
                            String title, String desc) {
        ALL.add(new Cve(cveId, ghsaId, module, severity, cvss, line,
                        low, lowIncl, high, highIncl, fixedIn, fixedAvailable, dependabotBlind,
                        gapAfter, gapAfterFix, condKind, condText, condExpr, negHint,
                        title, desc));
    }

    public static List<Cve> all() { return Collections.unmodifiableList(ALL); }
}
