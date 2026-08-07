package dev.mikko.log4jcheck;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * 触发条件的词表,由 tools/gen_rules.py 生成,请勿手工编辑。
 *
 * <p>分两层,可靠程度不同,报告里必须分开说:
 * <ul>
 *   <li><b>元素层</b> —— log4j2 配置里的插件/元素名。XML 与 properties 走**结构化解析**
 *       (元素名、属性归属都是读出来的);YAML / JSON / 源码只能走文本匹配。
 *   <li><b>词标记层</b> —— 只能文本匹配的东西(MapMessage、asJson() 之类)。
 * </ul>
 *
 * <p>🔴 <b>两组只差一点的名字,必须分得开</b>,否则用户会额外背上一条不属于他的 CVE:
 * <ul>
 *   <li>{@code XmlLayout}(CVE-2026-34480,log4j-core)vs
 *       {@code Log4j1XmlLayout}(CVE-2026-34479,1.2-api 桥)—— 前者是后者的子串。
 *   <li>{@code verifyHostName}(大写 N,{@code <Ssl>},CVE-2026-34477)vs
 *       {@code verifyHostname}(小写 n,HTTP appender,官方原文写明**不受影响**)。
 * </ul>
 * gen_rules.py 的 ASSERT14 在生成期就用正反样本各测一遍,不满足就不生成。
 */
public final class Triggers {
    private Triggers() {}

    /** 判断「这份配置到底是不是 log4j2 配置」的上锚。 */
    public static final String ANCHOR = "Configuration";

    private static final Map<String, List<Pattern>> ELEMENTS = new LinkedHashMap<>();
    private static final Map<String, Pattern> MARKERS = new LinkedHashMap<>();
    private static final Map<String, String> LABELS = new LinkedHashMap<>();
    private static final Map<String, java.util.Set<String>> ATTRS = new LinkedHashMap<>();

    static {
        elem("Ssl", "<Ssl> TLS 配置元素", "(?<![A-Za-z])Ssl(?![A-Za-z])");
        elem("Socket", "Socket appender", "(?<![A-Za-z])Socket(?:Appender)?(?![A-Za-z])");
        elem("Syslog", "Syslog appender", "(?<![A-Za-z])Syslog(?:Appender)?(?![A-Za-z])");
        elem("SMTP", "SMTP appender(大写写法)", "(?<![A-Za-z])SMTP(?:Appender)?(?![A-Za-z])");
        elem("Smtp", "SMTP appender(驼峰写法)", "(?<![A-Za-z])Smtp(?:Appender)?(?![A-Za-z])");
        elem("Http", "HTTP appender", "(?<![A-Za-z])Http(?:Appender)?(?![A-Za-z])");
        elem("Rfc5424Layout", "Rfc5424Layout", "(?i)(?<![A-Za-z])Rfc5424Layout(?![A-Za-z])");
        elem("XmlLayout", "XmlLayout(log4j-core)", "(?<!Log4j1)(?<![A-Za-z])XmlLayout(?![A-Za-z])");
        elem("Log4j1XmlLayout", "Log4j1XmlLayout(1.2-api 桥)", "(?<![A-Za-z])Log4j1XmlLayout(?![A-Za-z])");
        elem("JsonTemplateLayout", "JsonTemplateLayout", "(?<![A-Za-z])JsonTemplateLayout(?![A-Za-z])");
        elem("PatternLayout", "PatternLayout(默认,本批一条都不涉及)", "(?<![A-Za-z])PatternLayout(?![A-Za-z])");
        elem("Configuration", "log4j2 配置上锚(Configuration / rootLogger / Appenders)", "(?<![A-Za-z])Configuration(?![A-Za-z])", "(?<![A-Za-z])rootLogger(?![A-Za-z])", "(?<![A-Za-z])[Aa]ppenders?(?![A-Za-z])");
        mark("MapMessage", "\\bMapMessage\\b", "MapMessage");
        mark("ObjectMessage", "\\bObjectMessage\\b", "ObjectMessage");
        mark("asJson", "\\basJson\\s*\\(", "MapMessage.asJson()");
        mark("getFormattedMessage", "\\bgetFormattedMessage\\s*\\(", "getFormattedMessage()");
        mark("sslVerifyHostName", "log4j2?\\.sslVerifyHostName", "log4j2.sslVerifyHostName 系统属性");
        mark("verifyHostName", "verifyHostName", "verifyHostName(注意大写 N;HTTP appender 的是小写 n)");
        mark("org.apache.log4j.xml.XMLLayout", "org\\.apache\\.log4j\\.xml\\.XMLLayout", "log4j 1 兼容层的 XMLLayout 类名");
        attr("Http", "verifyHostname");
        attr("Ssl", "verifyHostName");
    }

    private static void elem(String name, String label, String... regexes) {
        List<Pattern> ps = new java.util.ArrayList<>();
        for (String r : regexes) {
            ps.add(Pattern.compile(r));
        }
        ELEMENTS.put(name, List.copyOf(ps));
        LABELS.put(name, label);
    }

    private static void mark(String name, String regex, String label) {
        MARKERS.put(name, Pattern.compile(regex));
        LABELS.put(name, label);
    }

    private static void attr(String element, String attribute) {
        ATTRS.computeIfAbsent(attribute, k -> new java.util.LinkedHashSet<>()).add(element);
    }

    /** 元素名 → 用于**文本兜底**的正则(结构化解析时不用它们,直接比元素名)。 */
    public static Map<String, List<Pattern>> elements() { return ELEMENTS; }

    /** 词标记名 → 正则。 */
    public static Map<String, Pattern> markers() { return MARKERS; }

    /**
     * 判定表关心的属性名 → 它可能挂在哪些元素上。
     *
     * <p>🔴 {@code verifyHostName}(大写 N)只挂在 {@code Ssl} 上,
     * {@code verifyHostname}(小写 n)只挂在 {@code Http} 上 —— 两个键在这张表里是分开的,
     * 这就是「一个字母之差不许混」在数据结构层面的落点。
     */
    public static Map<String, java.util.Set<String>> attrs() { return ATTRS; }

    public static String label(String name) { return LABELS.getOrDefault(name, name); }
}
