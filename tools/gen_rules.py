# -*- coding: utf-8 -*-
r"""从**两个一手源**生成 CveTable.java + Triggers.java —— 一行都不手抄。

源 A:Apache 官方 CycloneDX VDR   https://logging.apache.org/cyclonedx/vdr.xml
      = 维护者自己维护的**条目全集**,含逐模块的精确受影响区间 + 描述原文 + 修复建议原文。
      🔴 为什么不用 /repos/apache/logging-log4j2/security-advisories:**实测返回 0 条** ——
         Apache 不走 GitHub Security Advisories 那套流程。如果只查那一个端点,
         得到的会是「log4j 很太平」,而且不报错。
源 B:GitHub 全局 advisory DB     /advisories?ecosystem=maven&affects=<坐标>
      = **Dependabot 实际用的坐标索引**(四个模块坐标各查一次)

🔴 两个源必须都查(第 8/9 注的固定动作)。本注一比,差值不是 0:
   官方 Java 侧本批 7 条,而**按 log4j-core 单坐标只查得到 4 条** ——
   绝大多数人只在 pom 里写 log4j-core(另外三个模块靠传递或按需引入),
   于是另外 3 条对他们来说根本不存在。
   更硬的一条在 ASSERT13:其中 **CVE-2026-49844 按任何坐标都查不到** ——
   它的 GHSA 是 unreviewed 且 vulnerabilities 数组为空(没有包名、没有区间、没有修复版),
   **Dependabot 结构性报不出它**。而它恰好是唯一把正确答案从 2.25.4 顶到 2.25.5 的那一条。

🔴 本脚本存在的理由,是四个只有把两个源摆在一起、并去 Maven Central 实测才看得见的事实:

   1. **照这批 advisory 升到 2.25.4 的人没升到位。** 6 条的修复版都 ≤ 2.25.4,
      只有 CVE-2026-49844 要 2.25.5 / 2.26.1。ASSERT10 钉死这个差。
   2. **两条独立的「补丁不完整」链**:CVE-2025-68161(2.25.3)→ CVE-2026-34477(2.25.4);
      CVE-2026-34481(2.25.4)→ CVE-2026-49844(2.25.5)。两条链的原文都自己写着
      "The fix for ... was incomplete" / "did not cover all affected code paths"。ASSERT9 逐条核实。
   3. **判定粒度是 CVE × 模块,共 4 个模块**,不是「log4j-core < 2.25.4」一句话。ASSERT6。
   4. **触发条件在 log4j2 配置里,能结构化解析。** ASSERT11/12/14 保证降噪表不是我编的,
      且不会被两个只差一个字母的属性名骗到。

任一断言不满足 → **中止,不写文件**(防「解析失败生成空壳表而测试照样全绿」)。
"""
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
GH = r"D:\Program Files\GitHub CLI\gh.exe"
HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "src", "main", "java", "dev", "mikko", "log4jcheck")

VDR_URL = "https://logging.apache.org/cyclonedx/vdr.xml"
NS = "{http://cyclonedx.org/schema/bom/1.6}"
GROUP = "org.apache.logging.log4j"

# 本批 = 2025/2026 年那一串「配置静默失效」条目。
# 🔴 边界不是「年份」而是**这一批共同的机理**:配置或属性被静默忽略/静默改名/静默丢日志。
#    2021 年那批(44228 等)是 RCE,搜索生态、受众、工具形态全不同,不混进来。
BATCH = ["CVE-2026-49844", "CVE-2026-34481", "CVE-2026-34480", "CVE-2026-34479",
         "CVE-2026-34478", "CVE-2026-34477", "CVE-2025-68161"]

# VDR 里同时覆盖 Log4cxx(C++)与 Log4net(.NET)。本工具只做 Maven 生态。
JAVA_MODULES = {"log4j-api", "log4j-core", "log4j-1.2-api", "log4j-layout-template-json"}

# ────────────────────────── 唯一的人工输入(降噪表)──────────────────────────
#
# 🔴 这张表是本脚本仅有的人工内容,所以每一条都配了断言:
#    anchors 里的字符串必须**逐字出现在该条 CVE 的官方描述原文里**(ASSERT12)。
#    「我记得这条要用 XmlLayout」不算依据 —— 官方 VDR 原文里有这个词才算。
#
# 条件表达式语法(简单到能被人读懂并自己核对,Java 侧 Triggers.parse 解析同一套):
#    `;` 分隔的若干**必须全部成立**的要求;每个要求内 `|` 分隔**任一成立即可**的备选。
#    token 三种:
#      E:Name        —— 配置里出现了这个插件/元素(如 E:Socket、E:XmlLayout)
#      A:Elem@attr   —— 这个元素上带了这个属性(如 A:Ssl@verifyHostName)。
#                       🔴 只有**结构化解析**(XML / properties)才判得准;
#                          YAML/JSON 只能文本匹配,此时降级成「属性名出现过但归属不明」。
#      S:token       —— 源码或配置原文里出现了这个词(如 S:MapMessage)
#
# neg = (token, 说明):当第一个要求不成立、而 token 成立时,报告里印这句
#       —— 官方原文明确写了「这种情况不受影响」的那些负判据。不印出来的话,
#       用户看到「不适用」不知道是因为没扫到还是因为真的不适用。
CONDITIONS = {
    "CVE-2026-34477": (
        "SSL_VERIFY_HOST_NAME_ATTR",
        "仅当用 <Ssl> 元素的 verifyHostName **属性**配 TLS 主机名校验,"
        "且挂在 Socket / Syslog / SMTP appender 上(HTTP appender 用的是另一个属性,不受影响)",
        "A:Ssl@verifyHostName | S:verifyHostName ; E:Socket | E:Syslog | E:SMTP | E:Smtp",
        ("A:Http@verifyHostname",
         "你的配置里只有 HTTP appender 的 verifyHostname(小写 n)—— "
         "官方原文写明「This issue does not affect users of the HTTP appender」,本条不适用"),
        ["verifyHostName", "<Ssl>", "SMTP, Socket, or Syslog appender",
         "does not affect users of the HTTP appender", "verifyHostname"]),

    "CVE-2025-68161": (
        "SOCKET_APPENDER_TLS",
        "仅当用 SocketAppender 且为它配了 TLS(<Ssl> 元素或 log4j2.sslVerifyHostName 系统属性)",
        "E:Socket ; E:Ssl | S:sslVerifyHostName",
        None,
        ["Socket Appender", "verifyHostName", "log4j2.sslVerifyHostName"]),

    "CVE-2026-34478": (
        "RFC5424_LAYOUT_DIRECT",
        "仅当**直接**配置 Rfc5424Layout(用 SyslogAppender 的不受影响),"
        "且走 TCP(RFC 6587)或 TLS(RFC 5425)framing",
        "E:Rfc5424Layout",
        ("E:Syslog",
         "你用的是 SyslogAppender 而不是直接配 Rfc5424Layout —— "
         "官方原文写明「Users of the SyslogAppender are not affected」,本条不适用"),
        ["Rfc5424Layout", "newLineEscape", "useTlsMessageFormat",
         "Users of the `SyslogAppender` are not affected"]),

    "CVE-2026-34480": (
        "XML_LAYOUT",
        "仅当用 log4j-core 的 XmlLayout(注意:不是 log4j-1.2-api 桥的 Log4j1XmlLayout,那是 CVE-2026-34479)",
        "E:XmlLayout",
        None,
        ["XmlLayout", "XML 1.0 specification", "StAX", "Woodstox"]),

    "CVE-2026-34479": (
        "LOG4J1_XML_LAYOUT",
        "仅当用 log4j-1.2-api 桥的 Log4j1XmlLayout,"
        "或用 log4j 1 配置兼容层并把 layout 类写成 org.apache.log4j.xml.XMLLayout",
        "E:Log4j1XmlLayout | S:org.apache.log4j.xml.XMLLayout",
        None,
        ["Log4j1XmlLayout", "org.apache.log4j.xml.XMLLayout",
         "Log4j 1 configuration compatibility layer"]),

    "CVE-2026-34481": (
        "JSON_TEMPLATE_LAYOUT",
        "仅当用 JsonTemplateLayout,且记的日志里带 MapMessage / ObjectMessage "
        "(含直接 log 一个对象)里的浮点值",
        "E:JsonTemplateLayout ; S:MapMessage | S:ObjectMessage",
        None,
        ["JsonTemplateLayout", "MapMessage", "ObjectMessage", "non-finite floating-point"]),

    "CVE-2026-49844": (
        "MAP_MESSAGE_AS_JSON",
        "仅当用 JsonTemplateLayout 的 message resolver,或代码里直接调 MapMessage.asJson() / "
        "getFormattedMessage(new String[]{\"JSON\"}),且 MapMessage 里带浮点值",
        "E:JsonTemplateLayout | S:asJson | S:getFormattedMessage ; S:MapMessage",
        None,
        ["MapMessage.asJson()", "JsonTemplateLayout", "MapMessage",
         "getFormattedMessage(new String[] {\"JSON\"})"]),
}

# ── 配置层要识别的插件/元素名 ──
# 🔴 XmlLayout 必须排除 Log4j1XmlLayout:后者**包含**前者作为子串,
#    而它们分属两条不同的 CVE(34480 是 log4j-core,34479 是 log4j-1.2-api 桥)。
#    只 grep "XmlLayout" 会让只用桥的项目额外背上一条 34480 —— ASSERT14 双向自测这一点。
ELEMENTS = {
    "Ssl":                ((r"(?<![A-Za-z])Ssl(?![A-Za-z])",), "<Ssl> TLS 配置元素"),
    "Socket":             ((r"(?<![A-Za-z])Socket(?:Appender)?(?![A-Za-z])",), "Socket appender"),
    "Syslog":             ((r"(?<![A-Za-z])Syslog(?:Appender)?(?![A-Za-z])",), "Syslog appender"),
    "SMTP":               ((r"(?<![A-Za-z])SMTP(?:Appender)?(?![A-Za-z])",), "SMTP appender(大写写法)"),
    "Smtp":               ((r"(?<![A-Za-z])Smtp(?:Appender)?(?![A-Za-z])",), "SMTP appender(驼峰写法)"),
    "Http":               ((r"(?<![A-Za-z])Http(?:Appender)?(?![A-Za-z])",), "HTTP appender"),
    "Rfc5424Layout":      ((r"(?i)(?<![A-Za-z])Rfc5424Layout(?![A-Za-z])",), "Rfc5424Layout"),
    "XmlLayout":          ((r"(?<!Log4j1)(?<![A-Za-z])XmlLayout(?![A-Za-z])",), "XmlLayout(log4j-core)"),
    "Log4j1XmlLayout":    ((r"(?<![A-Za-z])Log4j1XmlLayout(?![A-Za-z])",), "Log4j1XmlLayout(1.2-api 桥)"),
    "JsonTemplateLayout": ((r"(?<![A-Za-z])JsonTemplateLayout(?![A-Za-z])",), "JsonTemplateLayout"),
    "PatternLayout":      ((r"(?<![A-Za-z])PatternLayout(?![A-Za-z])",), "PatternLayout(默认,本批一条都不涉及)"),
}

# ── 源码/原文层的词标记 ──
# 这些东西不在配置的元素树里,只能文本匹配。
SOURCE_MARKERS = {
    "MapMessage":          (r"\bMapMessage\b", "MapMessage"),
    "ObjectMessage":       (r"\bObjectMessage\b", "ObjectMessage"),
    "asJson":              (r"\basJson\s*\(", "MapMessage.asJson()"),
    "getFormattedMessage": (r"\bgetFormattedMessage\s*\(", "getFormattedMessage()"),
    "sslVerifyHostName":   (r"log4j2?\.sslVerifyHostName", "log4j2.sslVerifyHostName 系统属性"),
    "verifyHostName":      (r"verifyHostName", "verifyHostName(注意大写 N;HTTP appender 的是小写 n)"),
    "org.apache.log4j.xml.XMLLayout":
                           (r"org\.apache\.log4j\.xml\.XMLLayout", "log4j 1 兼容层的 XMLLayout 类名"),
}

# 判断「这份配置到底是不是 log4j2 的配置」的上锚 —— 一个元素都没命中时,
# 靠它区分两种完全不同的情况:压根没扫到 log4j2 配置(说明不了任何事) vs
# 扫到了配置但没用到这些 layout/appender(这才是降噪)。
ANCHOR = "Configuration"
ELEMENTS[ANCHOR] = ((r"(?<![A-Za-z])Configuration(?![A-Za-z])",
                     r"(?<![A-Za-z])rootLogger(?![A-Za-z])",
                     r"(?<![A-Za-z])[Aa]ppenders?(?![A-Za-z])"),
                    "log4j2 配置上锚(Configuration / rootLogger / Appenders)")


def die(msg):
    sys.exit("🔴 " + msg)


def gh_api(path):
    r = subprocess.run([GH, "api", path], capture_output=True, text=True,
                       encoding="utf-8", timeout=180)
    if r.returncode != 0:
        die("GitHub API 失败(%s):%s —— 拿不到 ≠ 没有,中止" % (path, (r.stderr or "")[:250]))
    return json.loads(r.stdout)


def http_get(url, timeout=90):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        return urllib.request.urlopen(req, timeout=timeout).read()
    except Exception as e:
        die("拉取失败 %s:%s —— 拿不到 ≠ 不存在,中止" % (url, str(e)[:150]))


def http_code(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}, method="HEAD")
        return urllib.request.urlopen(req, timeout=90).getcode()
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        die("探测失败 %s:%s —— 拿不到 ≠ 版本不存在,中止" % (url, str(e)[:150]))


# ══════════════════════ 源 A:Apache 官方 VDR ══════════════════════
print("源 A:拉 Apache 官方 CycloneDX VDR ...", flush=True)
root = ET.fromstring(http_get(VDR_URL))


def txt(node, tag):
    e = node.find(NS + tag) if node is not None else None
    return re.sub(r"\s+", " ", e.text).strip() if (e is not None and e.text) else ""


def raw(node, tag):
    e = node.find(NS + tag) if node is not None else None
    return e.text.strip() if (e is not None and e.text) else ""


vdr = {}
for v in root.findall(".//" + NS + "vulnerability"):
    vdr[raw(v, "id")] = v

print("   VDR 共 %d 条(覆盖 Log4j / Log4cxx / Log4net 三个项目)" % len(vdr))

# ASSERT1:形状检查。VDR 是官方维护的全集,少于 15 条说明格式变了而不是「log4j 很太平」。
if len(vdr) < 15:
    die("ASSERT1 失败:VDR 只解析出 %d 条,格式可能已变" % len(vdr))
missing_batch = [c for c in BATCH if c not in vdr]
if missing_batch:
    die("ASSERT1 失败:本批这些条目在 VDR 里找不到:%s" % missing_batch)
print("ASSERT1 ✅ VDR %d 条,本批 %d 条全部在册" % (len(vdr), len(BATCH)))


# ── 解析逐模块受影响区间 ──
# VDR 用 vers 语法:vers:maven/>=2.13.1|<2.25.5
VERS_RE = re.compile(r"^vers:(?P<scheme>[a-z]+)/(?P<constraints>.+)$")


def parse_vers(s):
    """把 'vers:maven/>=2.13.1|<2.25.5' 解析成 (low, lowIncl, high, highIncl)。

    🔴 端点开闭**照抄不换算**:第 6 注在「官方闭区间 ↔ GitHub first_patched」之间
       做换算时错位过一格,而错位一格的判定表看起来完全正常。
       少一次换算 = 少一处能静默出错的地方。
    """
    m = VERS_RE.match(s.strip())
    if not m:
        die("无法解析 vers 表达式 %r —— 解析不了就不能猜,中止" % s)
    if m.group("scheme") != "maven":
        return None
    low = high = ""
    li = hi = False
    for part in m.group("constraints").split("|"):
        part = part.strip()
        mm = re.match(r"^(>=|<=|<|>|=)\s*(\S+)$", part)
        if not mm:
            die("无法解析 vers 片段 %r(整段 %r)" % (part, s))
        op, ver = mm.group(1), mm.group(2)
        if op == "=":
            return ver, True, ver, True
        if op == ">=":
            low, li = ver, True
        elif op == ">":
            low, li = ver, False
        elif op == "<=":
            high, hi = ver, True
        elif op == "<":
            high, hi = ver, False
    return low, li, high, hi


def branch(version):
    """2.25.4 → '2.25';2.26.1 → '2.26'。维护分支,求交集时按它分组。"""
    m = re.match(r"^(\d+)\.(\d+)", version or "")
    return "%s.%s" % (m.group(1), m.group(2)) if m else "?"


def vkey(v):
    """版本排序键。预发布(alpha/beta/rc)排在同号正式版之前。Java 侧 Log4jVersion 同规则。"""
    m = re.match(r"^(\d+(?:\.\d+)*)(?:[.\-_]?(alpha|beta|rc|milestone|m|pr)[.\-_]?(\d*))?$",
                 (v or "").strip(), re.I)
    if not m:
        return (0,), 0, 0
    nums = tuple(int(x) for x in m.group(1).split("."))
    nums = nums + (0,) * (4 - len(nums))
    rank = {"milestone": 1, "m": 1, "alpha": 2, "beta": 3, "rc": 4, "pr": 4}.get(
        (m.group(2) or "").lower(), 100)
    return nums, rank, int(m.group(3) or 0)


rows = []
for cve in BATCH:
    v = vdr[cve]
    rating = v.find(NS + "ratings/" + NS + "rating")
    sev = txt(rating, "severity") or "unknown"
    try:
        score = float(txt(rating, "score") or -1)
    except ValueError:
        score = -1.0
    desc = raw(v, "description")
    rec = raw(v, "recommendation")

    for tgt in v.findall(NS + "affects/" + NS + "target"):
        module = txt(tgt, "ref")
        if module not in JAVA_MODULES:
            continue
        for ver in tgt.findall(NS + "versions/" + NS + "version"):
            expr = txt(ver, "range") or txt(ver, "version")
            parsed = parse_vers(expr)
            if parsed is None:
                continue
            low, li, high, hi = parsed
            # 修复版 = 开区间上界。闭区间上界(<=3.0.0-beta3)表示**官方没给修复版**
            # (3.x 还是 beta,补丁没有回合过去)—— 此时留空,报告里必须说清楚。
            fixed = high if (high and not hi) else ""
            # 🔴 版本线必须细到**维护分支**(2.25 / 2.26),不能压成一个 "2.x"。
            #    由来:CVE-2026-49844 在 log4j-api 上挂了**两条** 2.x 区间 ——
            #      >=2.13.1 <2.25.5(修复版 2.25.5)和 >=2.26.0 <2.26.1(修复版 2.26.1)。
            #    压成一条线取最大值,就会叫一个装 2.24.0 的人去跳 2.26.1(跨了小版本分支),
            #    而 2.25.5 才是他那条线上的答案。**这种建议不报错,只是让人多做一次风险更大的升级。**
            line = branch(fixed) if fixed else ("3.x" if (low or "3").startswith("3") else "2.x")
            rows.append({"cve": cve, "module": module, "sev": sev, "score": score,
                         "low": low, "low_incl": li, "high": high, "high_incl": hi,
                         "fixed": fixed, "line": line,
                         "desc": desc, "rec": rec})

if not rows:
    die("ASSERT1 失败:一条 Maven 规则都没解析出来")
print("   → 展开成 %d 条「CVE × 模块 × 区间」规则" % len(rows))

modules_hit = sorted({r["module"] for r in rows})
print("   → 涉及 %d 个 Maven 模块:%s" % (len(modules_hit), ", ".join(modules_hit)))

# ASSERT4:每条 CVE 都要落成至少一条规则 —— 防止某条被静默丢掉
lost = [c for c in BATCH if not any(r["cve"] == c for r in rows)]
if lost:
    die("ASSERT4 失败:这些条目一条 Maven 规则都没生成:%s" % lost)
print("ASSERT4 ✅ 本批 %d 条全部落成规则,无静默丢失" % len(BATCH))

# ASSERT3:描述原文必须够长 —— 触发条件全部来自它,它空了降噪就是编的
thin = [c for c in BATCH if len(vdr[c].find(NS + "description").text or "") < 200]
if thin:
    die("ASSERT3 失败:这些条目描述原文过短:%s" % thin)
print("ASSERT3 ✅ %d 条描述原文均 ≥ 200 字" % len(BATCH))

# ASSERT6 ⭐ 多模块覆盖 —— 判定粒度是 CVE × 模块。
# 只盯 log4j-core 的工具对另外三个模块的用户完全无效,而它看起来「跑得好好的」。
if len(modules_hit) < 4:
    die("ASSERT6 失败:只覆盖 %d 个模块(%s)—— "
        "「粒度是 CVE × 模块」这个核心主张不再成立" % (len(modules_hit), modules_hit))
core_only = sorted({r["cve"] for r in rows if r["module"] == "log4j-core"})
non_core = sorted(set(BATCH) - set(core_only))
print("ASSERT6 ✅ 覆盖 %d 个模块;只盯 log4j-core 会漏 %d 条:%s"
      % (len(modules_hit), len(non_core), ", ".join(non_core)))
if not non_core:
    die("ASSERT6 失败:本批全部落在 log4j-core 上 —— 多模块粒度这个论据没了")


# ══════════════════════ 源 B:按坐标反查(Dependabot 索引)══════════════════════
print("\n源 B:按四个模块坐标反查 GitHub advisory DB(= Dependabot 实际用的索引)...", flush=True)
srcB = {}
for mod in sorted(JAVA_MODULES):
    arr = gh_api("/advisories?ecosystem=maven&affects=%s:%s&per_page=100" % (GROUP, mod))
    got = {a.get("cve_id"): a for a in arr if a.get("cve_id") in BATCH}
    srcB[mod] = got
    print("   %-32s 本批命中 %d 条:%s" % (mod, len(got), ", ".join(sorted(got)) or "—"))

# ASSERT2 ⭐⭐ 双源盲区对比 —— 第 8/9 注的固定动作,这个判断本身就必须用两个源。
#
# 两个数字都要量,因为它们对应两种不同的现实做法:
#   (a) 只查 log4j-core —— 绝大多数人 pom 里只写这一个坐标
#   (b) 四个坐标全查 —— 认真的人才会做
# 剩下的差值就是**任何坐标都查不到**的,那才是结构性盲区。
core_visible = sorted(srcB["log4j-core"])
all_visible = sorted(set().union(*[set(v) for v in srcB.values()]))
blind_core = sorted(set(BATCH) - set(core_visible))
blind_all = sorted(set(BATCH) - set(all_visible))

print("\nASSERT2 盲区对比:")
print("   官方(源 A)本批 Java 条目            %d 条" % len(BATCH))
print("   按 log4j-core 单坐标反查得到          %d 条  → 差 %d 条:%s"
      % (len(core_visible), len(blind_core), ", ".join(blind_core) or "—"))
print("   四个模块坐标全查得到                  %d 条  → 差 %d 条:%s"
      % (len(all_visible), len(blind_all), ", ".join(blind_all) or "—"))
if len(blind_core) < 1:
    die("ASSERT2 失败:单查 log4j-core 就能看到全部 —— 「多模块盲区」论据不成立,文案要改")
extra_b = sorted(set(all_visible) - set(BATCH))
if extra_b:
    die("ASSERT2 反向失败:这些条目按坐标查得到,官方 VDR 里却没有 —— "
        "「VDR 是全集」这个前提不成立:%s" % extra_b)

# ASSERT13 ⭐⭐ 结构性盲区:blind_all 里的条目必须**能解释**,且解释必须是可复核的事实。
# 本注实测 CVE-2026-49844 的 GHSA 是 unreviewed 且 vulnerabilities 数组为空 ——
# 没有包名、没有版本区间、没有修复版,Dependabot **拿不到任何可比对的数据**。
# 🔴 这是本注最硬的论据,所以每次重跑都要重新核实,不许写死在文案里。
print("\nASSERT13 结构性盲区逐条解释:")
structural_blind = {}
for cve in blind_all:
    arr = gh_api("/advisories?cve_id=%s" % cve)
    if not arr:
        structural_blind[cve] = ("NOT_IN_DB", "GitHub advisory DB 里根本没有这条")
        print("   %-16s 🔴 GitHub advisory DB 里查不到这条" % cve)
        continue
    a = arr[0]
    vulns = a.get("vulnerabilities") or []
    reason = []
    if a.get("type") != "reviewed":
        reason.append("type=%s" % a.get("type"))
    if not vulns:
        reason.append("vulnerabilities 数组为空(无包名/无区间/无修复版)")
    if not reason:
        die("ASSERT13 失败:%s 按坐标查不到,但它的 advisory 看起来是正常的 reviewed 条目 —— "
            "说明是我们的坐标查询写错了,不是真盲区。必须查清楚再继续。" % cve)
    structural_blind[cve] = (a.get("ghsa_id"), " + ".join(reason))
    print("   %-16s 🔴 %s:%s" % (cve, a.get("ghsa_id"), " + ".join(reason)))
if not structural_blind:
    die("ASSERT13 失败:没有任何结构性盲区 —— 本注最硬的论据不成立,文案要重写")
print("   → %d 条**按任何坐标都查不到**,Dependabot 结构性报不出来 ✅" % len(structural_blind))


# ══════════════════════ ASSERT8 修复版必须来自官方原文 ══════════════════════
#
# 🔴 修复版是从区间上界推导出来的(<2.25.4 → 2.25.4)。推导可能错,而错了不报错。
#    判据:推出来的版本号必须**逐字出现在该条的官方 recommendation 原文里**。
print("\nASSERT8:核对推导出的修复版是否逐字出现在官方 recommendation 里...")
for r in rows:
    if not r["fixed"]:
        continue
    if r["fixed"] not in r["rec"]:
        die("ASSERT8 失败:%s / %s 推出修复版 %s,但官方 recommendation 原文里没有这个版本号 —— "
            "区间上界推导可能是错的\n     原文:%s"
            % (r["cve"], r["module"], r["fixed"], r["rec"][:250]))
fixed_set = sorted({(r["module"], r["fixed"]) for r in rows if r["fixed"]}, key=lambda x: (x[0], vkey(x[1])))
print("   %d 条规则的修复版全部在官方原文里逐字出现 ✅"
      % len([r for r in rows if r["fixed"]]))
no_fix = sorted({r["cve"] + "/" + r["module"] + "/" + r["line"] for r in rows if not r["fixed"]})
if no_fix:
    print("   ⚠️ 以下区间官方没给修复版(3.x 仍是 beta,补丁未回合):%s" % ", ".join(no_fix))


# ══════════════════════ ASSERT7 修复版可获取性探测 ══════════════════════
#
# 🔴 由来(第 5 / 8 / 9 注):把一个升不上去的版本印成升级建议,不是「误报」,
#    是让用户去做一件做不成的事。第 5 注遇到修复版只给商业支持,
#    第 9 注遇到 advisory 把版本区间贴到了错的 groupId 上,两次都是 HTTP 404。
#    本注实测**全部可获取**(见下),而这个 0 必须是量出来的,不是默认的 ——
#    所以带一个**负对照**:一个必然不存在的版本必须探到 404,否则说明探测逻辑坏了。
print("\nASSERT7:逐个探测修复版在 Maven Central 上拿不拿得到...", flush=True)


def central_jar(module, version):
    return "https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.jar" % (
        GROUP.replace(".", "/"), module, version, module, version)


probe = {}
for module, version in fixed_set:
    code = http_code(central_jar(module, version))
    probe[(module, version)] = (code == 200)
    print("   %s %-32s %-10s HTTP %s" % ("  " if code == 200 else "🔴", module, version, code))
for r in rows:
    r["fixed_ok"] = probe.get((r["module"], r["fixed"]), False) if r["fixed"] else False

# 负对照:证明探测器真的会说「拿不到」
ctrl_code = http_code(central_jar("log4j-core", "2.99.99"))
if ctrl_code == 200:
    die("ASSERT7 失败:负对照 log4j-core:2.99.99 居然 HTTP 200 —— 探测逻辑不可信")
print("   负对照 log4j-core:2.99.99 → HTTP %s(探测器会说「拿不到」)✅" % ctrl_code)
ghosts = sorted(k for k, ok in probe.items() if not ok)
print("   共 %d 个不同的修复版,其中 %d 个在 Central 上拿不到 %s"
      % (len(probe), len(ghosts), "✅(本注无幽灵坐标,这是实测值)" if not ghosts else "🔴 " + str(ghosts)))


# ══════════════════════ ASSERT9 补丁缺口链 ══════════════════════
#
# 🔴 本注有**两条**独立的「补丁不完整」链,原文自己写着。
#    它们的价值:照着前一条 advisory 升级的人以为修好了,实际还中后一条,
#    而两条不同的 CVE 编号之间没有任何搜索关联 —— 只有读原文才知道。
INCOMPLETE_RE = re.compile(
    r"The fix for (CVE-\d{4}-\d+) was incomplete"
    r"|The fix released in version `?([\d.]+)`? did not cover all affected code paths",
    re.I)
print("\nASSERT9:从原文里找「补丁不完整」链...")
chains = []          # (前一条, 后一条, 前一条的修复版, 后一条的修复版)


def fix_of(cve):
    """该条在 2.x 上的**最低**修复版 —— 即「至少要升到这里」。

    🔴 取最低而不是最高:CVE-2026-49844 在 2.25 线要 2.25.5、在 2.26 线要 2.26.1,
       而对绝大多数人(在 2.25 线以下)正确的下一步是 2.25.5。
       链条描述里说「要 2.26.1」会把人往更远的地方推,而那句话又不算错 —— 最难发现的一类偏差。
    """
    vs = [r["fixed"] for r in rows if r["cve"] == cve and r["fixed"] and r["line"].startswith("2.")]
    return min(vs, key=vkey) if vs else ""


for cve in BATCH:
    desc = raw(vdr[cve], "description")
    m = re.search(r"The fix for (CVE-\d{4}-\d+) was incomplete", desc, re.I)
    if m:
        chains.append((m.group(1), cve))
    # 反向写法:前一条的 recommendation 里点名了后一条
    rec = raw(vdr[cve], "recommendation")
    m2 = re.search(r"did not cover all affected code paths\.\s*(CVE-\d{4}-\d+) was assigned", rec, re.I | re.S)
    if m2:
        chains.append((cve, m2.group(1)))

chains = sorted(set(chains))
if len(chains) < 2:
    die("ASSERT9 失败:只找到 %d 条补丁缺口链 —— 「双链」这个论据不成立,文案要改:%s"
        % (len(chains), chains))
for a, b in chains:
    fa, fb = fix_of(a), fix_of(b)
    if not (fa and fb):
        die("ASSERT9 失败:链 %s → %s 有一端拿不到 2.x 修复版(%r / %r)" % (a, b, fa, fb))
    if vkey(fb) <= vkey(fa):
        die("ASSERT9 失败:链 %s(修复版 %s)→ %s(修复版 %s)—— "
            "后一环的修复版没有更高,「升了还中招」的说法不成立" % (a, fa, b, fb))
    print("   %s(升到 %s「修好了」) → 实际还中 %s(要 %s)✅" % (a, fa, b, fb))

# 链的终点是不是那个结构性盲区?这是本注最值钱的一句话,单独核实。
chain_ends = {b for _, b in chains}
blind_ends = chain_ends & set(structural_blind)
if blind_ends:
    print("   🔥 其中 %s 既是补丁缺口链的终点,**又是 Dependabot 结构性盲区** ——"
          % ", ".join(sorted(blind_ends)))
    print("      也就是说:让「升到 2.25.4 就好了」这句话变错的那一条,Dependabot 根本报不出来。")


# ══════════════════════ ASSERT10 逐条求交集 ══════════════════════
#
# 各模块 2.x 线的正确答案 = 该模块上所有 fixed 的最大值。
# 与「这批 advisory 里出现最多的那个版本」一比,差出来的就是照单升级会漏的那几条。
targets = {}
for r in rows:
    if r["fixed"] and r["line"].startswith("2."):
        k = (r["module"], r["line"])
        if k not in targets or vkey(r["fixed"]) > vkey(targets[k]):
            targets[k] = r["fixed"]

freq = {}
for r in rows:
    if r["fixed"] and r["line"].startswith("2."):
        freq[r["fixed"]] = freq.get(r["fixed"], 0) + 1
popular = max(freq, key=lambda v: freq[v])
beyond = sorted({r["cve"] for r in rows
                 if r["fixed"] and r["line"].startswith("2.") and vkey(r["fixed"]) > vkey(popular)})

print("\nASSERT10 逐条求交集(这批 advisory 里出现最多的修复版是 %s,出现 %d 次):"
      % (popular, freq[popular]))
for m, ln in sorted(targets):
    print("   %-32s %-6s 线交集目标 → %s" % (m, ln, targets[(m, ln)]))
if not beyond:
    die("ASSERT10 失败:所有条目的修复版都一样 —— 「照单条 advisory 升级会漏」不成立,核心主张要重估")
print("   → 升到 %s 仍然中 %d 条:%s" % (popular, len(beyond), ", ".join(beyond)))
_higher = ["%s(%s 线)=%s" % (m, ln, targets[(m, ln)])
           for m, ln in sorted(targets) if vkey(targets[(m, ln)]) > vkey(popular)]
print("   → 比 %s 更高的目标:%s ✅" % (popular, ", ".join(_higher) or "(无)"))


# ══════════════════════ ASSERT11/12 降噪表 ══════════════════════
missing = [c for c in BATCH if c not in CONDITIONS]
if missing:
    die("ASSERT11 失败:这些条目缺触发条件标注:%s" % missing)
extra = [c for c in CONDITIONS if c not in BATCH]
if extra:
    die("ASSERT11 失败:CONDITIONS 里有不属于本批的条目(该删):%s" % extra)
kinds = {CONDITIONS[c][0] for c in BATCH}
if len(kinds) < len(BATCH):
    die("ASSERT11 失败:%d 条 advisory 只分成 %d 种触发条件 —— 有重复,降噪区分度不足"
        % (len(BATCH), len(kinds)))
print("\nASSERT11 ✅ 降噪区分度:%d 条 advisory 分成 %d 种互不相同的触发条件" % (len(BATCH), len(kinds)))

print("ASSERT12 降噪溯源:逐条核对锚点串是否逐字出现在官方 VDR 原文里...")
KNOWN = set(ELEMENTS) | set(SOURCE_MARKERS)
for cve in BATCH:
    kind, text, expr, neg, anchors = CONDITIONS[cve]
    blob = raw(vdr[cve], "description") + "\n" + raw(vdr[cve], "recommendation")
    for anc in anchors:
        if anc not in blob:
            die("ASSERT12 失败:%s 的锚点串 %r 在官方原文里找不到 —— "
                "触发条件是我凭印象标的,不是原文说的\n     原文开头:%s" % (cve, anc, blob[:250]))
    # 表达式里用到的 token 必须都已定义,否则 Java 侧会静默永不命中
    toks = [t.strip() for grp in expr.split(";") for t in grp.split("|")]
    if neg:
        toks.append(neg[0])
    for t in toks:
        kindc, _, name = t.partition(":")
        base = name.split("@")[0] if kindc == "A" else name
        if kindc not in ("E", "A", "S"):
            die("ASSERT12 失败:%s 的 token %r 前缀不认识(只允许 E: / A: / S:)" % (cve, t))
        if base not in KNOWN:
            die("ASSERT12 失败:%s 用了未定义的 token %r —— "
                "Java 侧会静默永不命中,而永不命中长得和「你不受影响」一模一样" % (cve, t))
    print("   %-16s %-28s 锚点 %d 个全部命中 ✅" % (cve, kind, len(anchors)))


# ══════════════════════ ASSERT14 文本匹配陷阱双向自测 ══════════════════════
#
# 🔴 本批里有两组只差一点的名字,而它们分属不同的 CVE / 不同的结论。
#    判据看的东西必须和它想验证的事情是同一件事(第 9 注发文时栽三次的同一个病)。
#    所以在**生成期**就用正反两个样本各测一次,不满足就不生成。
print("\nASSERT14 文本匹配陷阱双向自测:")
TRAPS = [
    # (说明, 元素名, 应该命中的文本, 不该命中的文本)
    ("XmlLayout ≠ Log4j1XmlLayout(34480 vs 34479)",
     "XmlLayout", '<XmlLayout compact="true"/>', '<Log4j1XmlLayout locationInfo="true"/>'),
    ("Log4j1XmlLayout 只认自己",
     "Log4j1XmlLayout", '<Log4j1XmlLayout/>', '<XmlLayout/>'),
    ("Socket ≠ SocketChannel 之类的长词",
     "Socket", '<Socket host="h" port="1"/>', '<Http name="x"/>'),
]
for why, elem, yes, no in TRAPS:
    pats = [re.compile(p) for p in ELEMENTS[elem][0]]
    if not any(p.search(yes) for p in pats):
        die("ASSERT14 失败(%s):%s 的正则没能匹配应该命中的 %r" % (why, elem, yes))
    if any(p.search(no) for p in pats):
        die("ASSERT14 失败(%s):%s 的正则误命中了不该命中的 %r —— "
            "这会让用户额外背上一条不属于他的 CVE" % (why, elem, no))
    print("   %-46s 正例命中 / 反例不命中 ✅" % why)

# verifyHostName(大写 N,<Ssl>)vs verifyHostname(小写 n,HTTP appender)。
# 官方原文明写 HTTP appender 不受影响。结构化解析靠元素归属区分,
# 文本层靠大小写区分 —— 两条路都要测。
vhn = re.compile(SOURCE_MARKERS["verifyHostName"][0])
if not vhn.search('<Ssl verifyHostName="true">'):
    die("ASSERT14 失败:verifyHostName 正则匹配不到 <Ssl verifyHostName>")
if vhn.search('<Http verifyHostname="true"/>'):
    die("ASSERT14 失败:verifyHostName 正则把 HTTP appender 的 verifyHostname(小写 n)也匹配了 —— "
        "官方原文写明 HTTP appender 不受影响,这是一个字母造成的误报")
print("   %-46s 大写 N 命中 / 小写 n 不命中 ✅" % "verifyHostName ≠ verifyHostname(34477 的负判据)")


# ══════════════════════ ASSERT15 CVSS ══════════════════════
#
# 🔴 第 9 注 ASSERT12 的由来在这一注重现且更极端:GitHub advisory 的 `cvss.score`
#    (v3)对本批 **7 条全部是 null**,分数只在 `cvss_severities.cvss_v4` 里。
#    只看 v3 会让报告里 7 行分数全空,读者读成「都不严重」。
#    官方 VDR 给的就是 CVSS v4,所以以 VDR 为准,并核对 GitHub 侧 v4 是否一致。
print("\nASSERT15 CVSS(官方 VDR 给 v4;GitHub 的 v3 字段本批全为 null,已实测):")
for cve in BATCH:
    r0 = next(r for r in rows if r["cve"] == cve)
    if r0["score"] <= 0:
        die("ASSERT15 失败:%s 在 VDR 里拿不到 CVSS 分数,报告里会印出空分数" % cve)
    gh_v4 = None
    for mod in srcB:
        a = srcB[mod].get(cve)
        if a:
            gh_v4 = ((a.get("cvss_severities") or {}).get("cvss_v4") or {}).get("score")
            break
    flag = "" if (gh_v4 is None or abs(float(gh_v4) - r0["score"]) < 0.05) \
        else "  ⚠️ GitHub 侧 v4=%s,与官方不一致" % gh_v4
    print("   %-16s VDR %s %.1f%s" % (cve, r0["sev"], r0["score"], flag))
print("   %d 条全部拿到分数 ✅" % len(BATCH))

# 🔴 口径红线自检:本批必须全是 medium 且没有 RCE。
# 一旦哪天真出了 high/critical,文案口径就得整体改写,不能让「配置静默失效」这套说法顺延。
sev_set = {r["sev"] for r in rows}
if sev_set != {"medium"}:
    die("口径红线自检失败:本批出现了非 medium 的评级 %s —— "
        "『全部 medium、无 RCE』这句话不能再写,文案要重写" % sorted(sev_set))
print("   口径红线自检:%d 条全部 medium(最高 %.1f)✅ —— 文案不许说「又一个 Log4Shell」"
      % (len(BATCH), max(r["score"] for r in rows)))


# ══════════════════════ 生成 Java ══════════════════════
def jstr(s):
    return '"%s"' % (s or "").replace("\\", "\\\\").replace('"', '\\"')


def first_sentence(text, limit=220):
    """描述原文的第一句实质内容。

    🔴 必须**先把整段拼起来再断句**,不能逐行取。VDR 原文是 asciidoc 且带硬换行,
       一句话经常被折成三行,中间还夹着一整行裸链接:

           Apache Log4j Core's
           https://…[`XmlLayout`],
           in versions up to and including 2.25.3, fails to sanitize …

       逐行取会跳过前两行、返回 "in versions up to and including 2.25.3, fails to…" ——
       **一个没有主语的残句**,而它会被原样印进报告当作「官方原文」。
       句子不完整不报错,只是读起来像是我们抄漏了。
    """
    para = []
    for line in (text or "").splitlines():
        if not line.strip():
            if para:
                break                      # 第一段结束
            continue
        para.append(line.strip())
    s = " ".join(para)
    s = re.sub(r"https?://\S+?\[([^\]]*)\]", r"\1", s)     # asciidoc 链接 → 只留显示文字
    s = re.sub(r"https?://\S+", "", s)                     # 剩下的裸链接直接去掉
    s = re.sub(r"[`*]", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    # 断在第一个句号处(要求句号后面是空格或结尾,免得被 2.25.3 里的点切开)
    m = re.search(r"\.(?=\s|$)", s)
    if m:
        s = s[:m.end()]
    return s if len(s) <= limit else s[:limit - 1] + "…"


def title_of(cve):
    """标题。

    🔴 第 9 注 ASSERT13 的由来:advisory 的 summary 长度能差三个数量级,
       有一条是**一整段** 250+ 字,原样印会把报告排版整个撑破。
       VDR 没有 summary 字段,所以标题从 GitHub 侧取(有的话),取不到就用描述第一句;
       两种来源都走同一个截断函数,规则和判定表一起被 diff 看见。
    """
    for mod in srcB:
        a = srcB[mod].get(cve)
        if a and a.get("summary"):
            s = re.sub(r"\s+", " ", a["summary"]).strip()
            break
    else:
        s = first_sentence(raw(vdr[cve], "description"))
    limit = 100
    if len(s) <= limit:
        return s
    cut = s[:limit]
    sp = cut.rfind(" ")
    return (cut if sp < limit * 0.6 else cut[:sp]) + "…"


# ASSERT17 ⭐ 描述原文必须是**完整的句子**。
#
# 🔴 由来:第一版 first_sentence 逐行取,把 asciidoc 硬换行折断的句子取成了残句
#    ("in versions up to and including 2.25.3, fails to sanitize …" —— 没有主语)。
#    报告里那一行标的是「官方原文」,残句会让人以为我们抄漏了,而且**不报错**。
#    判据:必须以大写字母开头(英文句子的主语),且以句号或省略号结尾。
print("\nASSERT17:核对描述原文是不是完整句子(不是被 asciidoc 硬换行折断的残句)...")
for cve in BATCH:
    s = first_sentence(raw(vdr[cve], "description"))
    if not s:
        die("ASSERT17 失败:%s 取不到描述原文" % cve)
    if not s[0].isupper():
        die("ASSERT17 失败:%s 的描述原文以小写开头,像是被折断的残句:%r" % (cve, s[:120]))
    if not s.endswith((".", "…")):
        die("ASSERT17 失败:%s 的描述原文没有以句号/省略号收尾:%r" % (cve, s[-60:]))
    print("   %-16s %s" % (cve, s[:88] + ("…" if len(s) > 88 else "")))
print("   %d 条描述原文均为完整句子 ✅" % len(BATCH))

TITLE_MAX = 105
long_titles = [c for c in BATCH if len(title_of(c)) > TITLE_MAX]
if long_titles:
    die("ASSERT16 失败:这些标题截断后仍超长:%s" % long_titles)
print("ASSERT16 ✅ %d 条标题截断后均 ≤ %d 字" % (len(BATCH), TITLE_MAX - 5))

ghsa_of = {}
for cve in BATCH:
    for mod in srcB:
        if cve in srcB[mod]:
            ghsa_of[cve] = srcB[mod][cve].get("ghsa_id") or ""
            break
    else:
        ghsa_of[cve] = structural_blind.get(cve, ("", ""))[0] or ""

# 结构性盲区标记:这一条 Dependabot 报不出来,报告里必须单独说
blind_flag = {c: (c in structural_blind) for c in BATCH}
# 补丁缺口链:后一环 → (前一环, 前一环的修复版)
gap_of = {b: (a, fix_of(a)) for a, b in chains}

out = [
    "package dev.mikko.log4jcheck;",
    "",
    "import java.util.ArrayList;",
    "import java.util.Collections;",
    "import java.util.List;",
    "",
    "/**",
    " * 由 tools/gen_rules.py 从**两个一手源**生成,请勿手工编辑。",
    " *",
    " * <p>源 A:Apache 官方 CycloneDX VDR(" + VDR_URL + ")",
    " *        —— 条目全集 + 逐模块精确区间 + 描述原文。",
    " *        🔴 注意 /repos/apache/logging-log4j2/security-advisories <b>实测返回 0 条</b>,",
    " *        Apache 不走 GitHub Security Advisories,只查那里会得到「log4j 很太平」且不报错。",
    " * <p>源 B:/advisories?ecosystem=maven&amp;affects=&lt;坐标&gt;(Dependabot 实际用的坐标索引)",
    " *",
    " * <p>粒度是 <b>CVE × 模块 × 版本区间</b>:本批 " + str(len(BATCH)) + " 条散布在 "
    + str(len(modules_hit)) + " 个 Maven 模块上,",
    " * 而只在 pom 里写 log4j-core 的人按坐标只查得到 " + str(len(core_visible)) + " 条。",
    " */",
    "public final class CveTable {",
    "    private CveTable() {}",
    "",
    "    public static final String GENERATED_FROM = " + jstr(
        "Apache CycloneDX VDR (logging.apache.org/cyclonedx/vdr.xml) + GitHub Advisory API") + ";",
    "",
    "    /** 四个模块共用的 groupId。 */",
    "    public static final String GROUP = " + jstr(GROUP) + ";",
    "",
    "    /** 本批涉及的模块(artifactId),判定粒度是 CVE × 模块。 */",
    "    public static final List<String> MODULES = List.of("
    + ", ".join(jstr(m) for m in modules_hit) + ");",
    "",
    "    /** 官方(源 A)本批 Java 条目总数。 */",
    "    public static final int OFFICIAL_TOTAL = %d;" % len(BATCH),
    "",
    "    /**",
    "     * 只在 pom 里写 log4j-core 的人,按坐标反查能看到的条数。",
    "     *",
    "     * <p>🔴 与 {@link #OFFICIAL_TOTAL} 的差就是「只盯 log4j-core 会漏几条」。",
    "     * 这是量出来的,gen_rules.py 的 ASSERT2 每次重跑都重新核实。",
    "     */",
    "    public static final int VISIBLE_BY_CORE_COORD = %d;" % len(core_visible),
    "",
    "    /** 四个模块坐标全查也查不到的条数 —— 即 Dependabot <b>结构性</b>报不出来的。 */",
    "    public static final int DEPENDABOT_BLIND = %d;" % len(blind_all),
    "",
    "    /** 这批 advisory 里出现最多的修复版 —— 也就是大多数人照抄的那个。 */",
    "    public static final String POPULAR_FIX = " + jstr(popular) + ";",
    "",
    "    private static final List<Cve> ALL = new ArrayList<>();",
    "",
    "    static {",
]
for r in rows:
    cve = r["cve"]
    kind, cond_text, expr, neg, _anchors = CONDITIONS[cve]
    out.append("        add(%s, %s, %s, %s, %.1f, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);" % (
        jstr(cve), jstr(ghsa_of[cve]), jstr(r["module"]), jstr(r["sev"]), r["score"],
        jstr(r["line"]),
        jstr(r["low"]), "true" if r["low_incl"] else "false",
        jstr(r["high"]), "true" if r["high_incl"] else "false",
        jstr(r["fixed"]), "true" if r.get("fixed_ok") else "false",
        "true" if blind_flag[cve] else "false",
        jstr(gap_of.get(cve, ("", ""))[0]), jstr(gap_of.get(cve, ("", ""))[1]),
        jstr(kind), jstr(cond_text), jstr(expr),
        jstr(neg[0] + "||" + neg[1] if neg else ""),
        jstr(title_of(cve)), jstr(first_sentence(r["desc"]))))
out += [
    "    }",
    "",
    "    private static void add(String cveId, String ghsaId, String module, String severity,",
    "                            double cvss, String line,",
    "                            String low, boolean lowIncl, String high, boolean highIncl,",
    "                            String fixedIn, boolean fixedAvailable, boolean dependabotBlind,",
    "                            String gapAfter, String gapAfterFix,",
    "                            String condKind, String condText, String condExpr, String negHint,",
    "                            String title, String desc) {",
    "        ALL.add(new Cve(cveId, ghsaId, module, severity, cvss, line,",
    "                        low, lowIncl, high, highIncl, fixedIn, fixedAvailable, dependabotBlind,",
    "                        gapAfter, gapAfterFix, condKind, condText, condExpr, negHint,",
    "                        title, desc));",
    "    }",
    "",
    "    public static List<Cve> all() { return Collections.unmodifiableList(ALL); }",
    "}",
]
os.makedirs(PKG, exist_ok=True)
with open(os.path.join(PKG, "CveTable.java"), "w", encoding="utf-8") as f:
    f.write("\n".join(out) + "\n")

# ── Triggers.java:元素表 + 源码标记表,同样生成,别在 Java 里手抄一份 ──
tg = [
    "package dev.mikko.log4jcheck;",
    "",
    "import java.util.LinkedHashMap;",
    "import java.util.List;",
    "import java.util.Map;",
    "import java.util.regex.Pattern;",
    "",
    "/**",
    " * 触发条件的词表,由 tools/gen_rules.py 生成,请勿手工编辑。",
    " *",
    " * <p>分两层,可靠程度不同,报告里必须分开说:",
    " * <ul>",
    " *   <li><b>元素层</b> —— log4j2 配置里的插件/元素名。XML 与 properties 走**结构化解析**",
    " *       (元素名、属性归属都是读出来的);YAML / JSON / 源码只能走文本匹配。",
    " *   <li><b>词标记层</b> —— 只能文本匹配的东西(MapMessage、asJson() 之类)。",
    " * </ul>",
    " *",
    " * <p>🔴 <b>两组只差一点的名字,必须分得开</b>,否则用户会额外背上一条不属于他的 CVE:",
    " * <ul>",
    " *   <li>{@code XmlLayout}(CVE-2026-34480,log4j-core)vs",
    " *       {@code Log4j1XmlLayout}(CVE-2026-34479,1.2-api 桥)—— 前者是后者的子串。",
    " *   <li>{@code verifyHostName}(大写 N,{@code <Ssl>},CVE-2026-34477)vs",
    " *       {@code verifyHostname}(小写 n,HTTP appender,官方原文写明**不受影响**)。",
    " * </ul>",
    " * gen_rules.py 的 ASSERT14 在生成期就用正反样本各测一遍,不满足就不生成。",
    " */",
    "public final class Triggers {",
    "    private Triggers() {}",
    "",
    "    /** 判断「这份配置到底是不是 log4j2 配置」的上锚。 */",
    "    public static final String ANCHOR = " + jstr(ANCHOR) + ";",
    "",
    "    private static final Map<String, List<Pattern>> ELEMENTS = new LinkedHashMap<>();",
    "    private static final Map<String, Pattern> MARKERS = new LinkedHashMap<>();",
    "    private static final Map<String, String> LABELS = new LinkedHashMap<>();",
    "    private static final Map<String, java.util.Set<String>> ATTRS = new LinkedHashMap<>();",
    "",
    "    static {",
]
for name, (pats, label) in ELEMENTS.items():
    tg.append("        elem(%s, %s, %s);" % (jstr(name), jstr(label),
                                             ", ".join(jstr(p) for p in pats)))
for name, (rx, label) in SOURCE_MARKERS.items():
    tg.append("        mark(%s, %s, %s);" % (jstr(name), jstr(rx), jstr(label)))

# 判定表里 A: token 用到的属性名 —— 结构化解析时按「元素@属性」精确比对;
# YAML / JSON / 源码只能文本匹配,此时只知道「属性名出现过」而不知道它挂在谁身上,
# 记成 ?@属性名,报告里必须把这个差别说出来。
_attr_tokens = set()
for _c in BATCH:
    _expr, _neg = CONDITIONS[_c][2], CONDITIONS[_c][3]
    for _grp in _expr.split(";"):
        for _t in (x.strip() for x in _grp.split("|")):
            if _t.startswith("A:"):
                _attr_tokens.add(_t[2:])
    if _neg and _neg[0].startswith("A:"):
        _attr_tokens.add(_neg[0][2:])
for _tok in sorted(_attr_tokens):
    _elem, _, _attr = _tok.partition("@")
    tg.append("        attr(%s, %s);" % (jstr(_elem), jstr(_attr)))

tg += [
    "    }",
    "",
    "    private static void elem(String name, String label, String... regexes) {",
    "        List<Pattern> ps = new java.util.ArrayList<>();",
    "        for (String r : regexes) {",
    "            ps.add(Pattern.compile(r));",
    "        }",
    "        ELEMENTS.put(name, List.copyOf(ps));",
    "        LABELS.put(name, label);",
    "    }",
    "",
    "    private static void mark(String name, String regex, String label) {",
    "        MARKERS.put(name, Pattern.compile(regex));",
    "        LABELS.put(name, label);",
    "    }",
    "",
    "    private static void attr(String element, String attribute) {",
    "        ATTRS.computeIfAbsent(attribute, k -> new java.util.LinkedHashSet<>()).add(element);",
    "    }",
    "",
    "    /** 元素名 → 用于**文本兜底**的正则(结构化解析时不用它们,直接比元素名)。 */",
    "    public static Map<String, List<Pattern>> elements() { return ELEMENTS; }",
    "",
    "    /** 词标记名 → 正则。 */",
    "    public static Map<String, Pattern> markers() { return MARKERS; }",
    "",
    "    /**",
    "     * 判定表关心的属性名 → 它可能挂在哪些元素上。",
    "     *",
    "     * <p>🔴 {@code verifyHostName}(大写 N)只挂在 {@code Ssl} 上,",
    "     * {@code verifyHostname}(小写 n)只挂在 {@code Http} 上 —— 两个键在这张表里是分开的,",
    "     * 这就是「一个字母之差不许混」在数据结构层面的落点。",
    "     */",
    "    public static Map<String, java.util.Set<String>> attrs() { return ATTRS; }",
    "",
    "    public static String label(String name) { return LABELS.getOrDefault(name, name); }",
    "}",
]
with open(os.path.join(PKG, "Triggers.java"), "w", encoding="utf-8") as f:
    f.write("\n".join(tg) + "\n")

print("\n✅ 已生成 CveTable.java + Triggers.java")
print("   官方本批 %d 条 → 展开成 %d 条「CVE × 模块 × 区间」规则,涉及 %d 个模块"
      % (len(BATCH), len(rows), len(modules_hit)))
print("   只盯 log4j-core 会漏 %d 条;任何坐标都查不到的 %d 条" % (len(blind_core), len(blind_all)))
print("   各模块 × 维护分支的交集目标:" + ", ".join("%s/%s=%s" % (m, ln, targets[(m, ln)]) for m, ln in sorted(targets)))

json.dump({"rows": [{k: v for k, v in r.items() if k not in ("desc", "rec")} for r in rows],
           "batch": BATCH, "modules": modules_hit,
           "core_visible": core_visible, "all_visible": all_visible,
           "blind_core": blind_core, "blind_all": blind_all,
           "structural_blind": {k: list(v) for k, v in structural_blind.items()},
           "chains": [list(c) for c in chains],
           "targets": {"%s|%s" % k: v for k, v in targets.items()}, "popular": popular, "beyond": beyond,
           "ghosts": ["%s|%s" % k for k in ghosts],
           "titles": {c: title_of(c) for c in BATCH},
           "first_sentence": {c: first_sentence(raw(vdr[c], "description")) for c in BATCH}},
          open(os.path.join(HERE, "rules_dump.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)
print("   → tools/rules_dump.json 已更新(供文案与复核脚本引用)")
