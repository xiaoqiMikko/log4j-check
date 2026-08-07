# -*- coding: utf-8 -*-
r"""发文前的**独立口径**事实复核。用法:python tools/recheck_before_publish.py <文案文件>

🔴 **本脚本刻意不读 gen_rules.py 的任何输出**(不读 rules_dump.json、不读 CveTable.java)。
   理由是第 6 注的教训:完整性检查和正确性检查是两回事。
   如果复核用的是同一份解析结果,那它只能证明「我前后一致」,证不了「我说的是对的」——
   而解析 bug 恰好会让前后完全一致。所以这里全部重新拉,而且换源:

     独立源 ①  OSV.dev API(独立聚合器,不是 GitHub advisory 那份)
     独立源 ②  Apache 官方安全**网页** security.html(和 vdr.xml 是两个产物,同源不同渲染)
     独立源 ③  Maven Central(修复版到底拿不拿得到 / 2.26.x 线到底存不存在)

   三个源各自算出承重数字,再和文案里写的对一遍。任一项不符 → 中止,不许发。

🔴 另外查**口径红线**。本批全是 medium、没有 RCE,文案里不许出现「又一个 Log4Shell」这类说法。
   判据必须**读得出立场** —— 第 9 注在这里栽过一次:朴素的子串匹配会把
   「**不是**又一个 Log4Shell」判成踩线,而照那个判据改文案,
   就会亲手删掉唯一在防止说过头的那句话。所以这里要求:该短语出现时前面必须紧跟否定词。
"""
import json
import re
import sys
import urllib.error
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BATCH = ["CVE-2026-49844", "CVE-2026-34481", "CVE-2026-34480", "CVE-2026-34479",
         "CVE-2026-34478", "CVE-2026-34477", "CVE-2025-68161"]
GROUP_PATH = "org/apache/logging/log4j"
FAIL = []


def note(ok, label, detail=""):
    print(("   ✅ " if ok else "   🔴 ") + label + ("  " + detail if detail else ""))
    if not ok:
        FAIL.append(label + " " + detail)


def get(url, timeout=90, data=None, headers=None):
    h = {"User-Agent": "Mozilla/5.0"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h)
    return urllib.request.urlopen(req, timeout=timeout).read()


def head_code(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}, method="HEAD")
        return urllib.request.urlopen(req, timeout=60).getcode()
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        sys.exit("🔴 探测失败 %s:%s —— 拿不到 ≠ 不存在,中止" % (url, str(e)[:120]))


if len(sys.argv) < 2:
    sys.exit("用法:python tools/recheck_before_publish.py <文案文件>")
DOC = open(sys.argv[1], encoding="utf-8").read()
print("复核对象:%s(%d 字)\n" % (sys.argv[1], len(DOC)))

# ══════════════ 独立源 ①:OSV.dev ══════════════
#
# 🔴 OSV 里同一个漏洞有**两种记录**,数据完全不同,这一点必须先说清楚:
#      `CVE-xxxx` 记录来自 CVE/NVD 源,只带 GIT commit 区间,**没有 Maven 包数据**;
#      `GHSA-xxxx` 记录才带 Maven 坐标与修复版。
#    所以要先从 CVE 记录拿 alias 找到 GHSA,再去查 GHSA。
#    第一版直接查 CVE 记录、然后断言「有 Maven 模块」,结果 7 条全部量出 0 个模块 ——
#    **判据量的东西和它想验证的事情差了一层**(第 9 注栽三次的同一个病)。
print("独立源 ①:OSV.dev —— 先按 CVE 拿 alias,再按 GHSA 拿 Maven 坐标")
osv = {}
for cve in BATCH:
    try:
        d = json.loads(get("https://api.osv.dev/v1/vulns/" + cve))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            osv[cve] = {"ghsa": [], "modules": set(), "fixes": set()}
            print("      %-16s OSV 里没有这条 CVE 记录(404)" % cve)
            continue
        sys.exit("🔴 OSV 请求失败 %s:%s" % (cve, e))
    ghsas = [a for a in (d.get("aliases") or []) if a.startswith("GHSA-")]
    mods, fixes = set(), set()
    for g in ghsas:
        try:
            gd = json.loads(get("https://api.osv.dev/v1/vulns/" + g))
        except urllib.error.HTTPError:
            continue
        for a in gd.get("affected") or []:
            pkg = (a.get("package") or {}).get("name") or ""
            if pkg.startswith("org.apache.logging.log4j:"):
                mods.add(pkg.split(":")[1])
                for r in a.get("ranges") or []:
                    for ev in r.get("events") or []:
                        if ev.get("fixed"):
                            fixes.add(ev["fixed"])
    osv[cve] = {"ghsa": ghsas, "modules": mods, "fixes": fixes}
    print("      %-16s alias=%-24s 模块 %-44s 修复版 %s"
          % (cve, ",".join(ghsas) or "(无)", ",".join(sorted(mods)) or "(空)",
             ",".join(sorted(fixes)) or "(空)"))

print("\n承重结论逐条复核:")

# 承重一:多模块 —— 只盯 log4j-core 会漏
mods_all = set()
for v in osv.values():
    mods_all |= v["modules"]
note(len(mods_all) >= 3,
     "本批散布在多个 Maven 模块上(OSV 独立口径 %d 个:%s)"
     % (len(mods_all), ",".join(sorted(mods_all))))
non_core = sorted(c for c, v in osv.items()
                  if v["modules"] and "log4j-core" not in v["modules"])
note(len(non_core) >= 2,
     "只盯 log4j-core 会漏掉的条目(OSV 口径 %d 条:%s)" % (len(non_core), non_core))

# 承重二 ⭐ CVE-2026-49844 在 OSV 里既没有 GHSA alias、也没有任何 Maven 坐标
#          —— 这是「Dependabot 结构性报不出」在第三个源上的独立佐证
v = osv["CVE-2026-49844"]
note(not v["modules"],
     "CVE-2026-49844 在 OSV 里**也**拿不到 Maven 包/版本数据",
     "(alias=%s,模块=%s)—— 「Dependabot 结构性报不出」的独立佐证"
     % (v["ghsa"] or "无", sorted(v["modules"])))
others_with_data = [c for c in BATCH if c != "CVE-2026-49844" and osv[c]["modules"]]
note(len(others_with_data) == 6,
     "而另外 6 条在 OSV 里都拿得到 Maven 坐标(说明不是 OSV 整体没数据)",
     "实测 %d 条:%s" % (len(others_with_data), others_with_data))

# ══════════════ 独立源 ②:Apache 官方安全网页 ══════════════
print("\n独立源 ②:Apache 官方安全**网页**(与 vdr.xml 是两个产物)")
html = get("https://logging.apache.org/log4j/2.x/security.html").decode("utf-8", "replace")
txt = re.sub(r"<[^>]+>", "\n", re.sub(r"<(script|style).*?</\1>", "", html, flags=re.S))
txt = re.sub(r"\n+", "\n", txt)
missing = [c for c in BATCH if c not in html]
note(not missing, "7 条全部在官方网页上找得到", "缺:%s" % missing if missing else "")

# 网页上的 Components affected / Versions fixed 与文案说法对一遍
# 🔴 **必须锚在条目的起始处,不能只找 CVE 编号第一次出现的地方。**
#
#    这是第 6 注那个 bug 的原样重演(`bets/6-tomcat.md`:「标题里嵌别的 CVE 链接
#    → 条目张冠李戴」),而它这次是在**复核脚本**里被抓到的:
#    "CVE-2026-34481" 第一次出现是在 **CVE-2026-49844 的正文**里
#    (“The fix for CVE-2026-34481 did not cover all code paths”),
#    于是往后取 2200 字的窗口落到了下一个条目上,把 34481 读成了 Log4cxx / 1.7.0。
#    页面上每个条目的结构是「CVE 编号」紧跟一行「Summary」,拿这个当锚就准了。
blocks = {}
for c in BATCH:
    m = re.search(re.escape(c) + r"\s*\nSummary\s*\n(.{0,2600})", txt, re.S)
    if not m:
        note(False, "%s 在官方网页上找不到条目起始锚(CVE 编号 + Summary)" % c,
             "—— 页面结构可能变了,别用可能张冠李戴的窗口去核对")
        blocks[c] = ""
    else:
        blocks[c] = m.group(1)
web_fix = {}
for c in BATCH:
    m = re.search(r"Versions fixed\s*\n([\d.]+)", blocks[c])
    web_fix[c] = m.group(1) if m else ""
    m2 = re.search(r"Components affected\s*\n([^\n]+)", blocks[c])
    print("      %-16s 网页 Components=%-30s Versions fixed=%s"
          % (c, (m2.group(1).strip() if m2 else "?"), web_fix[c] or "?"))

# 承重三:6 条修复版 ≤ 2.25.4,而 CVE-2026-49844 要 2.25.5 —— 这是核心主张
note(web_fix.get("CVE-2026-49844") == "2.25.5",
     "官方网页上 CVE-2026-49844 的修复版是 2.25.5(不是 2.25.4)",
     "实读:%r" % web_fix.get("CVE-2026-49844"))
lower = [c for c in BATCH if c != "CVE-2026-49844" and web_fix.get(c) in ("2.25.3", "2.25.4")]
note(len(lower) == 6,
     "另外 6 条的修复版都是 2.25.3/2.25.4(所以「升到 2.25.4」是大多数人会得出的答案)",
     "符合的 %d 条:%s" % (len(lower), lower))

# 承重四:两条补丁缺口链的原文措辞
note("The fix for" in blocks["CVE-2026-34477"] and "incomplete" in blocks["CVE-2026-34477"],
     "CVE-2026-34477 原文自称是 CVE-2025-68161 的不完整修复")
note("did not cover all" in blocks["CVE-2026-34481"] or "CVE-2026-49844" in blocks["CVE-2026-34481"],
     "CVE-2026-34481 原文点名 CVE-2026-49844 是它没盖住的部分")

# 承重五:口径 —— 网页上这批的评级
sev = re.findall(r"(\d\.\d)\s+(MEDIUM|HIGH|CRITICAL|LOW)", html)
batch_sevs = set()
for c in BATCH:
    m = re.search(r"(\d\.\d)\s+(MEDIUM|HIGH|CRITICAL|LOW)", blocks[c])
    if m:
        batch_sevs.add(m.group(2))
note(batch_sevs == {"MEDIUM"},
     "本批 7 条在官方网页上全部是 MEDIUM(没有 high/critical,也没有 RCE)",
     "实读:%s" % sorted(batch_sevs))

# ══════════════ 独立源 ③:Maven Central ══════════════
print("\n独立源 ③:Maven Central —— 修复版到底拿不拿得到")
for mod, ver in [("log4j-core", "2.25.4"), ("log4j-api", "2.25.5"),
                 ("log4j-1.2-api", "2.25.4"), ("log4j-layout-template-json", "2.25.4"),
                 ("log4j-api", "2.26.1")]:
    code = head_code("https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.jar"
                     % (GROUP_PATH, mod, ver, mod, ver))
    note(code == 200, "%s:%s 可获取" % (mod, ver), "HTTP %d" % code)
ctrl = head_code("https://repo1.maven.org/maven2/%s/log4j-core/2.99.99/log4j-core-2.99.99.jar"
                 % GROUP_PATH)
note(ctrl != 200, "负对照 log4j-core:2.99.99 拿不到(证明上面那些 200 是真的)", "HTTP %d" % ctrl)

# ══════════════ 口径红线 ══════════════
print("\n口径红线(判据要读得出立场,不做朴素子串匹配):")
NEG = ("不是", "不许", "没有", "绝不", "不该", "并非", "谈不上", "远不", "别")


def unnegated(text, phrase):
    """返回该短语所有**没有被否定**的出现位置上下文。"""
    bad = []
    i = text.find(phrase)
    while i >= 0:
        before = text[max(0, i - 16):i]
        if not any(n in before for n in NEG):
            bad.append(text[max(0, i - 45):i + len(phrase) + 15].replace("\n", " "))
        i = text.find(phrase, i + 1)
    return bad


for phrase in ["又一个 Log4Shell", "新的 Log4Shell", "又出大洞", "严重漏洞", "高危漏洞",
               "紧急升级", "远程代码执行", "RCE"]:
    bad = unnegated(DOC, phrase)
    note(not bad, "文案里没有未被否定的「%s」" % phrase,
         "踩线上下文:%s" % bad[:2] if bad else "")

print("\n免责与边界(这几句必须在文案里,少一句就等于在暗示「扫过就没事」):")
REQUIRED = [
    ("medium", "要明说本批评级是 medium"),
    ("不等于安全", "要明说「没找到触发条件 ≠ 安全」"),
    ("文本匹配", "要明说 YAML/JSON 只能文本匹配,分不清属性归属"),
    ("排优先级", "要明说结论只够排优先级,不够宣布事故"),
]
for kw, why in REQUIRED:
    note(kw in DOC, why, "(缺关键词 %r)" % kw if kw not in DOC else "")

print("\n口径提醒(不是断言,人自己核):")
print("   · 「只盯 log4j-core 会漏 3 条」是**按坐标反查**的口径,")
print("     不等于「Dependabot 会漏 3 条」—— Dependabot 按你真实的依赖树逐模块告警。")
print("     真正的结构性盲区只有 1 条(CVE-2026-49844)。这两个数字不许混着写。")
print("   · 装机面 84,480 是**命中 pom.xml 的仓库数**,不是「有多少项目受影响」,更不是「多少人在搜」。")

print()
if FAIL:
    print("🔴 %d 项不通过,**不许发**:" % len(FAIL))
    for f in FAIL:
        print("   · " + f)
    sys.exit(1)
print("✅ 独立口径复核全部通过。")
