# log4j-check

**log4j 2025/2026 年这批「配置静默失效」公告的自查工具。** 零运行时依赖,单个 jar,不联网。

> ⚠️ **先把口径说清楚:这批全是 medium,一条 RCE 都没有,不是 Log4Shell 那种。**
> 它们的共同点是 **配置在没有任何报错的情况下失效了** —— 属性被静默忽略、
> 属性被静默改名、日志被静默丢掉。所以光看版本号看不出你到底中没中,要读配置。
> 如果你在找 CVE-2021-44228(Log4Shell),这个工具帮不了你。

```
java -jar log4j-check.jar app.jar          # fat jar 里带配置,一步到位
java -jar log4j-check.jar ./target ./src   # 构建产物 + 源码
java -jar log4j-check.jar ~/.m2/repository --no-config
```

## 它回答什么问题

Dependabot 告诉你「log4j 有 N 个漏洞」。这个工具回答三个它不回答的:

1. **你到底该升到哪个版本?** —— 不是照抄某一条 advisory,是把命中的条目**逐条求交集**。
2. **这 7 条里你真中几条?** —— 每条都要求你用了某个特定的 layout / appender,
   而那些东西写在 `log4j2.xml` 里,**能读,而且能读准**。
3. **你是不是属于「已经升过级、以为修完了」的那批人?** —— 这批里有两条补丁缺口链。

## 三个承重结论(都可以自己复核)

### 一、🔥 升到 2.25.4 的人没升到位,而漏掉的那条 Dependabot 报不出来

这批 7 条里,**6 条的修复版都 ≤ 2.25.4**。于是绝大多数人会得出「升到 2.25.4」这个答案。

但 **`CVE-2026-49844` 要 2.25.5**(2.26 线上要 2.26.1)。它的 advisory 原文写着自己是
`CVE-2026-34481` 的不完整修复:

> The fix released in version `2.25.4` did not cover all affected code paths.
> CVE-2026-49844 was assigned to the remaining issue …

而这一条**恰好是 Dependabot 结构性报不出来的那一条**:
它的 GitHub advisory(`GHSA-qv9r-c865-cp47`)是 `unreviewed`,
且 `vulnerabilities` 数组**为空** —— 没有包名、没有版本区间、没有修复版,
Dependabot 拿不到任何可以跟你的依赖树比对的数据。

在 OSV.dev 上同样如此:另外 6 条都能通过 GHSA alias 拿到 Maven 坐标,**只有它拿不到**
(它在 OSV 里连 GHSA alias 都没有)。这是第三个源上的独立佐证,
`tools/recheck_before_publish.py` 每次重跑都会重新核实。

> 🔴 **这一条别读成「Dependabot 不好用」。** 它是「这条数据不存在」,不是「这个工具有 bug」。

另一条链是 `CVE-2025-68161`(2.25.3)→ `CVE-2026-34477`(2.25.4):
`verifyHostName` **属性**自 2.12.0 引入,却一路到 2.25.3 都被静默忽略,
配了等于没配。照 68161 升到 2.25.3、且用属性(而不是 system property)配主机名校验的人,仍然中招。

### 二、判定粒度是 CVE × **模块**,共 4 个模块

| 模块 | 命中条目 | 该升到 |
|---|---|---|
| `log4j-core` | 34477 / 34478 / 34480 / 68161 | **2.25.4** |
| `log4j-api` | **49844** | **2.25.5**(2.26 线:2.26.1) |
| `log4j-1.2-api` | 34479 | 2.25.4 |
| `log4j-layout-template-json` | 34481 | 2.25.4 |

**目标版本不是同一个数字。** 而绝大多数项目的 pom 里只写 `log4j-core`
—— 按那一个坐标反查只查得到 **4 条**,另外 3 条对他们来说根本不存在。

这个工具把四个模块**分别**扫出版本并**分别**判定。四个模块版本错开时(BOM 覆盖、
手工排除、老 WAR 里塞着两代 jar)它会明确报出来。

### 三、降噪:每条都要求特定的 layout / appender,而那写在配置里

| CVE | 触发条件(取自官方原文) |
|---|---|
| `CVE-2026-34477` | `<Ssl>` 的 **`verifyHostName`** 属性 + Socket / Syslog / SMTP appender |
| `CVE-2025-68161` | `SocketAppender` + TLS |
| `CVE-2026-34478` | **直接**配 `Rfc5424Layout`(用 `SyslogAppender` 的不受影响) |
| `CVE-2026-34480` | log4j-core 的 `XmlLayout` |
| `CVE-2026-34479` | 桥的 `Log4j1XmlLayout`,或 log4j 1 兼容层 + `org.apache.log4j.xml.XMLLayout` |
| `CVE-2026-34481` | `JsonTemplateLayout` + `MapMessage`/`ObjectMessage` 里的浮点值 |
| `CVE-2026-49844` | `JsonTemplateLayout` 的 message resolver,或 `MapMessage.asJson()` |

实测(真实构件,见下):同一套装了受影响版本的四个模块,

- 配置是最常见的那种(`Console` + `RollingFile` + `PatternLayout`)→ 版本层报 **7 条**,真中 **0 条**
- 配置里有 `Socket`+`<Ssl verifyHostName>`+`Rfc5424Layout`+`XmlLayout` → 报 7 条,真中 **4 条**

**两个负判据是官方原文明说的,单独成档:**
用 `SyslogAppender` 的不中 34478;只用 HTTP appender 的 `verifyHostname` 的不中 34477。
这一档和「我没找到」的可靠程度完全不同 —— 前者有原文背书,后者只是我们没看见。

> 🔴 **`verifyHostName`(大写 N,`<Ssl>`,中招)与 `verifyHostname`(小写 n,HTTP appender,
> 官方写明**不受影响**)只差一个字母的大小写,结论完全相反。**
> 同理 `XmlLayout`(34480,log4j-core)是 `Log4j1XmlLayout`(34479,桥)的**子串**。
> 只 grep 名字会让人额外背上不属于他的 CVE。所以配置层做**结构化解析**而不是文本匹配。

## 它怎么读你的配置

| 格式 | 怎么读 | 能不能判准属性归属 |
|---|---|---|
| `log4j2*.xml`(含 strict 模式 `<Appender type="…">`) | DOM 解析,XXE 已关 | ✅ |
| `log4j2*.properties` | 按 `xxx.type = Foo` 建前缀→插件映射 | ✅ |
| `log4j2*.yaml` / `.json` | 文本匹配(JDK 无 YAML 解析器,而本工具坚持零依赖) | ❌ 标为「文本依据」 |
| `.java` | 文本匹配(已剥注释,认字符串) | ❌ |

配置**在归档内部也扫**(`BOOT-INF/classes/`、`WEB-INF/classes/`),
所以只丢一个 Spring Boot fat jar 给它,降噪也做得成 —— 不需要源码树。

`log4j-spring.xml` / `log4j2-test.xml` / `log4j.xml`(1 兼容层)都认。

## 🔴 这个报告不能证明什么

**「没找到触发条件」不等于安全**,至少四种情况会让它变成假的安心:

1. 配置是**代码里构建**的(`ConfigurationBuilder` / `Configurator.initialize`);
2. 配置运行时才注入(`log4j2.configurationFile` 指别处、容器里挂进来);
3. 第三方库自带一份 log4j2 配置而没被扫到;
4. 你压根没把配置传进来 —— 这种情况报告会单独标成「**本次没看到配置**」,
   而不是「不适用」。这两句话该导致完全不同的动作。

**「触发条件全部成立」也不等于确认中招**:多数条目还要求「攻击者能控制被记进日志的那个值」,
这一点工具判不了。所以结论只够用来**排优先级**,不够用来宣布事故。

**本工具不覆盖 log4j 1.x**(`log4j:log4j`)。扫到会告警,但不判定 —— 它是另一套代码。

## 判定表是生成的,不是手抄的

```
python tools/gen_rules.py          # 从两个一手源重建 CveTable.java + Triggers.java
```

- **源 A** = Apache 官方 CycloneDX VDR(`logging.apache.org/cyclonedx/vdr.xml`)——
  条目全集 + 逐模块精确区间 + 描述原文。
  > 🔴 `/repos/apache/logging-log4j2/security-advisories` **实测返回 0 条** ——
  > Apache 不走 GitHub Security Advisories。只查那个端点会得到「log4j 很太平」,而且不报错。
- **源 B** = GitHub advisory DB 按坐标反查(= Dependabot 实际用的索引),四个模块各查一次。

**17 条断言**,任一不满足就中止不写文件。其中几条是承重的:

| 断言 | 钉住的事 |
|---|---|
| ASSERT2 | 双源盲区:官方 7 条 vs 单坐标 4 条 vs 四坐标 6 条,三个数字都要量出来 |
| ASSERT13 | 那 1 条结构性盲区必须**能给出可复核的理由**,不许写死在文案里 |
| ASSERT7 | 每个修复版去 Central 实测 + **负对照**(证明探测器真会说「拿不到」) |
| ASSERT8 | 修复版是从区间上界推导的 → 必须逐字出现在官方 recommendation 原文里 |
| ASSERT9 | 两条补丁缺口链的原文措辞 + 后一环修复版必须真的更高 |
| ASSERT10 | 照最常见的修复版升级必须仍有漏 —— 否则「求交集」没价值 |
| ASSERT14 | `XmlLayout`≠`Log4j1XmlLayout`、`verifyHostName`≠`verifyHostname`,**正反样本各测一次** |
| ASSERT17 | 描述原文必须是完整句子,不是被 asciidoc 硬换行折断的残句 |

## 验证做到哪一步

- **93 个单测**,含报告**渲染层**的测试(不只测内部返回值,测印出来的字)
- **12 个真实构件场景**:14 个从 Maven Central 下的真 jar 拼成 Spring Boot fat jar / WAR /
  裸 m2 目录 / 源码树,端到端跑
- **发文前独立口径复核**(`tools/recheck_before_publish.py`):
  **不读生成脚本的任何输出**,换三个源(OSV.dev / 官方安全网页 / Maven Central)重新算一遍

真实构件复验抓到 3 个单测测不出的问题,都已修 + 加回归:

1. 真 `log4j-api` jar 里自带 `Log4j-charsets.properties`,被当成了用户的 log4j2 配置 →
   **「本次没看到配置」被翻译成「看过了,没找到」**,而只要 classpath 上有 log4j-api,
   这个翻译就一直在发生。
2. 一个标着「触发条件成立的:N 条」的数字把**部分成立**也算了进去 ——
   而这个数字是本工具唯一的卖点。现在拆成两个。
3. 纯 YAML 配置的命中被印成「**结构化解析,依据最硬**」——
   那份配置从头到尾没有被结构化解析过一次。

## 退出码

| 码 | 含义 |
|---|---|
| 0 | 版本没中 |
| 2 | 版本中,但配置里没找到触发条件(或本次没看到配置) |
| 3 | 触发条件也成立 |

## 构建

JDK 17+,`mvn package`。运行时零依赖 —— **尤其不依赖 log4j 本身**:
一个排查 log4j 配置问题的工具自己带着一份 log4j,会在扫自己的目录时把自己报出来。

## 一手来源

- Apache Log4j 安全公告:https://logging.apache.org/log4j/2.x/security.html
- CycloneDX VDR:https://logging.apache.org/cyclonedx/vdr.xml
- `CVE-2026-34477` https://github.com/advisories/GHSA-6hg6-v5c8-fphq
- `CVE-2026-34478` https://github.com/advisories/GHSA-445c-vh5m-36rj
- `CVE-2026-34479` https://github.com/advisories/GHSA-h383-gmxw-35v2
- `CVE-2026-34480` https://github.com/advisories/GHSA-3pxv-7cmr-fjr4
- `CVE-2026-34481` https://github.com/advisories/GHSA-w35j-pv5h-q9q9
- `CVE-2026-49844` https://github.com/advisories/GHSA-qv9r-c865-cp47 ← unreviewed,无包数据
- `CVE-2025-68161` https://github.com/advisories/GHSA-vc5p-v9hr-52mj

Apache License 2.0

<!-- cta:hire -->

---

## 需要更进一步的排查?

这个工具回答的是「**我中没中**」。下面这些它答不了,可以找我做:

- 依赖被 shade / relocate 过,或者构建产物根本拿不到
- 要判的是「这条 CVE 在**我们的调用链上**到底会不会触发」,而不只是版本命中
- 要按你们自己的构建流程或内网环境做定制、接进现有流水线
- 手上是**另一个**组件的同类问题,还没有现成工具

📮 **sikongjuechen@gmail.com** —— 说清情况,我 24 小时内给你一页书面答复:
能不能做、难在哪、大概多久。**这一步免费,也不用你先承诺什么。**
