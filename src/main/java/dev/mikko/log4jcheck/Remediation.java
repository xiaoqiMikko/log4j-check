package dev.mikko.log4jcheck;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 逐条求交集,算出「盖住你命中的全部条目的那个版本」——<b>按模块分别算</b>。
 *
 * <p>🔴 <b>这是本工具最硬的一块。</b>本批 7 条里有 6 条的修复版都 ≤ {@code 2.25.4},
 * 只有 {@code CVE-2026-49844} 要 {@code 2.25.5}(或 2.26 线上的 {@code 2.26.1})。
 * 而 {@code CVE-2026-49844} 挂在 <b>{@code log4j-api}</b> 上,不是 {@code log4j-core}。
 *
 * <p>于是有了这批 advisory 里最容易踩的那一脚:
 * <ul>
 *   <li>你看到 6 条 advisory 都写「升到 2.25.4」,于是把 log4j 升到 2.25.4;
 *   <li>{@code log4j-api} 跟着 BOM 也到了 2.25.4;
 *   <li><b>{@code CVE-2026-49844} 还在</b> —— 它要 2.25.5。
 * </ul>
 * <p>⚠️ <b>2026-08-16 修正</b>:这里原本写着「而这一条的 GitHub advisory 是 {@code unreviewed}
 * 且没有任何包/版本数据,Dependabot 不会提醒你」。
 * {@code GHSA-qv9r-c865-cp47} 已于 <b>2026-08-13</b> 转 {@code reviewed} 并补齐两条 2.x 区间
 * ({@code >=2.13.1,<2.25.5} 与 {@code >=2.26.0,<2.26.1}),所以<b>跑 2.x 的人现在收得到告警了</b>;
 * 仍然报不出来的只剩 <b>3.x 预览线</b>(见 {@link Cve#dependabotBlind()},该标志已按版本线逐行修正)。
 * <b>上面那条升级结论完全不受影响</b> —— 升到 2.25.4 仍然不够,{@code log4j-api} 仍要 2.25.5。
 *
 * <p>本批还有两条独立的「补丁不完整」链,原文自己写着:
 * {@code CVE-2025-68161}(2.25.3)→ {@code CVE-2026-34477}(2.25.4);
 * {@code CVE-2026-34481}(2.25.4)→ {@code CVE-2026-49844}(2.25.5)。
 *
 * <p>算法本身刻意做得简单到能被人核对:<b>把命中条目的修复版按「模块 × 版本线」分组,取最大值。</b>
 * 不做跨大版本线的比较 —— 2.x 用户不该被推去升 3.x(那还是 beta)。
 */
public final class Remediation {

    /**
     * @param module      该升哪个模块
     * @param target      目标版本
     * @param available   这个版本在 Maven Central 上拿不拿得到
     * @param current     你现在的版本
     * @param crossBranch 目标版本是不是跨了次版本分支(如 2.17 → 2.25),升级风险更大
     * @param covers      升到它能盖住的 CVE 编号
     * @param drivenBy    把目标顶到这么高的那一条(即「照多数 advisory 升级会漏的那条」)
     * @param blindDriven {@link #drivenBy} 那条是不是 Dependabot 结构性盲区
     */
    public record Plan(String module, String target, boolean available, Log4jVersion current,
                       boolean crossBranch, List<String> covers, String drivenBy,
                       boolean blindDriven) {
    }

    /**
     * 按模块 + 版本线求交集。
     *
     * @param hits 版本命中的规则(触发条件是否成立不影响升级目标 —— 装了受影响版本就该升)
     */
    public static List<Plan> plan(List<Cve> hits, List<Scanner.Artifact> scanned) {
        // key = 模块 + "|" + 版本线,例如 "log4j-core|2.x"
        Map<String, List<Cve>> byLine = new LinkedHashMap<>();
        for (Cve c : hits) {
            byLine.computeIfAbsent(c.module() + "|" + c.line(), k -> new ArrayList<>()).add(c);
        }

        List<Plan> plans = new ArrayList<>();
        for (Map.Entry<String, List<Cve>> e : byLine.entrySet()) {
            String module = e.getKey().substring(0, e.getKey().indexOf('|'));
            Cve top = null;
            for (Cve c : e.getValue()) {
                if (c.fixedIn().isEmpty()) {
                    continue;
                }
                if (top == null || newer(c.fixedIn(), top.fixedIn())) {
                    top = c;
                }
            }
            List<String> covers = new ArrayList<>();
            for (Cve c : e.getValue()) {
                if (!covers.contains(c.cveId())) {
                    covers.add(c.cveId());
                }
            }
            if (top == null) {
                // 🔴 官方没给修复版(本批 3.x 就是这样)—— 必须显式说出来,
                //    不许静默跳过,也不许拿 2.x 的版本号糊上去。
                plans.add(new Plan(module, "", false, currentOf(scanned, module), false,
                        covers, "", false));
                continue;
            }
            Log4jVersion current = currentOf(scanned, module);
            Log4jVersion tv = Log4jVersion.parse(top.fixedIn());
            boolean cross = current != null && tv != null && !current.branch().equals(tv.branch());
            plans.add(new Plan(module, top.fixedIn(), top.fixedAvailable(), current, cross,
                    covers, top.cveId(), top.dependabotBlind()));
        }
        return plans;
    }

    /** 你当前装的、属于这个模块的版本(取最低的那份 —— 它是短板)。 */
    private static Log4jVersion currentOf(List<Scanner.Artifact> scanned, String module) {
        Log4jVersion current = null;
        for (Scanner.Artifact a : scanned) {
            if (a.module().equals(module)
                    && (current == null || a.version().compareTo(current) < 0)) {
                current = a.version();
            }
        }
        return current;
    }

    /**
     * 找出「照这批 advisory 里最常见的那个修复版升级,仍然中的那几条」。
     *
     * <p>这是文章和报告里的承重数字,单独抽成方法以便单独测。
     * 判据不是「比同模块最低修复版高」,而是**比 {@link CveTable#POPULAR_FIX} 高** ——
     * 因为用户照抄的正是那个到处出现的版本号,而不是他自己算出来的最低值。
     */
    public static List<Cve> beyondPopularFix(List<Cve> hits) {
        List<Cve> out = new ArrayList<>();
        for (Cve c : hits) {
            if (!c.fixedIn().isEmpty() && newer(c.fixedIn(), CveTable.POPULAR_FIX)) {
                out.add(c);
            }
        }
        return out;
    }

    /**
     * 补丁缺口特判:「你以为按 X 升到 {@code fix} 就修好了,其实 Y 还在」。
     *
     * <p>本批两条链的落点。触发条件是<b>当前装的版本刚好落在前一环的修复版和后一环的修复版之间</b>——
     * 也就是「照前一条 advisory 升过级、但没升到后一条要求的高度」的那个精确窗口。
     * 这个窗口里的人主观上认为自己已经修完了,是最不会再去查的一批。
     *
     * @return 处在缺口窗口里的规则 → 说明文本
     */
    public static Map<Cve, String> patchGaps(List<Cve> hits, List<Scanner.Artifact> scanned) {
        Map<Cve, String> out = new LinkedHashMap<>();
        for (Cve c : hits) {
            if (!c.isPatchGap() || c.fixedIn().isEmpty()) {
                continue;
            }
            Log4jVersion cur = currentOf(scanned, c.module());
            if (cur == null) {
                continue;
            }
            Log4jVersion prevFix = Log4jVersion.parse(c.gapAfterFix());
            if (prevFix == null) {
                continue;
            }
            if (cur.compareTo(prevFix) >= 0) {
                out.put(c, "你装的 " + c.module() + " " + cur + " 已经 ≥ " + c.gapAfter()
                        + " 要求的 " + c.gapAfterFix()
                        + " —— 照那一条你已经「修好了」,但官方原文写明那个修复**不完整**:"
                        + c.cveId() + " 仍然中,要升到 " + c.fixedIn());
            }
        }
        return out;
    }

    /** 模块之间修复版目标不一致的情况 —— 「我把 log4j 升到 2.25.4 了」为什么不够。 */
    public static Set<String> distinctTargets(List<Plan> plans) {
        Set<String> t = new LinkedHashSet<>();
        for (Plan p : plans) {
            if (!p.target().isEmpty()) {
                t.add(p.target());
            }
        }
        return t;
    }

    /** a 是否严格新于 b。解析不了的一律返回 false —— 宁可不给建议,也不给错建议。 */
    private static boolean newer(String a, String b) {
        Log4jVersion va = Log4jVersion.parse(a);
        Log4jVersion vb = Log4jVersion.parse(b);
        return va != null && vb != null && va.compareTo(vb) > 0;
    }

    private Remediation() {
    }
}
