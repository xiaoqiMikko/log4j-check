package dev.mikko.log4jcheck;

/**
 * 一条 advisory 在**一个模块的一条版本线**上的判定规则。由 tools/gen_rules.py 生成。
 *
 * <p>🔴 <b>粒度是「CVE × 模块 × 版本区间」而不是「CVE」</b> —— 这是本工具存在的理由之一。
 * 本批 7 条散布在 <b>4 个 Maven 模块</b>上:
 * {@code log4j-core}(4 条)、{@code log4j-api}、{@code log4j-1.2-api}、
 * {@code log4j-layout-template-json}(各 1 条)。
 * 而绝大多数项目的 pom 里只写 {@code log4j-core} —— 按那个坐标反查只看得到 4 条,
 * 压成「log4j-core &lt; 2.25.4 有洞」就是替用户做错了判断:
 * 他升到 2.25.4 之后,{@code log4j-api} 上的 {@code CVE-2026-49844} 还在,那条要 2.25.5。
 */
public record Cve(
        /** CVE 编号。本批全部有 CVE 号,所以主键用 CVE。 */
        String cveId,
        /** GHSA 编号;拿不到时为空串。 */
        String ghsaId,
        /** 受影响模块的 artifactId(groupId 四个模块共用 {@link CveTable#GROUP})。 */
        String module,
        /** 官方(Apache VDR)给的评级。本批全部 medium。 */
        String severity,
        /** CVSS v4 分数。🔴 GitHub 的 v3 字段对本批 7 条全是 null,分数只能从 VDR / v4 取。 */
        double cvss,
        /** 版本线:{@code "2.x"} 或 {@code "3.x"}。3.x 仍是 beta,官方没给修复版。 */
        String line,
        /** 受影响下限;空表示不设下限。 */
        String low,
        /** 下限是否含端点。 */
        boolean lowIncl,
        /** 受影响上限;空表示不设上限。 */
        String high,
        /** 上限是否含端点。 */
        boolean highIncl,
        /**
         * 修复版本(升到它或更高即可覆盖本条)。
         *
         * <p>空串表示<b>官方没给修复版</b> —— 本批 3.x 区间就是这种情况
         * (3.0.0 还在 beta,补丁没回合过去)。此时报告必须说「官方没给」,
         * 不许静默显示成一个空白,更不许拿 2.x 的版本号糊上去。
         */
        String fixedIn,
        /**
         * 这个修复版本在 Maven Central 上**拿得到吗**。
         *
         * <p>🔴 由来是第 5 / 8 / 9 注各踩过一次:第 5 注的修复版只给商业支持,
         * 第 8 注的坐标是个 {@code packaging=pom} 的父 POM 没有 jar,
         * 第 9 注的 advisory 把版本区间贴到了错的 groupId 上 —— 三次都是 HTTP 404。
         * <b>把一个升不上去的版本印成升级建议,不是「误报」,是让用户去做一件做不成的事。</b>
         * 本注实测全部可获取,而这个结论是 gen_rules.py 的 ASSERT7 带负对照量出来的,不是默认的。
         */
        boolean fixedAvailable,
        /**
         * Dependabot <b>结构性</b>报不出<b>这一条版本线</b>。
         *
         * <p>🔴 <b>粒度是「版本线」不是「CVE」</b> —— 同一条 CVE 的不同版本线可以一条可见、一条不可见。
         * 这不是设计洁癖,是被真事逼出来的:
         *
         * <p>{@code CVE-2026-49844} 的 GitHub advisory({@code GHSA-qv9r-c865-cp47})
         * 原本是 {@code unreviewed} 且 {@code vulnerabilities} 数组为空 ——
         * 没有包名、没有版本区间、没有修复版,Dependabot 拿不到任何可比对的数据。
         * <b>2026-08-13,GitHub 把它转成 {@code reviewed} 并补齐了两条区间</b>
         * ({@code >=2.13.1,<2.25.5} 和 {@code >=2.26.0,<2.26.1}),
         * 于是 <b>2.25 / 2.26 两条线不再是盲区,而 3.x 预览线至今没有对应区间、仍然是</b>。
         *
         * <p>⚠️ <b>所以别一刀切</b>:按 CVE 整条翻这个标志,两个方向都会错 ——
         * 翻成 {@code false} 会漏掉 3.x,留成 {@code true} 会对 2.x 用户说假话。
         * {@code CveTableTest#oneStructuralBlindSpot} 两个方向都钉死了。
         *
         * <p>🔑 教训本身比这条数据值钱:<b>advisory 的形态会随时间被上游补齐,而没有任何东西会通知你。</b>
         * 「当时扫过了」和「现在是安全的」是两件事。
         */
        boolean dependabotBlind,
        /**
         * 这一条是<b>哪一条的补丁缺口</b> —— 即「你照那一条升级了,以为修好了,其实还中这一条」。
         *
         * <p>本批有两条这样的链,原文自己写着:
         * <ul>
         *   <li>{@code CVE-2025-68161}(升到 2.25.3)→ 还中 {@code CVE-2026-34477}(要 2.25.4)
         *   <li>{@code CVE-2026-34481}(升到 2.25.4)→ 还中 {@code CVE-2026-49844}(要 2.25.5)
         * </ul>
         * 空串表示这一条不是任何链的终点。
         */
        String gapAfter,
        /** {@link #gapAfter} 那一条的修复版 —— 也就是「用户以为自己已经到位的那个版本号」。 */
        String gapAfterFix,
        /** 触发条件分类,如 XML_LAYOUT / SSL_VERIFY_HOST_NAME_ATTR。7 条互不相同。 */
        String condKind,
        /** 触发条件的中文说明,逐条对照官方原文,未作外推。 */
        String condText,
        /**
         * 触发条件表达式。语法见 {@link Conditions}:
         * {@code ;} 分隔的若干必须全部成立的要求,每个要求内 {@code |} 分隔任一成立即可的备选。
         */
        String condExpr,
        /**
         * 负判据提示,格式 {@code token||说明};空串表示没有。
         *
         * <p>官方原文明确写了「这种情况不受影响」的那几条,要把话说出来 ——
         * 不说的话,用户看到「不适用」分不清是**没扫到**还是**真的不适用**,
         * 而这两件事该导致完全不同的下一步动作。
         */
        String negHint,
        /** 标题(GitHub advisory 的 summary,截断后)。 */
        String title,
        /** 官方描述原文的第一句(英文原句,非转述)。 */
        String desc) {

    /** 报告里显示的坐标。 */
    public String coord() {
        return CveTable.GROUP + ":" + module;
    }

    /** 区间文本,照官方的开闭端点渲染,不做换算。 */
    public String rangeText() {
        StringBuilder sb = new StringBuilder();
        if (low != null && !low.isEmpty()) {
            sb.append(low).append(lowIncl ? " <= " : " < ");
        }
        sb.append("版本");
        if (high != null && !high.isEmpty()) {
            sb.append(highIncl ? " <= " : " < ").append(high);
        }
        return sb.toString();
    }

    /** 这一条是不是某条的补丁缺口(「升了还中招」)。 */
    public boolean isPatchGap() {
        return gapAfter != null && !gapAfter.isEmpty();
    }

    /** 负判据 token;没有则返回空串。 */
    public String negToken() {
        int i = negHint.indexOf("||");
        return i < 0 ? "" : negHint.substring(0, i);
    }

    /** 负判据说明;没有则返回空串。 */
    public String negText() {
        int i = negHint.indexOf("||");
        return i < 0 ? "" : negHint.substring(i + 2);
    }
}
