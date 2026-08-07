package dev.mikko.log4jcheck;

import java.util.ArrayList;
import java.util.List;

/**
 * 触发条件表达式的解析与求值。
 *
 * <h2>语法(刻意做到能被人读懂并自己核对)</h2>
 * <pre>
 *   要求1 ; 要求2 ; 要求3            —— 分号分隔,**全部**成立才算触发条件成立
 *   备选A | 备选B                    —— 竖线分隔,**任一**成立即可
 * </pre>
 * token 三种:
 * <ul>
 *   <li>{@code E:Name} —— 配置里出现了这个插件/元素,如 {@code E:Socket}
 *   <li>{@code A:Elem@attr} —— 这个元素上带了这个属性,如 {@code A:Ssl@verifyHostName}。
 *       <b>只有结构化解析(XML / properties)判得准</b>;YAML / JSON 只知道属性名出现过,
 *       此时算成立但标为「文本依据」。
 *   <li>{@code S:token} —— 源码或原文里出现了这个词,如 {@code S:MapMessage}
 * </ul>
 *
 * <p>🔴 <b>为什么不做 AST / 不引 YAML 解析器</b>:关键路径必须能被人读懂并自己核对 ——
 * 一个看不懂的判定出错时没人能发现。代价是 YAML/JSON 那一档分不清属性归属,
 * 而这个代价必须在报告里如实印出来,不能藏。
 */
public final class Conditions {

    /** 一个 token 的求值结果。 */
    public enum Strength {
        /** 结构化解析读出来的 —— 元素名、属性归属都是确定的。 */
        STRUCTURAL,
        /** 只有文本匹配到 —— 可能成立,但属性归属不明或来自源码/YAML。 */
        TEXT,
        /** 没找到。 */
        NONE
    }

    /**
     * 一次求值的结果。
     *
     * @param satisfied 是否全部要求都成立
     * @param anchorMet <b>第一个要求</b>是否成立 —— 见下方「首要要求」一节
     * @param anyFound  是否至少有一个要求成立
     * @param textOnly  成立的依据里是否含只靠文本匹配的部分(报告要如实标注)
     * @param met       成立的要求,渲染成人看得懂的 token 串
     * @param unmet     不成立的要求
     */
    public record Result(boolean satisfied, boolean anchorMet, boolean anyFound, boolean textOnly,
                         List<String> met, List<String> unmet) {

        /**
         * 「可能成立,要人看一眼」—— 只有<b>首要要求成立</b>时才允许这么说。
         *
         * <p>🔴 <b>为什么不能只看 anyFound</b>(建造时实测踩到的):
         * CVE-2025-68161 的表达式是 {@code E:Socket ; E:Ssl | S:sslVerifyHostName}。
         * 一份只有 HTTP appender、但为它配了 {@code <Ssl>} 的配置里,
         * 第二个要求成立、第一个不成立 —— 按 anyFound 会印成「部分成立」,
         * 而这份配置<b>根本没有 SocketAppender</b>,68161 压根不适用。
         *
         * <p>把这种情况算进「你真中几条」会让那个数字<b>虚高</b>,
         * 而那个数字是本工具唯一的卖点。所以规则写死:
         * <b>每条表达式的第一个要求就是这条 advisory 的定义性特征</b>
         * (那个 layout / appender / 属性),它不成立就不存在「部分成立」。
         */
        public boolean partial() {
            return !satisfied && anchorMet;
        }
    }

    /** 把表达式拆成「要求 → 备选 token 列表」。 */
    public static List<List<String>> parse(String expr) {
        List<List<String>> reqs = new ArrayList<>();
        for (String group : expr.split(";")) {
            List<String> alts = new ArrayList<>();
            for (String t : group.split("\\|")) {
                String s = t.trim();
                if (!s.isEmpty()) {
                    alts.add(s);
                }
            }
            if (!alts.isEmpty()) {
                reqs.add(alts);
            }
        }
        return reqs;
    }

    /** 求一个 token 的强度。 */
    public static Strength evalToken(String token, ConfigScan scan) {
        String kind = token.substring(0, Math.min(2, token.length()));
        String name = token.length() > 2 ? token.substring(2) : "";
        switch (kind) {
            case "E:" -> {
                // 🔴 元素**在哪种解析里被读到**决定了这条依据有多硬。
                //    真实构件复验抓到:一律返回 STRUCTURAL 会让纯 YAML 配置的命中
                //    被印成「结构化解析,依据最硬」,而那份配置从没被结构化解析过。
                if (scan.hasElementStructural(name)) {
                    return Strength.STRUCTURAL;
                }
                return scan.hasElement(name) ? Strength.TEXT : Strength.NONE;
            }
            case "A:" -> {
                if (scan.hasAttr(name)) {
                    return Strength.STRUCTURAL;
                }
                // 结构化没读到 —— 退一步看文本层有没有这个属性名(归属不明)
                int at = name.indexOf('@');
                String attr = at < 0 ? name : name.substring(at + 1);
                return scan.hasLooseAttr(attr) ? Strength.TEXT : Strength.NONE;
            }
            case "S:" -> {
                return scan.hasMark(name) ? Strength.TEXT : Strength.NONE;
            }
            default -> {
                // 🔴 未知前缀返回 NONE 会让这条规则**永不命中**,而永不命中长得和
                //    「你不受影响」一模一样。gen_rules.py 的 ASSERT12 在生成期就挡住了这种情况,
                //    这里再抛一次,保证真出现时是响的而不是静默的。
                throw new IllegalArgumentException("未知的条件 token 前缀:" + token);
            }
        }
    }

    /**
     * 求整个表达式。
     *
     * <p>强度的意义:{@code STRUCTURAL} = 元素名/属性归属是从结构化解析(XML / properties)
     * 里**读出来**的;{@code TEXT} = 只是在 YAML / JSON / 源码里按词匹到的。
     * 两者的差别不是学术性的:只有结构化那一档能区分
     * {@code <Ssl verifyHostName>}(中 CVE-2026-34477)和
     * {@code <Http verifyHostname>}(官方原文写明不受影响)。
     */
    public static Result eval(String expr, ConfigScan scan) {
        List<String> met = new ArrayList<>();
        List<String> unmet = new ArrayList<>();
        boolean textOnly = false;
        boolean anchorMet = false;
        int index = 0;
        for (List<String> alts : parse(expr)) {
            String hit = null;
            Strength best = Strength.NONE;
            for (String t : alts) {
                Strength s = evalToken(t, scan);
                if (s == Strength.STRUCTURAL) {
                    hit = t;
                    best = s;
                    break;
                }
                if (s == Strength.TEXT && hit == null) {
                    hit = t;
                    best = s;
                }
            }
            if (hit == null) {
                unmet.add(String.join(" 或 ", alts));
            } else {
                met.add(hit);
                if (best == Strength.TEXT) {
                    textOnly = true;
                }
                if (index == 0) {
                    anchorMet = true;      // 第一个要求 = 这条 advisory 的定义性特征
                }
            }
            index++;
        }
        return new Result(unmet.isEmpty() && !met.isEmpty(), anchorMet, !met.isEmpty(),
                textOnly, met, unmet);
    }

    private Conditions() {
    }
}
