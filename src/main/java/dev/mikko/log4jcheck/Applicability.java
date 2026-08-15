package dev.mikko.log4jcheck;

import java.util.List;

/**
 * 判断一条规则对**这次扫到的这套东西**适不适用。分两步,两步都可能出错,方向不同:
 *
 * <ol>
 *   <li><b>版本判定</b>(硬判据)—— 扫到的模块坐标 + 版本落不落在受影响区间里。
 *       这一步 Dependabot 也做 —— 但只对它<b>索引得到</b>的条目做,
 *       本批仍有一条<b>版本线</b>它结构性索引不到(见 {@link Cve#dependabotBlind()};
 *       粒度是版本线不是 CVE —— 49844 的 2.x 线已于 2026-08-13 被上游补齐,3.x 线仍不可见)。
 *   <li><b>触发条件判定</b>(降噪)—— 你的 log4j2 配置里有没有那条 advisory 要求的
 *       layout / appender / 属性。这一步是本工具存在的理由,也是唯一能给出
 *       「7 条里你真中 2 条」的地方。
 * </ol>
 *
 * <p>🔴 <b>两步的错误代价不对称,所以处理方式也不对称:</b>
 * 版本判定漏了 → 真有风险却不报,而不报警长得和「你很安全」一模一样;
 * 触发条件判定漏了 → 只是没降下噪,用户仍会看到那一条。
 * 因此<b>条件判定永远只降级不排除</b>:未命中的条目仍然完整列出,只是标成
 * {@link Kind#VERSION_HIT_NO_TRIGGER},绝不从报告里消失。
 */
public final class Applicability {

    public enum Kind {
        /** 版本中 + 触发条件全部成立,且依据来自结构化解析 —— 最该先修的。 */
        HIT,
        /** 版本中 + 触发条件全部成立,但依据里含只靠文本匹配的部分(YAML/JSON/源码)。 */
        HIT_TEXT,
        /** 版本中 + 触发条件只部分成立 —— 可能成立,要人看一眼。 */
        HIT_PARTIAL,
        /**
         * 版本中,但一个触发条件都没找到。
         *
         * <p>🔴 <b>这不等于安全</b>:配置可能是代码里构建的、运行时注入的,
         * 或者干脆没传给我们。
         */
        VERSION_HIT_NO_TRIGGER,
        /**
         * 版本中,但这次<b>根本没看到任何 log4j2 配置</b>,所以降噪没做。
         *
         * <p>🔴 必须和 {@link #HIT_PARTIAL} 分开 —— 这是第 9 注真实构件复验抓到的问题:
         * 扫一个不含配置的 jar 会把命中的条目全印成「触发条件部分成立」,
         * 而那句话是**假的**,我们根本没看过任何配置。
         * <b>「没做判断」和「判断结果是一半」长得像,含义完全不同,
         * 而这两句话会把人推向不同的动作。</b>
         */
        NO_CONFIG_SEEN,
        /**
         * 版本中,而且官方原文明确写了「你这种用法不受影响」。
         *
         * <p>本批有两条这样的负判据:用 {@code SyslogAppender} 的不中 CVE-2026-34478;
         * 只用 HTTP appender 的 {@code verifyHostname} 的不中 CVE-2026-34477。
         * 单独立一档,是因为它和「没找到」的可靠程度完全不同 ——
         * 这一档有官方原文背书,那一档只是我们没看见。
         */
        NOT_APPLICABLE,
        /** 装了这个模块,但版本不在受影响区间内。 */
        VERSION_SAFE,
        /** 没扫到这条规则针对的那个模块。 */
        NOT_PRESENT
    }

    /**
     * @param kind    判定结果
     * @param version 参与判定的版本;NOT_PRESENT 时为 null
     * @param where   该构件在哪个文件里;NOT_PRESENT 时为空串
     * @param met     成立的触发条件
     * @param unmet   不成立的触发条件
     * @param reason  说明
     */
    public record Verdict(Kind kind, Log4jVersion version, String where,
                          List<String> met, List<String> unmet, String reason) {

        /** 版本落在受影响区间内(不论触发条件如何)—— Dependabot 若索引得到,报的就是这一档。 */
        public boolean versionHit() {
            return kind == Kind.HIT || kind == Kind.HIT_TEXT || kind == Kind.HIT_PARTIAL
                    || kind == Kind.VERSION_HIT_NO_TRIGGER || kind == Kind.NO_CONFIG_SEEN
                    || kind == Kind.NOT_APPLICABLE;
        }

        /**
         * 触发条件全部或部分成立 —— 这才是「你真中的」。
         *
         * <p>🔴 {@link Kind#NO_CONFIG_SEEN} <b>不算</b>:没看过配置时我们没有任何依据说它触发了。
         * 但它仍是 {@link #versionHit()},所以既不会消失,也不会被冒充成一个我们没做过的判断。
         */
        public boolean triggered() {
            return kind == Kind.HIT || kind == Kind.HIT_TEXT || kind == Kind.HIT_PARTIAL;
        }
    }

    /**
     * @param cve     一条规则(已是 CVE × 模块 × 区间 粒度)
     * @param scanned 扫到的构件
     * @param scan    配置/源码扫描结果;为 null 表示这次完全没扫(此时不做降噪)
     */
    public static Verdict judge(Cve cve, List<Scanner.Artifact> scanned, ConfigScan scan) {
        // ── 第一步:版本 ──
        // 同一个模块可能扫到多份(fat jar 里一份、WEB-INF/lib 里又一份)。
        // 🔴 **任一份命中即命中** —— 挑其中一份来判会漏:老 WAR 里塞着两代 jar 时,
        //    拿新的那份判成安全,而老的那份明明中。
        Scanner.Artifact hit = null;
        Scanner.Artifact anySameModule = null;
        for (Scanner.Artifact a : scanned) {
            if (!a.module().equals(cve.module())) {
                continue;
            }
            if (anySameModule == null) {
                anySameModule = a;
            }
            if (a.version().inRange(cve.low(), cve.lowIncl(), cve.high(), cve.highIncl())) {
                hit = a;
                break;
            }
        }
        if (hit == null) {
            if (anySameModule == null) {
                return new Verdict(Kind.NOT_PRESENT, null, "", List.of(), List.of(),
                        "未扫到 " + cve.coord());
            }
            return new Verdict(Kind.VERSION_SAFE, anySameModule.version(), anySameModule.path(),
                    List.of(), List.of(),
                    "版本 " + anySameModule.version() + " 不在受影响区间(" + cve.rangeText() + ")内");
        }

        // ── 第二步:触发条件降噪 ──
        if (scan == null || !scan.sawAnyConfig()) {
            return new Verdict(Kind.NO_CONFIG_SEEN, hit.version(), hit.path(),
                    List.of(), List.of(),
                    "本次没看到任何 log4j2 配置,降噪这一步没做 —— 不是「部分成立」,是没有依据");
        }
        Conditions.Result r = Conditions.eval(cve.condExpr(), scan);
        if (r.satisfied()) {
            return new Verdict(r.textOnly() ? Kind.HIT_TEXT : Kind.HIT,
                    hit.version(), hit.path(), r.met(), r.unmet(),
                    r.textOnly()
                            ? "🟠 依据里含**文本匹配**部分(YAML/JSON/源码分不清属性归属),可靠性低于结构化解析"
                            : "");
        }
        // 官方原文写明不受影响的那几种用法 —— 这一档有原文背书,和「没找到」不是一回事
        String neg = cve.negToken();
        if (!neg.isEmpty() && Conditions.evalToken(neg, scan) != Conditions.Strength.NONE) {
            return new Verdict(Kind.NOT_APPLICABLE, hit.version(), hit.path(),
                    r.met(), r.unmet(), cve.negText());
        }
        // 🔴 只有**首要要求**(这条 advisory 的定义性 layout / appender / 属性)成立时,
        //    才允许说「部分成立」。见 Conditions.Result#partial() 里记的那个实测例子:
        //    否则一份只有 HTTP appender 的配置会被算成「68161 部分成立」,
        //    而它连 SocketAppender 都没有 —— 那会让「你真中几条」这个数字虚高。
        if (r.partial()) {
            return new Verdict(Kind.HIT_PARTIAL, hit.version(), hit.path(), r.met(), r.unmet(),
                    "满足 " + r.met().size() + "/" + (r.met().size() + r.unmet().size())
                            + " 个要求(定义性特征已出现,其余要求要你自己确认)");
        }
        return new Verdict(Kind.VERSION_HIT_NO_TRIGGER, hit.version(), hit.path(),
                r.met(), r.unmet(),
                (r.anyFound()
                        ? "只命中了次要要求(" + String.join("、", r.met())
                          + "),而这条 advisory 的定义性特征(" + String.join("、", r.unmet())
                          + ")不在你的配置里 —— 不按「部分成立」算。"
                        : "未在你的配置/源码里找到触发条件")
                        + " 🔴 这不等于安全,见报告末尾说明");
    }

    private Applicability() {
    }
}
