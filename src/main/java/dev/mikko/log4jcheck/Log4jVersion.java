package dev.mikko.log4jcheck;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * log4j 版本号解析与比较。
 *
 * <p>🔴 <b>log4j 的受影响区间下界大量使用预发布号</b> —— 本批里就有
 * {@code 2.0-alpha1}(CVE-2026-34480)和 {@code 2.0-beta9}(CVE-2025-68161)。
 * 「按 x.y.z 解析」的实现会在这里直接失败,而失败之后的行为通常是「当成不受影响」——
 * <b>那是漏报方向的错,而不报警长得和「你很安全」一模一样。</b>
 *
 * <p>🔴 <b>限定符只认 log4j 真实用过的那几个</b>,别放宽成 {@code [A-Za-z]+} ——
 * 那样 {@code 2.25.x} 这种通配写法也会被「成功」解析成某个预发布版,
 * 于是区间判定拿它去比较,<b>结果既不报错也不正确</b>(第 6 注 tomcat-check 踩过)。
 * 解析不了就返回 null,让调用方显式处理。
 *
 * <p>排序:同数字段时 <b>预发布排在正式版前面</b>,即 {@code 3.0.0-beta3 < 3.0.0};
 * 且 {@code alpha < beta < rc},所以 {@code 2.0-alpha1 < 2.0-beta9 < 2.0}。
 */
public final class Log4jVersion implements Comparable<Log4jVersion> {

    private static final Pattern P = Pattern.compile(
            "^(\\d+(?:\\.\\d+)*)"                            // 数字段,段数不限
            + "(?:[.\\-_]?(alpha|beta|rc|milestone|m|pr)"    // 限定符(可无分隔符)
            + "[.\\-_]?(\\d*))?$",                           // 限定符序号(可缺省)
            Pattern.CASE_INSENSITIVE);

    /** 限定符排序权。正式版用 {@link #RELEASE},排在所有预发布之后。 */
    private static final int RELEASE = 100;

    private static int qualRank(String q) {
        return switch (q.toLowerCase(Locale.ROOT)) {
            case "milestone", "m" -> 1;
            case "alpha" -> 2;
            case "beta" -> 3;
            case "rc", "pr" -> 4;
            default -> RELEASE;
        };
    }

    private final List<Integer> nums;
    private final int qual;
    private final int qualOrd;
    private final String raw;

    private Log4jVersion(List<Integer> nums, int qual, int qualOrd, String raw) {
        this.nums = nums;
        this.qual = qual;
        this.qualOrd = qualOrd;
        this.raw = raw;
    }

    /** 解析失败返回 null —— 调用方必须处理,不要用「解析不出就当 0」蒙混过去。 */
    public static Log4jVersion parse(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        if (t.isEmpty()) {
            return null;
        }
        Matcher m = P.matcher(t);
        if (!m.matches()) {
            return null;
        }
        List<Integer> ns = new ArrayList<>();
        for (String part : m.group(1).split("\\.")) {
            try {
                ns.add(Integer.parseInt(part));
            } catch (NumberFormatException e) {
                return null;
            }
        }
        int q = RELEASE;
        int ord = 0;
        if (m.group(2) != null) {
            q = qualRank(m.group(2));
            String d = m.group(3);
            ord = (d == null || d.isEmpty()) ? 0 : Integer.parseInt(d);
        }
        return new Log4jVersion(ns, q, ord, t);
    }

    /** 大版本线:2.25.4 → 2;3.0.0-beta3 → 3。 */
    public int major() {
        return nums.get(0);
    }

    /** 版本线标签,和判定表里的 {@link Cve#line()} 对齐:{@code "2.x"} / {@code "3.x"}。 */
    public String lineTag() {
        return major() + ".x";
    }

    /** 次版本分支:2.25.4 → "2.25";2.26.0 → "2.26"。求交集时按它分组。 */
    public String branch() {
        return nums.size() >= 2 ? nums.get(0) + "." + nums.get(1) : nums.get(0) + ".0";
    }

    @Override
    public int compareTo(Log4jVersion o) {
        int n = Math.max(nums.size(), o.nums.size());
        for (int i = 0; i < n; i++) {
            // 🔴 2.25 与 2.25.0 必须相等:缺省段补 0,段数不同的版本才能正确比较。
            int a = i < nums.size() ? nums.get(i) : 0;
            int b = i < o.nums.size() ? o.nums.get(i) : 0;
            if (a != b) {
                return Integer.compare(a, b);
            }
        }
        if (qual != o.qual) {
            return Integer.compare(qual, o.qual);
        }
        return Integer.compare(qualOrd, o.qualOrd);
    }

    /**
     * 区间判定,端点是否包含由调用方给出。
     *
     * <p>🔴 <b>端点开闭直接照抄官方原文,不做「上限 ±1」的转换</b>:
     * 本批里 {@code < 2.25.4}(开)和 {@code <= 3.0.0-beta3}(闭)两种写法都有,
     * 第 6 注 tomcat-check 就是在做这种换算时错位过一格 —— 而错位一格的判定表看起来完全正常。
     * 少一次换算 = 少一个能静默出错的地方。
     *
     * @param low      下限,空表示不设限
     * @param lowIncl  下限是否含端点
     * @param high     上限,空表示不设限
     * @param highIncl 上限是否含端点
     */
    public boolean inRange(String low, boolean lowIncl, String high, boolean highIncl) {
        if (low != null && !low.isEmpty()) {
            Log4jVersion lo = parse(low);
            if (lo == null) {
                return false;
            }
            int c = compareTo(lo);
            if (c < 0 || (c == 0 && !lowIncl)) {
                return false;
            }
        }
        if (high != null && !high.isEmpty()) {
            Log4jVersion hi = parse(high);
            if (hi == null) {
                return false;
            }
            int c = compareTo(hi);
            if (c > 0 || (c == 0 && !highIncl)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Log4jVersion v && compareTo(v) == 0;
    }

    @Override
    public int hashCode() {
        return nums.get(0);
    }

    @Override
    public String toString() {
        return raw;
    }
}
