package dev.mikko.log4jcheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class Log4jVersionTest {

    private static Log4jVersion v(String s) {
        Log4jVersion x = Log4jVersion.parse(s);
        assertTrue(x != null, "应该能解析:" + s);
        return x;
    }

    @Test
    @DisplayName("本批区间下界用的预发布号必须解析得出来 —— 解析失败会退化成漏报")
    void parsesPreReleaseBounds() {
        // CVE-2026-34480 的下界是 2.0-alpha1,CVE-2025-68161 的是 2.0-beta9。
        // 🔴 按 x.y.z 解析的实现会在这里失败,而失败之后通常被当成「不受影响」——
        //    那是漏报方向的错,而不报警长得和「你很安全」一模一样。
        assertEquals("2.0-alpha1", v("2.0-alpha1").toString());
        assertEquals("2.0-beta9", v("2.0-beta9").toString());
        assertEquals("3.0.0-beta3", v("3.0.0-beta3").toString());
        assertEquals(2, v("2.0-beta9").major());
        assertEquals(3, v("3.0.0-beta3").major());
    }

    @Test
    @DisplayName("预发布排在同号正式版之前,且 alpha < beta < rc")
    void preReleaseOrdering() {
        assertTrue(v("2.0-alpha1").compareTo(v("2.0-beta9")) < 0);
        assertTrue(v("2.0-beta9").compareTo(v("2.0")) < 0);
        assertTrue(v("3.0.0-beta3").compareTo(v("3.0.0")) < 0);
        assertTrue(v("3.0.0-alpha1").compareTo(v("3.0.0-beta1")) < 0);
    }

    @Test
    @DisplayName("段数不同也要比得对:2.25 == 2.25.0")
    void paddingShorterVersions() {
        assertEquals(v("2.25"), v("2.25.0"));
        assertTrue(v("2.25.4").compareTo(v("2.25")) > 0);
        assertTrue(v("2.26.0").compareTo(v("2.25.5")) > 0);
    }

    @Test
    @DisplayName("解析不了要返回 null,不许当成 0 —— 第 6 注踩过这个洞")
    void refusesToGuess() {
        // 🔴 通配写法必须解析失败。若把限定符正则放宽成 [A-Za-z]+,"2.25.x" 会被
        //    「成功」解析成某个预发布版,于是区间判定拿它去比较,结果既不报错也不正确。
        assertNull(Log4jVersion.parse("2.25.x"));
        assertNull(Log4jVersion.parse("latest"));
        assertNull(Log4jVersion.parse("${log4j.version}"));
        assertNull(Log4jVersion.parse(""));
        assertNull(Log4jVersion.parse(null));
    }

    @Test
    @DisplayName("区间端点开闭照抄不换算 —— 错位一格的判定表看起来完全正常")
    void rangeEndpoints() {
        // CVE-2026-34477:>= 2.12.0, < 2.25.4
        assertFalse(v("2.11.9").inRange("2.12.0", true, "2.25.4", false));
        assertTrue(v("2.12.0").inRange("2.12.0", true, "2.25.4", false));
        assertTrue(v("2.25.3").inRange("2.12.0", true, "2.25.4", false));
        assertFalse(v("2.25.4").inRange("2.12.0", true, "2.25.4", false), "开区间上界不含端点");

        // 3.x 的上界是闭的:>= 3.0.0-alpha1, <= 3.0.0-beta3
        assertTrue(v("3.0.0-beta3").inRange("3.0.0-alpha1", true, "3.0.0-beta3", true),
                "闭区间上界必须含端点");
        assertFalse(v("3.0.0").inRange("3.0.0-alpha1", true, "3.0.0-beta3", true));
    }

    @Test
    @DisplayName("CVE-2026-49844 的两条 2.x 区间必须互斥,不能同时命中")
    void the49844TwoRangesAreDisjoint() {
        // >= 2.13.1, < 2.25.5 和 >= 2.26.0, < 2.26.1
        // 🔴 2.25.5 必须两条都不中(它正是第一条的修复版);2.26.0 只中第二条。
        assertFalse(v("2.25.5").inRange("2.13.1", true, "2.25.5", false));
        assertFalse(v("2.25.5").inRange("2.26.0", true, "2.26.1", false));
        assertTrue(v("2.25.4").inRange("2.13.1", true, "2.25.5", false));
        assertFalse(v("2.25.4").inRange("2.26.0", true, "2.26.1", false));
        assertTrue(v("2.26.0").inRange("2.26.0", true, "2.26.1", false));
        assertFalse(v("2.26.1").inRange("2.26.0", true, "2.26.1", false));
    }

    @Test
    @DisplayName("维护分支标签用于求交集分组")
    void branchTag() {
        assertEquals("2.25", v("2.25.4").branch());
        assertEquals("2.26", v("2.26.0").branch());
        assertEquals("2.0", v("2.0-beta9").branch());
        assertEquals("2.x", v("2.25.4").lineTag());
        assertEquals("3.x", v("3.0.0-beta3").lineTag());
    }
}
