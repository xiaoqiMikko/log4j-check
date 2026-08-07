package dev.mikko.log4jcheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 判定表的自洽性检查。
 *
 * <p>这些断言和 gen_rules.py 里的 ASSERT 是**两道独立的闸门**:那边保证生成时数据对得上,
 * 这边保证生成出来的东西被 Java 读进来之后还是那个意思 ——
 * 中间那一步(字符串拼接 + 转义)出错的话生成期是发现不了的。
 */
class CveTableTest {

    @Test
    @DisplayName("判定表不能是空壳 —— 空表会让所有测试照样全绿")
    void notEmpty() {
        assertFalse(CveTable.all().isEmpty());
        assertEquals(7, CveTable.OFFICIAL_TOTAL);
        Set<String> cves = new LinkedHashSet<>();
        CveTable.all().forEach(c -> cves.add(c.cveId()));
        assertEquals(7, cves.size(), "本批 7 条,一条都不能在生成过程中丢掉");
    }

    @Test
    @DisplayName("粒度是 CVE × 模块:必须覆盖 4 个模块,且不止 log4j-core")
    void multiModule() {
        Set<String> modules = new LinkedHashSet<>();
        CveTable.all().forEach(c -> modules.add(c.module()));
        assertEquals(4, modules.size(), "本批散布在 4 个模块上:" + modules);
        assertTrue(modules.containsAll(List.of("log4j-core", "log4j-api",
                "log4j-1.2-api", "log4j-layout-template-json")));
        assertEquals(4, CveTable.VISIBLE_BY_CORE_COORD,
                "只盯 log4j-core 时按坐标查得到的条数(实测值)");
    }

    @Test
    @DisplayName("🔴 承重:恰好一条是 Dependabot 结构性盲区,且它就是 CVE-2026-49844")
    void oneStructuralBlindSpot() {
        List<Cve> blind = CveTable.all().stream().filter(Cve::dependabotBlind).toList();
        assertFalse(blind.isEmpty(), "本注最硬的论据不能消失");
        Set<String> ids = new HashSet<>();
        blind.forEach(c -> ids.add(c.cveId()));
        assertEquals(Set.of("CVE-2026-49844"), ids);
        assertEquals(1, CveTable.DEPENDABOT_BLIND);
    }

    @Test
    @DisplayName("🔴 承重:两条补丁缺口链都在,且后一环的修复版确实更高")
    void patchGapChains() {
        Set<String> chains = new LinkedHashSet<>();
        for (Cve c : CveTable.all()) {
            if (!c.isPatchGap()) {
                continue;
            }
            chains.add(c.gapAfter() + "→" + c.cveId());
            Log4jVersion prev = Log4jVersion.parse(c.gapAfterFix());
            Log4jVersion now = Log4jVersion.parse(c.fixedIn());
            if (now == null) {
                continue;                 // 3.x 那条官方没给修复版,跳过
            }
            assertNotNull(prev, "前一环的修复版必须解析得出来:" + c.gapAfterFix());
            assertTrue(now.compareTo(prev) > 0,
                    c.cveId() + " 的修复版 " + now + " 必须严格高于 " + c.gapAfter()
                            + " 的 " + prev + ",否则「升了还中招」不成立");
        }
        assertEquals(Set.of("CVE-2025-68161→CVE-2026-34477", "CVE-2026-34481→CVE-2026-49844"),
                chains);
    }

    @Test
    @DisplayName("🔴 承重:照最常见的修复版升级,仍然有条目没盖住")
    void popularFixIsNotEnough() {
        assertEquals("2.25.4", CveTable.POPULAR_FIX);
        List<Cve> beyond = Remediation.beyondPopularFix(CveTable.all());
        assertFalse(beyond.isEmpty(),
                "如果所有条目都被 " + CveTable.POPULAR_FIX + " 盖住,「逐条求交集」就没价值了");
        Set<String> ids = new LinkedHashSet<>();
        beyond.forEach(c -> ids.add(c.cveId()));
        assertEquals(Set.of("CVE-2026-49844"), ids);
    }

    @Test
    @DisplayName("每条规则的字段都要立得住:区间可解析、修复版可解析、条件表达式可求值")
    void everyRuleIsWellFormed() {
        ConfigScan empty = new ConfigScan();
        for (Cve c : CveTable.all()) {
            assertFalse(c.cveId().isBlank(), "CVE 号不能空");
            assertFalse(c.module().isBlank());
            assertTrue(CveTable.MODULES.contains(c.module()), "模块必须在 MODULES 里:" + c.module());
            assertTrue(c.cvss() > 0, c.cveId() + " 必须有 CVSS 分数,否则报告里印出空分数");
            assertEquals("medium", c.severity(),
                    "🔴 口径红线:本批必须全是 medium。出现别的评级就说明文案口径要整体重写");
            assertFalse(c.low().isBlank(), "本批每条都有下界");
            assertNotNull(Log4jVersion.parse(c.low()), "下界要能解析:" + c.low());
            assertFalse(c.high().isBlank());
            assertNotNull(Log4jVersion.parse(c.high()), "上界要能解析:" + c.high());
            if (!c.fixedIn().isEmpty()) {
                assertNotNull(Log4jVersion.parse(c.fixedIn()), "修复版要能解析:" + c.fixedIn());
                assertTrue(c.fixedAvailable(),
                        c.cveId() + "/" + c.module() + " 的修复版 " + c.fixedIn()
                                + " 应在 Central 上拿得到(本注实测全部可获取)");
            } else {
                assertEquals("3.x", c.line(), "只有 3.x 允许没有修复版(仍是 beta)");
            }
            assertFalse(c.condExpr().isBlank(), "🔴 空表达式会被读成「无条件即中招」");
            assertFalse(c.condText().isBlank());
            assertFalse(c.title().isBlank());
            assertTrue(c.title().length() <= 105, "标题过长会撑破排版:" + c.title().length());
            assertFalse(c.desc().isBlank());
            assertTrue(Character.isUpperCase(c.desc().charAt(0)),
                    "原文必须是完整句子(大写开头),不能是被硬换行折断的残句:" + c.desc());
            // 求值一次:未定义的 token 会在这里抛,而不是静默永不命中
            Conditions.eval(c.condExpr(), empty);
            if (!c.negToken().isEmpty()) {
                Conditions.evalToken(c.negToken(), empty);
                assertFalse(c.negText().isBlank(), "负判据必须有说明,否则用户分不清「不适用」的来源");
            }
        }
    }

    @Test
    @DisplayName("触发条件必须有区分度 —— 7 条 7 种,否则退化成版本检测器")
    void conditionsAreDistinct() {
        Set<String> kinds = new LinkedHashSet<>();
        Set<String> exprs = new LinkedHashSet<>();
        for (Cve c : CveTable.all()) {
            kinds.add(c.condKind());
            exprs.add(c.condExpr());
        }
        assertEquals(7, kinds.size(), "7 条应分成 7 种触发条件:" + kinds);
        assertEquals(7, exprs.size(), "7 条的表达式也应互不相同");
    }

    @Test
    @DisplayName("同一条 CVE 在 2.x 和 3.x 上的区间不能重叠")
    void linesDoNotOverlap() {
        for (Cve a : CveTable.all()) {
            for (Cve b : CveTable.all()) {
                if (a == b || !a.cveId().equals(b.cveId()) || !a.module().equals(b.module())) {
                    continue;
                }
                Log4jVersion aLow = Log4jVersion.parse(a.low());
                // a 的下界不该落在 b 的区间里(否则同一个版本会命中两条规则,重复计数)
                assertFalse(aLow.inRange(b.low(), b.lowIncl(), b.high(), b.highIncl())
                                && !a.line().equals(b.line()),
                        a.cveId() + "/" + a.module() + " 的 " + a.line() + " 与 " + b.line()
                                + " 区间重叠");
            }
        }
    }
}
