package dev.mikko.log4jcheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class RemediationTest {

    private static Scanner.Artifact art(String module, String version) {
        return new Scanner.Artifact("/fake/" + module + ".jar", module,
                Log4jVersion.parse(version), "测试");
    }

    private static List<Cve> versionHits(List<Scanner.Artifact> arts) {
        List<Cve> out = new ArrayList<>();
        for (Cve c : CveTable.all()) {
            if (Applicability.judge(c, arts, null).versionHit()) {
                out.add(c);
            }
        }
        return out;
    }

    private static Remediation.Plan planFor(List<Remediation.Plan> plans, String module) {
        return plans.stream().filter(p -> p.module().equals(module)).findFirst().orElseThrow(
                () -> new AssertionError("没有 " + module + " 的升级计划,实有:"
                        + plans.stream().map(Remediation.Plan::module).toList()));
    }

    @Test
    @DisplayName("⭐ 承重:四个模块都在 2.24.0 时,目标版本**不是同一个数字**")
    void targetsDifferPerModule() {
        List<Scanner.Artifact> arts = List.of(
                art("log4j-core", "2.24.0"), art("log4j-api", "2.24.0"),
                art("log4j-1.2-api", "2.24.0"), art("log4j-layout-template-json", "2.24.0"));
        List<Remediation.Plan> plans = Remediation.plan(versionHits(arts), arts);
        assertEquals("2.25.4", planFor(plans, "log4j-core").target());
        assertEquals("2.25.4", planFor(plans, "log4j-1.2-api").target());
        assertEquals("2.25.4", planFor(plans, "log4j-layout-template-json").target());
        assertEquals("2.25.5", planFor(plans, "log4j-api").target(),
                "🔴 log4j-api 要 2.25.5,不是 2.25.4 —— 这就是「我把 log4j 升到 2.25.4 了」不够用的地方");
        Set<String> distinct = Remediation.distinctTargets(plans);
        assertTrue(distinct.size() > 1, "目标不唯一这件事本身就是本注的核心结论:" + distinct);
    }

    @Test
    @DisplayName("🔴 承重:装 2.24.0 的人不该被推去跳 2.26.1(那跨了维护分支)")
    void doesNotPushAcrossMinorBranchUnnecessarily() {
        // CVE-2026-49844 在 log4j-api 上有两条 2.x 区间:2.25 线要 2.25.5、2.26 线要 2.26.1。
        // 压成一条线取最大值就会给 2.24.0 的用户建议 2.26.1 —— 那个建议不算错,
        // 只是让人白做一次风险更大的跨分支升级,而且**不报错**。
        List<Scanner.Artifact> arts = List.of(art("log4j-api", "2.24.0"));
        Remediation.Plan p = planFor(Remediation.plan(versionHits(arts), arts), "log4j-api");
        assertEquals("2.25.5", p.target());
        assertTrue(p.crossBranch(), "2.24 → 2.25 确实跨了次版本分支,要提示跑回归");
    }

    @Test
    @DisplayName("装 2.26.0 的人要被指到 2.26.1,不是 2.25.5(不许推人降级)")
    void the226LineGetsItsOwnTarget() {
        List<Scanner.Artifact> arts = List.of(art("log4j-api", "2.26.0"));
        Remediation.Plan p = planFor(Remediation.plan(versionHits(arts), arts), "log4j-api");
        assertEquals("2.26.1", p.target());
        assertFalse(p.crossBranch(), "2.26.0 → 2.26.1 是同分支补丁版");
    }

    @Test
    @DisplayName("⭐ 承重:照最常见的 2.25.4 升级仍然漏一条(2026-08-16:漏这条的事实没变,"
            + "但它已不再是 Dependabot 盲区)")
    void popularFixLeavesOneBehind() {
        List<Scanner.Artifact> arts = List.of(
                art("log4j-core", "2.24.0"), art("log4j-api", "2.24.0"));
        List<Cve> beyond = Remediation.beyondPopularFix(versionHits(arts));
        Set<String> ids = new LinkedHashSet<>();
        beyond.forEach(c -> ids.add(c.cveId()));

        // ✅ 真正的承重论据:升到 2.25.4 不够,log4j-api 上还有一条要 2.25.5。**这条没变。**
        assertEquals(Set.of("CVE-2026-49844"), ids);

        // 🔴 2026-08-16 事实变更(本测试是被这次变更打挂之后改的,不是先改测试再改代码):
        //    GHSA-qv9r-c865-cp47 于 2026-08-13 转 reviewed 并补齐两条 2.x 区间,
        //    所以对跑 2.x 的人来说,它**现在报得出来了**。
        //    原断言是 allMatch(dependabotBlind),曾是「本注最值钱的一句话」——
        //    ⚠️ 那句话有时效,而工具此前每次运行都在无条件重复它。
        assertTrue(beyond.stream().noneMatch(Cve::dependabotBlind),
                "2.x 线已被上游补齐,不该再声称『这条机器报不出来』");

        // 把目标顶高的那条仍要能在计划里指名道姓(这部分与盲区无关,不受影响)
        Remediation.Plan p = planFor(Remediation.plan(versionHits(arts), arts), "log4j-api");
        assertEquals("CVE-2026-49844", p.drivenBy());
        assertFalse(p.blindDriven(),
                "2.x 线不再是盲区驱动 —— 3.x 线仍是,见 CveTableTest#oneStructuralBlindSpot");
    }

    @Test
    @DisplayName("⭐⭐ 承重:补丁缺口特判 —— 装 2.25.4 的人正处在「以为修完了」的窗口里")
    void patchGapWindowFor49844() {
        List<Scanner.Artifact> arts = List.of(
                art("log4j-core", "2.25.4"), art("log4j-api", "2.25.4"),
                art("log4j-layout-template-json", "2.25.4"));
        Map<Cve, String> gaps = Remediation.patchGaps(versionHits(arts), arts);
        assertFalse(gaps.isEmpty(), "🔴 这个特判是本注的落点,不能空");
        Set<String> ids = new LinkedHashSet<>();
        gaps.keySet().forEach(c -> ids.add(c.cveId()));
        assertEquals(Set.of("CVE-2026-49844"), ids);
        String why = gaps.values().iterator().next();
        assertTrue(why.contains("CVE-2026-34481"), "要说清是照哪一条升的:" + why);
        assertTrue(why.contains("2.25.5"), "要说清该升到哪:" + why);
    }

    @Test
    @DisplayName("⭐ 承重:装 2.25.3 的人处在另一条链的缺口窗口里(68161 → 34477)")
    void patchGapWindowFor34477() {
        List<Scanner.Artifact> arts = List.of(art("log4j-core", "2.25.3"));
        Map<Cve, String> gaps = Remediation.patchGaps(versionHits(arts), arts);
        Set<String> ids = new LinkedHashSet<>();
        gaps.keySet().forEach(c -> ids.add(c.cveId()));
        assertTrue(ids.contains("CVE-2026-34477"),
                "照 CVE-2025-68161 升到 2.25.3 的人仍然中 CVE-2026-34477:" + ids);
        String why = gaps.entrySet().stream()
                .filter(e -> e.getKey().cveId().equals("CVE-2026-34477"))
                .findFirst().orElseThrow().getValue();
        assertTrue(why.contains("2.25.3") && why.contains("2.25.4"), why);
    }

    @Test
    @DisplayName("还没升过级的人(2.17.1)不该被塞补丁缺口那段话 —— 他不在那个窗口里")
    void noPatchGapNoiseForOldVersions() {
        List<Scanner.Artifact> arts = List.of(art("log4j-core", "2.17.1"));
        Map<Cve, String> gaps = Remediation.patchGaps(versionHits(arts), arts);
        // 2.17.1 < 2.25.3,他从来没「以为自己修好了」,直接给他最终目标就行。
        assertTrue(gaps.isEmpty(), "不在缺口窗口里的人不该看到那段话:" + gaps.values());
        assertEquals("2.25.4", planFor(Remediation.plan(versionHits(arts), arts),
                "log4j-core").target());
    }

    @Test
    @DisplayName("3.x beta 用户:官方没给修复版,必须显式说出来,不许糊一个 2.x 版本号")
    void threeXHasNoTarget() {
        List<Scanner.Artifact> arts = List.of(art("log4j-core", "3.0.0-beta3"));
        List<Remediation.Plan> plans = Remediation.plan(versionHits(arts), arts);
        assertFalse(plans.isEmpty());
        plans.forEach(p -> {
            assertTrue(p.target().isEmpty(), "3.x 不该有目标版本,实得:" + p.target());
            assertFalse(p.covers().isEmpty(), "但要说清它盖住哪几条");
        });
    }

    @Test
    @DisplayName("当前版本取同模块最低的那份 —— 短板决定升级起点")
    void currentIsTheLowestCopy() {
        List<Scanner.Artifact> arts = List.of(
                new Scanner.Artifact("a.war!/WEB-INF/lib/log4j-core-2.25.4.jar", "log4j-core",
                        Log4jVersion.parse("2.25.4"), "文件名"),
                new Scanner.Artifact("a.war!/WEB-INF/lib/old/log4j-core-2.17.1.jar", "log4j-core",
                        Log4jVersion.parse("2.17.1"), "文件名"));
        Remediation.Plan p = planFor(Remediation.plan(versionHits(arts), arts), "log4j-core");
        assertEquals("2.17.1", p.current().toString(), "🔴 报最高那份会让人以为只差一小步");
    }

    @Test
    @DisplayName("没有命中就没有计划,不许无中生有")
    void noHitsNoPlans() {
        List<Scanner.Artifact> arts = List.of(
                art("log4j-core", "2.25.4"), art("log4j-api", "2.25.5"));
        assertTrue(Remediation.plan(versionHits(arts), arts).isEmpty());
        assertTrue(Remediation.patchGaps(versionHits(arts), arts).isEmpty());
    }
}
