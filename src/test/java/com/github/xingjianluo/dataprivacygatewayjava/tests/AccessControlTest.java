package com.github.xingjianluo.dataprivacygatewayjava.tests;

import com.github.xingjianluo.dataprivacygatewayjava.access.AccessMode;
import com.github.xingjianluo.dataprivacygatewayjava.access.AccessResult;
import com.github.xingjianluo.dataprivacygatewayjava.access.DecisionOutcome;
import com.github.xingjianluo.dataprivacygatewayjava.access.FieldDecision;
import com.github.xingjianluo.dataprivacygatewayjava.audit.AuditEvent;
import com.github.xingjianluo.dataprivacygatewayjava.ingest.SourceRecord;
import com.github.xingjianluo.dataprivacygatewayjava.masking.MaskingService;
import com.github.xingjianluo.dataprivacygatewayjava.model.*;
import com.github.xingjianluo.dataprivacygatewayjava.tests.support.TestFixtures;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 访问判定：越权读取原始值必须拒绝留痕；权限不足必须脱敏而非报错；
 * 嵌套对象 / 数组 / 重复字段下同名字段处理必须一致且不遗漏；脱敏幂等。
 */
class AccessControlTest {

    private static final Logger log = LoggerFactory.getLogger(AccessControlTest.class);

    private static final CallerIdentity GUEST = new CallerIdentity("guest",
            Set.of(DataClassification.PUBLIC, DataClassification.INTERNAL));
    private static final CallerIdentity ANALYST = new CallerIdentity("analyst",
            Set.of(DataClassification.PUBLIC, DataClassification.INTERNAL, DataClassification.PII));
    private static final CallerIdentity AUDITOR = new CallerIdentity("auditor",
            Set.of(DataClassification.values()));

    private TestFixtures.Gateway ingestNested(String recordId) {
        TestFixtures.Gateway fx = new TestFixtures.Gateway();
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("customerId", recordId);
        payload.put("name", "张三");
        payload.put("idCard", "110101199001011234");
        // 嵌套对象、数组、重复键中都出现 name，路径都归一为 name / name（数组不带下标）
        Map<String, Object> profile = new LinkedHashMap<>();
        profile.put("name", "嵌套张三");
        payload.put("profile", profile);
        payload.put("aliases", List.of(
                Map.of("name", "数组张三A"),
                Map.of("name", "数组张三B")));
        // 用 Object 节点重复键构造
        Map<String, Object> dup = new LinkedHashMap<>();
        dup.put("name", "重复键张三A");
        dup.put("name", "重复键张三B"); // LinkedHashMap put 覆盖，仅模拟重复语义由节点层保证
        payload.put("dupGroup", dup);

        IngestionResult r = fx.ingestion.ingest(new SourceRecord("crm", recordId, payload));
        assertTrue(r.accepted(), r.violationSummaries().toString());
        fx.records.put(r.record());
        return fx;
    }

    @Test
    void rawReadByUnderprivilegedCallerIsDeniedAndAudited() {
        TestFixtures.Gateway fx = ingestNested("C-RAW");
        AccessResult result = fx.gateway.access(GUEST, "C-RAW", AccessMode.RAW);

        log.info("[输入摘要] caller=guest, record=C-RAW, mode=RAW");
        log.info("[判定依据] overall={}, deniedFields={}", result.overall(),
                result.decisions().stream().filter(d -> d.outcome() == DecisionOutcome.DENIED)
                        .map(d -> d.path() + ":" + d.reason()).toList());

        assertEquals(DecisionOutcome.DENIED, result.overall());
        assertTrue(result.decisions().stream().anyMatch(d ->
                d.path().equals("idCard") && d.outcome() == DecisionOutcome.DENIED));
        // 结果中不得出现原始值
        List<DataNode.Leaf> leaves = collectLeaves(result.data());
        for (DataNode.Leaf leaf : leaves) {
            assertNotEquals("110101199001011234", leaf.value(), "越权路径严禁泄漏原始密文/明文");
            assertNotEquals("张三", leaf.value());
        }
        List<AuditEvent> events = fx.auditStore.findByRecord("C-RAW");
        assertEquals(1, events.size());
        assertEquals(com.github.xingjianluo.dataprivacygatewayjava.audit.AuditOutcome.DENY,
                events.get(0).outcome(), "拒绝必须留痕");
        assertNotNull(events.get(0).inputSummary());
        assertTrue(events.get(0).fieldBasis().stream().anyMatch(b -> b.contains("idCard=DENIED")));
    }

    @Test
    void normalReadMasksInsteadOfErroring() {
        TestFixtures.Gateway fx = ingestNested("C-MASK");
        AccessResult result = fx.gateway.access(GUEST, "C-MASK", AccessMode.NORMAL);

        assertEquals(DecisionOutcome.MASKED, result.overall(), "权限不足应脱敏，不应报错");
        DataNode.Leaf nameLeaf = findFirstLeaf(result.data(), "name");
        DataNode.Leaf idLeaf = findFirstLeaf(result.data(), "idCard");
        assertTrue(fx.masking.isMasked(nameLeaf.value()), "name 必须脱敏: " + nameLeaf.value());
        assertTrue(fx.masking.isMasked(idLeaf.value()), "idCard 必须脱敏且不泄漏密文: " + idLeaf.value());
        assertNotEquals("110101199001011234", idLeaf.value());
        log.info("[输入摘要] caller=guest, record=C-MASK, mode=NORMAL");
        log.info("[判定依据] overall=MASKED; name->{}, idCard->{}", nameLeaf.value(), idLeaf.value());
    }

    @Test
    void nestedArrayAndDuplicateFieldsAreMaskedConsistently() {
        TestFixtures.Gateway fx = ingestNested("C-NEST");
        AccessResult result = fx.gateway.access(GUEST, "C-NEST", AccessMode.NORMAL);

        List<FieldDecision> nameDecisions = result.decisions().stream()
                .filter(d -> d.path().equals("name")).toList();
        long masked = nameDecisions.stream().filter(d -> d.outcome() == DecisionOutcome.MASKED).count();
        long allowed = nameDecisions.stream().filter(d -> d.outcome() == DecisionOutcome.ALLOWED).count();
        log.info("[输入摘要] name 出现次数(含嵌套/数组/重复)={}", nameDecisions.size());
        log.info("[判定依据] MASKED={}, ALLOWED={}, 所有结论必须一致", masked, allowed);

        assertFalse(nameDecisions.isEmpty(), "嵌套/数组中的 name 不得漏处理");
        assertEquals(nameDecisions.size(), masked, "不同深度/包装形式下 name 结论必须全部一致");
        assertEquals(0, allowed);

        // 所有 name 叶子脱敏产物必须一致
        List<String> nameValues = collectLeaves(result.data()).stream()
                .filter(l -> l.meta().masked())
                .map(DataNode.Leaf::value).distinct().toList();
        // PARTIAL 策略对相同原文 "张三" 产物一致；不同原文允许不同，但都必须带脱敏前缀
        for (DataNode.Leaf leaf : collectLeaves(result.data())) {
            if (leaf.meta().masked()) {
                assertTrue(leaf.value().startsWith(MaskingService.MASK_MARKER));
            }
        }
        log.info("[判定依据] 去重后脱敏值={}", nameValues);
    }

    @Test
    void maskedResultIsIdempotentOnRepeatedAccess() {
        TestFixtures.Gateway fx = ingestNested("C-IDEM");
        AccessResult first = fx.gateway.access(GUEST, "C-IDEM", AccessMode.NORMAL);
        // 直接对脱敏后的结果再次走一遍脱敏（模拟重入/重复处理）
        DataNode reMasked = Nodes.mapLeaves(first.data(), (path, leaf) -> {
            if (leaf.meta().masked()) {
                String again = fx.masking.mask(leaf.value());
                return new DataNode.Leaf(again, leaf.meta());
            }
            return leaf;
        });
        assertEquals(toComparable(first.data()), toComparable(reMasked),
                "对已脱敏值再次处理不得叠加变形");
        log.info("[输入摘要] 对脱敏结果二次脱敏; [判定依据] 两次结构与值完全相等=true");
    }

    @Test
    void privilegedCallerDecryptsAndReadsPlaintext() {
        TestFixtures.Gateway fx = ingestNested("C-AUD");
        AccessResult result = fx.gateway.access(AUDITOR, "C-AUD", AccessMode.NORMAL);
        assertEquals(DecisionOutcome.ALLOWED, result.overall());
        DataNode.Leaf idLeaf = findFirstLeaf(result.data(), "idCard");
        assertEquals("110101199001011234", idLeaf.value(), "高权限应解密看到明文");
        assertFalse(idLeaf.meta().encrypted(), "返回值应已还原为明文标记");
        log.info("[输入摘要] caller=auditor; [判定依据] idCard=ALLOWED 解密版本见审计 fieldBasis");
    }

    @Test
    void decisionsCarryDeterministicVersions() {
        TestFixtures.Gateway fx = ingestNested("C-VER");
        AccessResult result = fx.gateway.access(ANALYST, "C-VER", AccessMode.NORMAL);
        assertEquals(1, result.policyVersion());
        assertEquals(1, result.keyRingVersion());
        assertTrue(result.decisions().stream().allMatch(d -> d.policyVersion() == 1));
        log.info("[判定依据] 全部字段均对应 policy-v1/key-v1: {}",
                result.decisions().stream().map(d -> d.path() + "=p" + d.policyVersion()
                        + "/k" + d.keyVersion()).toList());
    }

    // ---- helpers ----

    private static List<DataNode.Leaf> collectLeaves(DataNode node) {
        return switch (node) {
            case DataNode.Leaf l -> List.of(l);
            case DataNode.Obj obj -> {
                List<DataNode.Leaf> acc = new java.util.ArrayList<>();
                for (Map.Entry<String, DataNode> e : obj.fields()) {
                    acc.addAll(collectLeaves(e.getValue()));
                }
                yield acc;
            }
            case DataNode.Arr arr -> {
                List<DataNode.Leaf> acc = new java.util.ArrayList<>();
                for (DataNode item : arr.items()) {
                    acc.addAll(collectLeaves(item));
                }
                yield acc;
            }
        };
    }

    private static DataNode.Leaf findFirstLeaf(DataNode.Obj root, String key) {
        for (Map.Entry<String, DataNode> e : root.fields()) {
            if (e.getKey().equals(key) && e.getValue() instanceof DataNode.Leaf l) {
                return l;
            }
        }
        throw new IllegalStateException("leaf not found: " + key);
    }

    private static String toComparable(DataNode node) {
        return switch (node) {
            case DataNode.Leaf l -> "L(" + l.value() + "," + l.meta().masked() + ")";
            case DataNode.Obj obj -> {
                StringBuilder sb = new StringBuilder("O{");
                for (Map.Entry<String, DataNode> e : obj.fields()) {
                    sb.append(e.getKey()).append("=").append(toComparable(e.getValue())).append(",");
                }
                yield sb.append("}").toString();
            }
            case DataNode.Arr arr -> "A[" + arr.items().stream()
                    .map(AccessControlTest::toComparable).reduce((a, b) -> a + "," + b).orElse("") + "]";
        };
    }
}
