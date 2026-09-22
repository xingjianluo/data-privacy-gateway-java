package com.github.xingjianluo.dataprivacygatewayjava.tests;

import com.github.xingjianluo.dataprivacygatewayjava.access.AccessGateway;
import com.github.xingjianluo.dataprivacygatewayjava.access.AccessMode;
import com.github.xingjianluo.dataprivacygatewayjava.access.AccessResult;
import com.github.xingjianluo.dataprivacygatewayjava.access.DecisionOutcome;
import com.github.xingjianluo.dataprivacygatewayjava.access.RecordStore;
import com.github.xingjianluo.dataprivacygatewayjava.audit.AuditService;
import com.github.xingjianluo.dataprivacygatewayjava.audit.AuditStore;
import com.github.xingjianluo.dataprivacygatewayjava.config.GatewayProperties;
import com.github.xingjianluo.dataprivacygatewayjava.crypto.CryptoService;
import com.github.xingjianluo.dataprivacygatewayjava.crypto.KeyStore;
import com.github.xingjianluo.dataprivacygatewayjava.masking.MaskStrategy;
import com.github.xingjianluo.dataprivacygatewayjava.masking.MaskingService;
import com.github.xingjianluo.dataprivacygatewayjava.model.*;
import com.github.xingjianluo.dataprivacygatewayjava.policy.FieldRule;
import com.github.xingjianluo.dataprivacygatewayjava.policy.PolicyStore;
import com.github.xingjianluo.dataprivacygatewayjava.tests.support.TestFixtures;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 纯嵌套 / 数组 / 重复键脱敏一致性：直接在统一模型上构造，绕开 Map 载荷对重复键的折叠。
 */
class NestedMaskingTest {

    private static final Logger log = LoggerFactory.getLogger(NestedMaskingTest.class);

    private static final CallerIdentity GUEST = new CallerIdentity("g",
            Set.of(DataClassification.INTERNAL));

    private AccessGateway gateway(RecordStore records, PolicyStore policyStore, KeyStore keyStore,
                                  AuditStore auditStore, AuditService audit, MaskingService masking,
                                  GatewayProperties p) {
        return new AccessGateway(records, policyStore, new CryptoService(keyStore),
                masking, audit, p);
    }

    @Test
    void duplicateKeysAndDeepNestingAllMasked() {
        GatewayProperties p = TestFixtures.properties();
        RecordStore records = new RecordStore();
        PolicyStore policies = TestFixtures.policyStore();
        KeyStore keys = new KeyStore(KeyStore.initialRing());
        AuditStore auditStore = new AuditStore(30);
        AuditService audit = new AuditService(auditStore, 30);
        MaskingService masking = new MaskingService(MaskStrategy.FULL);
        AccessGateway gw = gateway(records, policies, keys, auditStore, audit, masking, p);

        // 同一对象里两个同名 name（重复字段）+ 数组里两个 name + 深层 name
        DataNode.Obj root = DataNode.Obj.of(
                "id", new DataNode.Leaf("R-1", FieldMeta.plain(DataClassification.INTERNAL)),
                "name", new DataNode.Leaf("张三A", FieldMeta.plain(DataClassification.PII)),
                "name", new DataNode.Leaf("张三B", FieldMeta.plain(DataClassification.PII)),
                "people", new DataNode.Arr(List.of(
                        DataNode.Obj.of("name",
                                new DataNode.Leaf("李四", FieldMeta.plain(DataClassification.PII))),
                        DataNode.Obj.of("name",
                                new DataNode.Leaf("王五", FieldMeta.plain(DataClassification.PII))))),
                "deep", DataNode.Obj.of("layer", DataNode.Obj.of("x",
                        DataNode.Obj.of("name", new DataNode.Leaf("赵六",
                                FieldMeta.plain(DataClassification.PII)))))
        );
        records.put(new NormalizedRecord("R-1", "crm", root));

        AccessResult result = gw.access(GUEST, "R-1", AccessMode.NORMAL);
        long nameMasked = result.decisions().stream()
                .filter(d -> d.path().equals("name") && d.outcome() == DecisionOutcome.MASKED)
                .count();
        log.info("[输入摘要] name 出现次数=4（重复键2 + 数组2）, 深层路径=deep.layer.x.name");
        log.info("[判定依据] path=name 的 MASKED 条数={}; 全部 decisions={}",
                nameMasked, result.decisions().stream().map(d -> d.path() + "=" + d.outcome()).toList());

        assertEquals(4, nameMasked, "重复键与数组中的同名 name 必须全部脱敏，不得遗漏");
        // 深层 name 的路径与根 name 不同，应单独有判定
        assertTrue(result.decisions().stream()
                .anyMatch(d -> d.path().equals("deep.layer.x.name")
                        && d.outcome() == DecisionOutcome.MASKED));

        // 所有叶子值中不得残留任何原始姓名
        List<DataNode.Leaf> leaves = collect(result.data());
        for (DataNode.Leaf l : leaves) {
            assertFalse(List.of("张三A", "张三B", "李四", "王五", "赵六").contains(l.value()),
                    "不得残留原文: " + l.value());
        }
    }

    @Test
    void maskingIsIdempotentAndNeverStacks() {
        MaskingService masking = new MaskingService(MaskStrategy.PARTIAL);
        String once = masking.mask("13812345678");
        String twice = masking.mask(once);
        String thrice = masking.mask(twice);
        assertEquals(once, twice);
        assertEquals(twice, thrice);
        log.info("[输入摘要] phone 11 位; [判定依据] 脱敏链一次/二次/三次完全相同: {}", once);
    }

    private static List<DataNode.Leaf> collect(DataNode node) {
        return switch (node) {
            case DataNode.Leaf l -> List.of(l);
            case DataNode.Obj obj -> {
                List<DataNode.Leaf> acc = new java.util.ArrayList<>();
                for (Map.Entry<String, DataNode> e : obj.fields()) {
                    acc.addAll(collect(e.getValue()));
                }
                yield acc;
            }
            case DataNode.Arr arr -> {
                List<DataNode.Leaf> acc = new java.util.ArrayList<>();
                for (DataNode item : arr.items()) {
                    acc.addAll(collect(item));
                }
                yield acc;
            }
        };
    }
}
