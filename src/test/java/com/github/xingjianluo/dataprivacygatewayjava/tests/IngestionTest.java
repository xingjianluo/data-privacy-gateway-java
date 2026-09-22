package com.github.xingjianluo.dataprivacygatewayjava.tests;

import com.github.xingjianluo.dataprivacygatewayjava.config.GatewayProperties;
import com.github.xingjianluo.dataprivacygatewayjava.crypto.KeyStore;
import com.github.xingjianluo.dataprivacygatewayjava.ingest.IngestionService;
import com.github.xingjianluo.dataprivacygatewayjava.ingest.SourceRecord;
import com.github.xingjianluo.dataprivacygatewayjava.model.DataNode;
import com.github.xingjianluo.dataprivacygatewayjava.model.IngestionResult;
import com.github.xingjianluo.dataprivacygatewayjava.model.RejectionReason;
import com.github.xingjianluo.dataprivacygatewayjava.tests.support.TestFixtures;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 多来源接入：缺失 / 类型不符 / 超规模必须给出可区分原因，不得静默丢弃。
 */
class IngestionTest {

    private static final Logger log = LoggerFactory.getLogger(IngestionTest.class);

    private TestFixtures.Gateway fixture() {
        return new TestFixtures.Gateway();
    }

    @Test
    void missingAndTypeMismatchAreDistinct() {
        TestFixtures.Gateway fx = fixture();
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("customerId", "C-1");
        // name 缺失（必填）
        payload.put("idCard", List.of("应为标量却给了数组")); // 类型不匹配
        payload.put("contacts", "应为数组却给了标量");

        IngestionResult result = fx.ingestion.ingest(new SourceRecord("crm", null, payload));
        assertFalse(result.accepted());
        log.info("[输入摘要] source=crm, keys={}, 缺失=name, 类型错=idCard/contacts", payload.keySet());
        log.info("[判定依据] violations={}", result.violationSummaries());

        assertEquals(RejectionReason.MISSING_FIELD, result.violations().get("name"));
        assertEquals(RejectionReason.TYPE_MISMATCH, result.violations().get("idCard"));
        assertEquals(RejectionReason.TYPE_MISMATCH, result.violations().get("contacts"));
    }

    @Test
    void unknownSourceAndMalformedPayloadRejected() {
        TestFixtures.Gateway fx = fixture();
        IngestionResult r1 = fx.ingestion.ingest(new SourceRecord("unknown-system", null, Map.of("a", 1)));
        assertFalse(r1.accepted());
        assertEquals(RejectionReason.MALFORMED_RECORD, r1.violations().values().iterator().next());

        IngestionResult r2 = fx.ingestion.ingest(new SourceRecord("crm", null, "not-an-object"));
        assertFalse(r2.accepted());
        assertEquals(RejectionReason.MALFORMED_RECORD, r2.violations().get("(root)"));
        log.info("[判定依据] unknownSource/malformed 均明确拒绝: {}, {}",
                r1.violationSummaries(), r2.violationSummaries());
    }

    @Test
    void oversizedArrayIsTruncatedByDefaultAndFlagged() {
        TestFixtures.Gateway fx = fixture();
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("customerId", "C-2");
        payload.put("name", "张三");
        payload.put("idCard", "110101199001011234");
        List<Map<String, Object>> contacts = new ArrayList<>();
        for (int i = 0; i < 60; i++) {
            contacts.add(Map.of("phone", "1380000" + String.format("%04d", i)));
        }
        payload.put("contacts", contacts);

        IngestionResult result = fx.ingestion.ingest(new SourceRecord("crm", null, payload));
        assertTrue(result.accepted(), "截断策略下应接受: " + result.violationSummaries());
        DataNode.Obj root = result.record().root();
        DataNode.Arr arr = (DataNode.Arr) root.fields().stream()
                .filter(e -> e.getKey().equals("contacts")).findFirst().orElseThrow().getValue();
        assertEquals(fx.properties.getMaxArrayLength(), arr.items().size(), "数组应被截断到上限");
        assertTrue(arr.truncated(), "截断必须带标记，不能静默丢数据");
        log.info("[输入摘要] contacts=60 项, maxArrayLength={}", fx.properties.getMaxArrayLength());
        log.info("[判定依据] accepted=true, truncated=true, kept={}", arr.items().size());
    }

    @Test
    void oversizedRecordIsRejectedWhenTruncationDisabled() {
        GatewayProperties p = TestFixtures.properties();
        p.setTruncateOversizeArrays(false);
        p.setMaxArrayLength(10);
        TestFixtures.Gateway fx = new TestFixtures.Gateway(p);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("customerId", "C-3");
        payload.put("name", "李四");
        payload.put("idCard", "11010119900101123X");
        payload.put("contacts", List.of(Map.of("phone", "1"), Map.of("phone", "2"),
                Map.of("phone", "3"), Map.of("phone", "4"), Map.of("phone", "5"),
                Map.of("phone", "6"), Map.of("phone", "7"), Map.of("phone", "8"),
                Map.of("phone", "9"), Map.of("phone", "10"), Map.of("phone", "11")));

        IngestionResult result = fx.ingestion.ingest(new SourceRecord("crm", null, payload));
        assertFalse(result.accepted());
        assertEquals(RejectionReason.SIZE_LIMIT_EXCEEDED, result.violations().get("contacts"),
                "禁止截断时超规模必须明确拒绝");
        log.info("[判定依据] violations={}", result.violationSummaries());
    }

    @Test
    void encryptedAtRestFieldIsAcceptedAsCiphertext() {
        TestFixtures.Gateway fx = fixture();
        IngestionResult result = fx.ingestion.ingest(new SourceRecord("crm", null,
                Map.of("customerId", "C-4", "name", "王五", "idCard", "110101199001011234")));
        assertTrue(result.accepted(), result.violationSummaries().toString());
        DataNode.Leaf idCard = findLeaf(result.record().root(), "idCard");
        assertTrue(idCard.meta().encrypted(), "idCard 必须落库加密");
        assertTrue(com.github.xingjianluo.dataprivacygatewayjava.crypto.CipherToken
                .looksLikeToken(idCard.value()));
        log.info("[输入摘要] idCard 明文 18 位; [判定依据] 落库为密文 v{}",
                com.github.xingjianluo.dataprivacygatewayjava.crypto.CipherToken
                        .parse(idCard.value()).keyVersion());
    }

    private static DataNode.Leaf findLeaf(DataNode.Obj obj, String key) {
        return (DataNode.Leaf) obj.fields().stream()
                .filter(e -> e.getKey().equals(key)).findFirst().orElseThrow().getValue();
    }
}
