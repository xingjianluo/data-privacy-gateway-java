package com.github.xingjianluo.dataprivacygatewayjava.web;

import com.github.xingjianluo.dataprivacygatewayjava.error.GatewayException;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessRequest;
import com.github.xingjianluo.dataprivacygatewayjava.model.AccessResponse;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldRule;
import com.github.xingjianluo.dataprivacygatewayjava.model.IngestReport;
import com.github.xingjianluo.dataprivacygatewayjava.model.JsonType;
import com.github.xingjianluo.dataprivacygatewayjava.model.Level;
import com.github.xingjianluo.dataprivacygatewayjava.model.ReasonCode;
import com.github.xingjianluo.dataprivacygatewayjava.model.FieldSpec;
import com.github.xingjianluo.dataprivacygatewayjava.model.RecordSchema;
import com.github.xingjianluo.dataprivacygatewayjava.service.PrivacyGateway;
import com.github.xingjianluo.dataprivacygatewayjava.store.KeyStore;
import com.github.xingjianluo.dataprivacygatewayjava.store.PolicyStore;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** REST 入口。 */
@RestController
@RequestMapping("/api/gateway")
public class GatewayController {

    private final PrivacyGateway gateway;
    private final PolicyStore policyStore;
    private final KeyStore keyStore;

    public GatewayController(PrivacyGateway gateway, PolicyStore policyStore, KeyStore keyStore) {
        this.gateway = gateway;
        this.policyStore = policyStore;
        this.keyStore = keyStore;
    }

    /** 接入：body 至少包含 {"recordId":...,"source":...,"data":{...}}。 */
    @PostMapping("/records")
    public IngestReport ingest(@RequestBody Map<String, Object> body) {
        String recordId = str(body.get("recordId"));
        String source = str(body.get("source"));
        Object dataObj = body.get("data");
        if (!(dataObj instanceof Map<?, ?>)) {
            throw new GatewayException(ReasonCode.BAD_REQUEST, "data 必须是 JSON 对象");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) dataObj;
        RecordSchema schema = parseSchema(body.get("schema"));
        return gateway.ingest(source, recordId, data, schema);
    }

    @GetMapping("/records/{id}")
    public AccessResponse access(@PathVariable String id,
                                 @RequestParam String caller,
                                 @RequestParam(defaultValue = "PUBLIC") Level clearance,
                                 @RequestParam(defaultValue = "false") boolean raw) {
        return gateway.access(new AccessRequest(caller, clearance, id, raw));
    }

    /** 发布新策略版本，返回新版本号。 */
    @PostMapping("/policy/versions")
    public Map<String, Object> publishPolicy(@RequestBody List<Map<String, Object>> rulesBody) {
        List<FieldRule> rules = new ArrayList<>();
        for (Map<String, Object> r : rulesBody) {
            Level lvl = Level.valueOf(str(r.getOrDefault("requiredLevel", "PUBLIC")));
            @SuppressWarnings("unchecked")
            List<String> aliases = (List<String>) r.getOrDefault("aliases", List.of());
            rules.add(new FieldRule(str(r.get("field")), lvl, str(r.get("maskPattern")), aliases));
        }
        var policy = policyStore.publish(rules);
        return Map.of("policyVersion", policy.version(), "ruleCount", policy.rules().size());
    }

    /** 密钥轮换：生成新版本，旧版本保留。 */
    @PostMapping("/keys/rotate")
    public Map<String, Object> rotateKey() {
        var km = keyStore.rotate(null);
        return Map.of("keyVersion", km.version(), "createdAt", km.createdAt());
    }

    /** 字段加密（用当前密钥版本）。 */
    @PostMapping("/records/{id}/encrypt")
    public Map<String, Object> encrypt(@PathVariable String id,
                                       @RequestBody Map<String, Object> body) {
        @SuppressWarnings("unchecked")
        List<String> fields = (List<String>) body.getOrDefault("fields", List.of());
        int changed = gateway.encryptFields(id, fields);
        return Map.of("recordId", id, "changed", changed, "keyVersion", keyStore.currentVersion());
    }

    /** 解密记录（RESTRICTED 语义，明文不落库）。 */
    @PostMapping("/records/{id}/decrypt")
    public Map<String, Object> decrypt(@PathVariable String id,
                                       @RequestParam String caller) {
        return Map.of("recordId", id, "data", gateway.decryptRecord(caller, id));
    }

    @SuppressWarnings("unchecked")
    private RecordSchema parseSchema(Object schemaObj) {
        if (!(schemaObj instanceof Map<?, ?> sm)) {
            return null;
        }
        List<FieldSpec> specs = new ArrayList<>();
        Object fieldsObj = sm.get("fields");
        if (fieldsObj instanceof List<?> list) {
            for (Object item : list) {
                if (!(item instanceof Map<?, ?> fm)) {
                    continue;
                }
                specs.add(new FieldSpec(
                        str(fm.get("name")),
                        JsonType.valueOf(strOr(fm.get("type"), "STRING")),
                        Boolean.TRUE.equals(fm.get("required"))));
            }
        }
        Object nm = sm.get("name");
        return new RecordSchema(nm == null ? "default" : String.valueOf(nm), specs);
    }

    private static String str(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    private static String strOr(Object o, String dflt) {
        return o == null ? dflt : String.valueOf(o);
    }
}
