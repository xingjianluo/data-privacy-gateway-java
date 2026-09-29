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
import com.github.xingjianluo.dataprivacygatewayjava.service.BatchService;
import com.github.xingjianluo.dataprivacygatewayjava.service.GrantService;
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
    private final BatchService batchService;
    private final GrantService grantService;

    public GatewayController(PrivacyGateway gateway, PolicyStore policyStore, KeyStore keyStore,
                             BatchService batchService, GrantService grantService) {
        this.gateway = gateway;
        this.policyStore = policyStore;
        this.keyStore = keyStore;
        this.batchService = batchService;
        this.grantService = grantService;
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
                                 @RequestParam(defaultValue = "false") boolean raw,
                                 @RequestParam(required = false) String grantId) {
        return gateway.access(new AccessRequest(caller, clearance, id, raw, grantId));
    }

    /**
     * 批量脱敏访问。body：
     * {"caller":"..","clearance":"PUBLIC","raw":false,"requestId":"可选幂等键",
     *  "items":[{"recordId":"r1","fields":["phone",null 表示全部]}]}
     */
    @PostMapping("/batch/access")
    public com.github.xingjianluo.dataprivacygatewayjava.model.BatchAccessResponse batchAccess(
            @RequestBody Map<String, Object> body) {
        String caller = str(body.get("caller"));
        Level clearance = Level.valueOf(strOr(body.get("clearance"), "PUBLIC"));
        boolean raw = Boolean.TRUE.equals(body.get("raw"));
        String requestId = str(body.get("requestId"));
        List<com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemRequest> items =
                parseItems(body.get("items"));
        return batchService.accessBatch(new AccessRequest(caller, clearance, "*", raw),
                items, requestId);
    }

    /**
     * 批量明文导出（限时授权）。body：
     * {"caller":"..","clearance":"PUBLIC","grantId":"..","requestId":"可选",
     *  "items":[{"recordId":"r1","fields":["idCard"]}]}
     */
    @PostMapping("/batch/export")
    public com.github.xingjianluo.dataprivacygatewayjava.model.BatchAccessResponse batchExport(
            @RequestBody Map<String, Object> body) {
        String caller = str(body.get("caller"));
        Level clearance = Level.valueOf(strOr(body.get("clearance"), "PUBLIC"));
        String grantId = str(body.get("grantId"));
        String requestId = str(body.get("requestId"));
        List<com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemRequest> items =
                parseItems(body.get("items"));
        return batchService.exportBatch(caller, clearance, grantId, items, requestId);
    }

    /**
     * 发放限时明文授权。body：
     * {"caller":"auditor","records":["r1","r2"],"fields":["idCard"],"ttlMillis":300000}
     */
    @PostMapping("/grants")
    public Map<String, Object> issueGrant(@RequestBody Map<String, Object> body) {
        String caller = str(body.get("caller"));
        java.util.Set<String> records = new java.util.LinkedHashSet<>(
                toStringList(body.get("records")));
        java.util.Set<String> fields = new java.util.LinkedHashSet<>(
                toStringList(body.get("fields")));
        long ttl = body.get("ttlMillis") instanceof Number n ? n.longValue() : 0L;
        var grant = grantService.issue(caller, records, fields, ttl);
        return Map.of("grantId", grant.grantId(), "caller", grant.caller(),
                "issuedAt", grant.issuedAt(), "expiresAt", grant.expiresAt(),
                "records", grant.recordScope(), "fields", grant.fieldScope());
    }

    /** 撤销授权（仅绑定调用方可撤销自己的授权）。 */
    @DeleteMapping("/grants/{grantId}")
    public Map<String, Object> revokeGrant(@PathVariable String grantId,
                                           @RequestParam String caller) {
        boolean changed = grantService.revoke(caller, grantId);
        return Map.of("grantId", grantId, "revoked", changed);
    }

    /** 查询授权状态（便于本地验证过期/撤销）。 */
    @GetMapping("/grants/{grantId}")
    public Map<String, Object> grantStatus(@PathVariable String grantId) {
        var grant = grantService.get(grantId);
        if (grant == null) {
            return Map.of("grantId", grantId, "status", "NOT_FOUND");
        }
        return Map.of("grantId", grant.grantId(), "status", grant.status().name(),
                "caller", grant.caller(), "expiresAt", grant.expiresAt());
    }

    @SuppressWarnings("unchecked")
    private List<com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemRequest> parseItems(
            Object itemsObj) {
        if (!(itemsObj instanceof List<?> list)) {
            throw new GatewayException(ReasonCode.BAD_REQUEST, "items 必须是数组");
        }
        List<com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemRequest> items =
                new ArrayList<>();
        for (Object o : list) {
            if (!(o instanceof Map<?, ?> m)) {
                throw new GatewayException(ReasonCode.BAD_REQUEST, "items 每个元素必须是对象");
            }
            Object fieldsObj = m.get("fields");
            List<String> fields = fieldsObj == null ? null : toStringList(fieldsObj);
            items.add(new com.github.xingjianluo.dataprivacygatewayjava.model.BatchItemRequest(
                    str(m.get("recordId")), fields));
        }
        return items;
    }

    @SuppressWarnings("unchecked")
    private List<String> toStringList(Object value) {
        if (value == null) {
            return List.of();
        }
        if (!(value instanceof List<?> list)) {
            throw new GatewayException(ReasonCode.BAD_REQUEST, "期望字符串数组");
        }
        List<String> result = new ArrayList<>();
        for (Object o : list) {
            if (o != null) {
                result.add(String.valueOf(o));
            }
        }
        return result;
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
