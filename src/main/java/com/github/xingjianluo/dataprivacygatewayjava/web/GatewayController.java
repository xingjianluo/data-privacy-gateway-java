package com.github.xingjianluo.dataprivacygatewayjava.web;

import com.github.xingjianluo.dataprivacygatewayjava.access.AccessGateway;
import com.github.xingjianluo.dataprivacygatewayjava.access.AccessMode;
import com.github.xingjianluo.dataprivacygatewayjava.access.AccessResult;
import com.github.xingjianluo.dataprivacygatewayjava.access.RecordStore;
import com.github.xingjianluo.dataprivacygatewayjava.audit.AuditStore;
import com.github.xingjianluo.dataprivacygatewayjava.config.CallerDirectory;
import com.github.xingjianluo.dataprivacygatewayjava.crypto.KeyStore;
import com.github.xingjianluo.dataprivacygatewayjava.ingest.IngestionService;
import com.github.xingjianluo.dataprivacygatewayjava.ingest.SourceRecord;
import com.github.xingjianluo.dataprivacygatewayjava.model.CallerIdentity;
import com.github.xingjianluo.dataprivacygatewayjava.model.IngestionResult;
import com.github.xingjianluo.dataprivacygatewayjava.policy.PolicyStore;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 演示与验证用 HTTP 入口。
 */
@RestController
@RequestMapping("/api/gateway")
public class GatewayController {

    private final IngestionService ingestionService;
    private final AccessGateway accessGateway;
    private final RecordStore recordStore;
    private final PolicyStore policyStore;
    private final KeyStore keyStore;
    private final AuditStore auditStore;
    private final CallerDirectory callerDirectory;

    public GatewayController(IngestionService ingestionService, AccessGateway accessGateway,
                             RecordStore recordStore, PolicyStore policyStore, KeyStore keyStore,
                             AuditStore auditStore, CallerDirectory callerDirectory) {
        this.ingestionService = ingestionService;
        this.accessGateway = accessGateway;
        this.recordStore = recordStore;
        this.policyStore = policyStore;
        this.keyStore = keyStore;
        this.auditStore = auditStore;
        this.callerDirectory = callerDirectory;
    }

    @PostMapping("/ingest")
    public Map<String, Object> ingest(@RequestBody Map<String, Object> body) {
        String source = (String) body.get("source");
        String hint = (String) body.get("recordId");
        Object payload = body.get("payload");
        IngestionResult result = ingestionService.ingest(new SourceRecord(source, hint, payload));
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("accepted", result.accepted());
        if (result.accepted()) {
            recordStore.put(result.record());
            resp.put("recordId", result.record().recordId());
        } else {
            resp.put("violations", result.violations());
            resp.put("reasons", result.violationSummaries());
        }
        return resp;
    }

    @PostMapping("/access")
    public Map<String, Object> access(@RequestBody Map<String, Object> body) {
        String callerId = (String) body.get("callerId");
        String recordId = (String) body.get("recordId");
        AccessMode mode = "RAW".equalsIgnoreCase((String) body.getOrDefault("mode", "NORMAL"))
                ? AccessMode.RAW : AccessMode.NORMAL;
        CallerIdentity caller = callerDirectory.resolve(callerId);
        Map<String, Object> resp = new LinkedHashMap<>();
        if (caller == null) {
            resp.put("overall", "FAILED");
            resp.put("reason", "UNKNOWN_CALLER:" + callerId);
            return resp;
        }
        AccessResult result = accessGateway.access(caller, recordId, mode);
        resp.put("overall", result.overall());
        resp.put("policyVersion", result.policyVersion());
        resp.put("keyRingVersion", result.keyRingVersion());
        resp.put("decisions", result.decisions());
        resp.put("data", result.data() == null ? null
                : com.github.xingjianluo.dataprivacygatewayjava.model.Nodes.toJsonView(result.data()));
        return resp;
    }

    @PostMapping("/keys/rotate")
    public Map<String, Object> rotate() {
        var ring = keyStore.rotate(Instant.now().toString());
        return Map.of("currentVersion", ring.currentVersion(), "versions", ring.versionList());
    }

    @GetMapping("/policy")
    public Map<String, Object> policy() {
        var p = policyStore.current();
        return Map.of("version", p.version(), "updatedAt", p.updatedAt(), "rules", p.rules());
    }

    @PostMapping("/audit/purge")
    public Map<String, Object> purge() {
        int removed = auditStore.purgeExpired(Instant.now());
        return Map.of("purged", removed, "remaining", auditStore.size());
    }

    @GetMapping("/audit/{recordId}")
    public List<?> audit(@PathVariable String recordId) {
        return auditStore.findByRecord(recordId);
    }
}
