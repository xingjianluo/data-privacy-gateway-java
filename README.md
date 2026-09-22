# 本地敏感数据访问网关（内存版）

在单进程内用内存存储模拟「策略库 / 密钥库 / 记录库 / 审计库」，提供多来源接入归一、
字段级访问判定、嵌套/数组脱敏、版本化加解密、并发一致性更新与审计留存能力。
所有结论都带**稳定原因码 + 可复现判定依据**，底层异常从不直接透出。

## 1. 总体结构

```
model/      统一领域模型：分级、原因码、策略快照、密钥版本、密文信封、审计条目、判定结果
error/      GatewayException（只携带 ReasonCode + 受控消息）
config/     GatewayProperties（规模/耗时/留存可配置）、@EnableScheduling
crypto/     CryptoService + AesGcmCryptoService（AES-GCM-256，版本化）
store/      PolicyStore / KeyStore / RecordStore / AuditStore（内存、线程安全、版本化）
service/    IngestService / DecisionService / MaskingService /
            LimitGuard / AuditService / PrivacyGateway（门面对外统一入口）
bootstrap/  SeedDataInitializer（播种密钥 v1、策略 v1）
web/        REST 控制器 + GlobalExceptionHandler（统一受控错误响应）
```

## 2. 策略模型

- **敏感分级 `Level`**：`PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED`，
  既是数据分类所需等级，也是调用方持证等级；`clearance.covers(required)` 判定是否覆盖。
- **字段规则 `FieldRule`**：`field`（逻辑名）、`requiredLevel`（读取原文所需等级）、
  `maskPattern`（`FULL` / `TAIL4` / `EMAIL`）、`aliases`（别名，如 phone←mobile）。
- **策略快照 `Policy`**：`version + 不可变规则列表`。策略库原子发布、版本单调递增，
  历史版本全部保留。一次访问开始即固定一个快照，处理期间策略更新不影响本次结论。
- **字段级判定三态（原因码彼此可区分）**：

| 条件 | 动作 | ReasonCode |
|---|---|---|
| 持证等级 ≥ 所需等级 | ALLOW 原样返回 | `ALLOWED` |
| 等级不足、普通读取 | MASK 脱敏（**不报错**） | `MASKED_INSUFFICIENT_CLEARANCE` |
| 等级不足、显式 `raw=true` 取原文 | DENY 整单拒绝 | `DENIED_UNAUTHORIZED_RAW_READ` |

- **嵌套 / 数组 / 包装一致处理**：递归遍历时按「逻辑字段名」匹配规则；字段无论出现在
  任意深度、数组下标、别名键，还是 `{"value": x}` / `{"type":"HOME","value":x}` 包装下，
  都得到相同处理，并有独立的 `FieldDecision(path, field, action, reason, caller, required, policyVersion)`。
- **脱敏幂等**：固定脱敏结果；已是脱敏令牌 `***MASKED***` 或密文信封的值不再变形，
  重复处理不会叠加（不会出现 `********` 或把密文再脱敏）。

## 3. 接入归一与拒绝原因

`IngestService` 对多来源数据做深拷贝、结构归一与声明校验（`RecordSchema`/`FieldSpec`），
任何违规**整单拒绝、不落库、不留部分状态**，按字段路径给出可区分原因码：

- `REJECT_MISSING_FIELD`：必填字段缺失
- `REJECT_TYPE_MISMATCH`：类型不符（字符串/数字/布尔/对象/数组）
- `REJECT_SIZE_EXCEEDED`：整体字节超限
- `REJECT_DEPTH_EXCEEDED` / `REJECT_ARRAY_TOO_LARGE` / `REJECT_STRING_TOO_LONG`
- `REQUEST_TIMEOUT`：超过耗时上限
- `TRUNCATED_BY_LIMIT`：TRUNCATE 模式下深度/数组超限被安全裁断
- `BAD_REQUEST`：recordId 缺失、请求体为空等

## 4. 密钥轮换与历史密文兼容

- 密文采用**自描述信封**：`{"enc":"AES-GCM-256","v":<密钥版本>,"ct":"<base64(IV12||密文+tag)>"}`。
- 轮换 = 在 `KeyStore` 新增版本并原子切换 current；**全部历史版本保留**。
- 解密按信封内 `v` 取对应历史密钥，因此轮换后旧密文仍可正确解密。
- 加解密幂等：已是信封的值再次「加密」时原样保留，不会换版本重复包裹。
- 三类失败严格区分，且底层 AEAD 异常不外泄：

| 场景 | ReasonCode |
|---|---|
| 信封里的版本在密钥库中不存在 | `KEY_VERSION_MISSING` |
| 指定期望版本与信封版本不一致（用错版本） | `KEY_VERSION_MISMATCH` |
| 密文损坏 / 认证标签失败 | `CRYPTO_FAILURE` |
| 信封结构不完整 | `MALFORMED_ENVELOPE` |

- 解密结果只存在于返回视图，**绝不写回记录库**，杜绝明文残留。

## 5. 并发一致性

- `PolicyStore` / `KeyStore`：`AtomicReference` 原子切换不可变快照 + 单调递增版本号；
  读路径无锁，永远拿到完整旧版或完整新版，无半更新；`publishAt` 拒绝旧版本覆盖新版本。
- `PrivacyGateway.access`：进入时固定 `(policyVersion, keyVersion)`，本次递归全程对应
  同一快照，响应回传版本戳；并发读写时每次结论都能对应到确定版本。

## 6. 审计与留存

- 允许 / 脱敏 / 拒绝 / 失败 / 接入 / 加密 / 解密全部写审计；条目包含事件 ID、时间、
  调用方、操作、目标、结论码、策略版本、密钥版本、**输入 SHA-256 摘要（不留原文）**、
  逐字段判定依据。越权拒绝可凭 `caller + target + outcome + rationale` 追溯。
- 审计写入失败（故障/注入/容量）只产生 `AUDIT_WRITE_FAILED` 告警，**不改变主流程结论**。
- 审计库有界；定时按 TTL 整条清除过期数据，不残留任何可识别字段。

## 7. 规模 / 耗时上限

通过 `privacy-gateway.limits.*` 配置（见 `application.properties`）。
REJECT 模式超限直接拒绝；TRUNCATE 模式仅对过深子树与超长数组安全截断并标记
`TRUNCATED_BY_LIMIT`；字符串与整体字节规模在任何模式下都拒绝。处理全程在深拷贝副本上
进行，失败时不写半成品、不泄漏解密中间结果。

## 8. REST 速览

```
POST /api/gateway/records                 接入（body: recordId, source, data, schema?）
GET  /api/gateway/records/{id}?caller=&clearance=&raw=   字段级判定访问
POST /api/gateway/policy/versions         发布新策略（完整规则数组）
POST /api/gateway/keys/rotate             密钥轮换
POST /api/gateway/records/{id}/encrypt    按逻辑字段名加密（body: {"fields":["phone"]}）
POST /api/gateway/records/{id}/decrypt?caller=ops        解密（明文不落库）
```

错误响应统一为 `{"ok":false,"reason":"<ReasonCode>","message":"<受控消息>"}`。

## 9. 验证方法

```bash
mvn -o test                 # 离线全量测试（27 个用例）
mvn -o test -Dtest=KeyRotationTest       # 只跑密钥轮换
mvn -o test -Dtest=ConcurrencyUpdateTest # 只跑并发更新
mvn spring-boot:run         # 启动服务（播种密钥 v1、策略 v1）
```

测试以**越权、嵌套结构、密钥轮换、并发更新**为核心（每个类之间用
`@DirtiesContext` 隔离），日志中统一打印「输入摘要（字节数 + SHA-256）」与
「判定依据（path/field/action/reason/caller/required/policyVersion）」：

- `IngestValidationTest`：缺失、类型不符、超规模、超长字符串、多来源归一
- `AccessDecisionTest`：允许 / 脱敏不报错 / 显式越权取原文被拒且有审计 / 结论一致
- `NestedMaskingTest`：深层、数组、两种包装、别名同结果；重复脱敏与密文信封幂等
- `KeyRotationTest`：轮换后旧密文可解；版本缺失 vs 用错版本 vs 密文损坏原因码不同
- `ConcurrencyUpdateTest`：策略/密钥并发发布版本唯一单调、历史可读、读写版本自洽
- `AuditRetentionTest`：四类结论留痕、审计失败不影响主结论、TTL 整条清除
- `LimitGuardTest`：REJECT/TRUNCATE、深度/数组/耗时超限、拒绝无半成品

### curl 示例

```bash
curl -s -XPOST localhost:8080/api/gateway/records -H 'Content-Type: application/json' -d '{
  "recordId":"u1","source":"crm",
  "data":{"name":"Alice","phone":"13800001111","idCard":"11010119900101001X"}}'

curl -s 'localhost:8080/api/gateway/records/u1?caller=guest&clearance=PUBLIC'
curl -s 'localhost:8080/api/gateway/records/u1?caller=guest&clearance=PUBLIC&raw=true'
curl -s -XPOST localhost:8080/api/gateway/keys/rotate
```
