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

## 8. 批量访问与限时明文授权（feature-b）

在单条字段级判定之上新增两条使用路径，判定口径与既有单条能力**完全一致**——
同一逻辑字段，无论从单条入口还是批量入口取，允许/脱敏/拒绝结论相同。

### 8.1 批量脱敏访问 `POST /api/gateway/batch/access`

- 请求一次可带多条记录，每条可只点名 `fields`（空/省略表示全部），裁剪按
  策略**逻辑名/别名**匹配，嵌套、数组、`{"value":..}` 包装口径与单条一致。
- 返回**逐条**结论 `results[]`：`ok / reason / view / decisions / auditEventId /
  truncated / policyVersion / keyVersion`。允许、脱敏、拒绝在同一条内也分得清；
  被 DENY 的字段不出现在该条 `view` 中（Map 删键、List 置 null）。
- **单条隔离**：某条记录不存在或处理失败只把该条标为 `ok=false`（`view=null` 且带
  独立审计事件），不拖垮、不影响其他条目。
- **版本固定**：批量开始时固定一个策略快照版本与一个当前密钥版本戳，整批所有条目都
  对应这一确定版本；期间策略发布 / 密钥轮换不会造成半新半旧。
- **规模 / 耗时**：条数与整批时限可配（`privacy-gateway.batch.*`）。
  - REJECT 模式：条数超限整批拒绝（`REJECT_BATCH_TOO_LARGE`），不处理任何条目；
  - TRUNCATE 模式：截断到约定条数，结果以 `truncated=true` + `TRUNCATED_BY_LIMIT` 标明；
  - 超时：整批失败（`REQUEST_TIMEOUT`），不返回任何已处理视图，不留中间明文，可安全重试。
- **幂等**：可带 `requestId`；相同 `caller + requestId` 的并发或重试请求被拒绝
  （`DUPLICATE_REQUEST`）并指向首个事件，处理失败会回滚占位，不重复计数。

### 8.2 限时明文授权与批量导出

明文导出在字段级判定之外再收紧一层，必须持有一张**限时授权**：

- 授权四要素绑定：`caller`（调用方）、`records`（记录范围）、`fields`（字段范围，
  按策略逻辑名）、`expiresAt`（有效期，TTL 受 `max-grant-ttl-millis` 上限约束）。
- 发放后不可变；可随时撤销（`DELETE /grants/{id}`，仅绑定调用方可撤销自己的）。
- 使用授权时严格校验，每种失败都有独立原因码且**全部留痕**：
  `GRANT_NOT_FOUND / GRANT_CALLER_MISMATCH（跨调用方）/ GRANT_EXPIRED /
  GRANT_REVOKED / GRANT_INVALID`；
  点名字段超出字段范围：该字段判 `DENY(GRANT_SCOPE_VIOLATION)` 且明文不出现；
  请求记录超出记录范围：**整批拒绝**（`GRANT_SCOPE_VIOLATION`），一条越界也不处理。
- **双时点校验**：批量开始前校验一次，全部条目处理完、交付前再复核一次；
  授权在处理期间被并发撤销或恰好过期，整批拒绝交付，已解开的明文一律不返回。
- **密文处理**：授权覆盖字段的密文信封按信封自身 `v` 取历史密钥解密，
  因此**密钥轮换后批量导出仍能正确解密历史密文**；未授权字段的信封不展开、不解密。
  （密文信封在判定遍历时是不透明标量叶子，不会被当普通 JSON 递归。）
- 单条入口同样支持 `grantId`（见下），授权字段的信封也会解密；授权只对覆盖字段生效，
  未覆盖字段回到常规脱敏口径，不会因为“带了授权 + raw”而被额外拒绝。

## 9. REST 速览

```
POST /api/gateway/records                 接入（body: recordId, source, data, schema?）
GET  /api/gateway/records/{id}?caller=&clearance=&raw=&grantId=   字段级判定访问（grantId 可选）
POST /api/gateway/policy/versions         发布新策略（完整规则数组）
POST /api/gateway/keys/rotate             密钥轮换
POST /api/gateway/records/{id}/encrypt    按逻辑字段名加密（body: {"fields":["phone"]}）
POST /api/gateway/records/{id}/decrypt?caller=ops        解密（明文不落库）

# 批量与限时授权
POST /api/gateway/batch/access            批量脱敏访问
POST /api/gateway/batch/export            批量明文导出（需 grantId）
POST /api/gateway/grants                  发放限时授权（caller, records, fields, ttlMillis）
GET    /api/gateway/grants/{id}           查询授权状态（ACTIVE/REVOKED/NOT_FOUND）
DELETE /api/gateway/grants/{id}?caller=   撤销授权（仅绑定调用方）
```

批量请求体示例：

```json
// batch/access
{"caller":"guest","clearance":"PUBLIC","raw":false,"requestId":"可选幂等键",
 "items":[{"recordId":"u1","fields":["phone"]},{"recordId":"u2"}]}

// 发放授权
{"caller":"auditor","records":["u1","u2"],"fields":["idCard"],"ttlMillis":300000}

// batch/export
{"caller":"auditor","clearance":"PUBLIC","grantId":"<上一步返回>","requestId":"exp-1",
 "items":[{"recordId":"u1","fields":["idCard"]}]}
```

错误响应统一为 `{"ok":false,"reason":"<ReasonCode>","message":"<受控消息>"}`。

## 10. 验证方法

```bash
mvn -o test                 # 离线全量测试（45 个用例：27 既有 + 18 新增）
mvn -o test -Dtest=KeyRotationTest       # 只跑密钥轮换
mvn -o test -Dtest=ConcurrencyUpdateTest # 只跑并发更新
mvn -o test -Dtest=BatchAccessTest       # 只跑批量访问
mvn -o test -Dtest=GrantExportTest       # 只跑限时授权/导出
mvn -o test -Dtest=BatchLimitConcurrencyTest # 只跑超限/超时/幂等/并发撤销
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
- `BatchAccessTest`：同批混合允许/脱敏/拒绝逐条可分；单条坏记录不拖垮整批；
  点名字段裁剪；空批整批拒绝；整批固定同一 policy/key 版本戳
- `GrantExportTest`：授权批量导出解密信封；字段/记录越范围、跨调用方、过期、撤销均拒绝
  且留痕；单条与批量授权口径一致；轮换后批量解密历史密文；非法授权参数拒绝
- `BatchLimitConcurrencyTest`：REJECT 整批拒绝 / TRUNCATE 截断并标记；
  超时整批失败无中间结果；`requestId` 并发/重试幂等、失败后可安全重试；
  处理期间并发撤销授权整批拒绝

### curl 端到端验证（批量 + 限时授权）

```bash
# 1) 接入并加密敏感字段
curl -s -XPOST localhost:8080/api/gateway/records -H 'Content-Type: application/json' -d '{
  "recordId":"u1","source":"crm",
  "data":{"name":"Alice","phone":"13800001111","idCard":"11010119900101001X"}}'
curl -s -XPOST localhost:8080/api/gateway/records/u1/encrypt -H 'Content-Type: application/json' \
  -d '{"fields":["phone","idCard"]}'

# 2) 批量脱敏访问：PUBLIC 调用方拿到的是密文/脱敏视图，逐条带判定依据与版本戳
curl -s -XPOST localhost:8080/api/gateway/batch/access -H 'Content-Type: application/json' -d '{
  "caller":"guest","clearance":"PUBLIC",
  "items":[{"recordId":"u1","fields":["phone","idCard"]}]}'

# 3) 发放限时授权（绑定调用方/记录/字段/有效期）
curl -s -XPOST localhost:8080/api/gateway/grants -H 'Content-Type: application/json' -d '{
  "caller":"auditor","records":["u1"],"fields":["idCard"],"ttlMillis":300000}'
# 用返回的 grantId 导出：idCard 解密为明文；换成 phone（不在字段范围）该字段被 DENY
curl -s -XPOST localhost:8080/api/gateway/batch/export -H 'Content-Type: application/json' -d '{
  "caller":"auditor","clearance":"PUBLIC","grantId":"<grantId>","requestId":"exp-1",
  "items":[{"recordId":"u1","fields":["idCard"]}]}'

# 4) 越界 / 换人 / 过期 / 撤销都会被拒绝并留痕
curl -s -XDELETE 'localhost:8080/api/gateway/grants/<grantId>?caller=auditor'
curl -s -XPOST localhost:8080/api/gateway/batch/export -H 'Content-Type: application/json' -d '{
  "caller":"auditor","clearance":"PUBLIC","grantId":"<grantId>","requestId":"exp-2",
  "items":[{"recordId":"u1","fields":["idCard"]}]}'   # -> 403 GRANT_REVOKED
```

### curl 单条速查

```bash
curl -s -XPOST localhost:8080/api/gateway/records -H 'Content-Type: application/json' -d '{
  "recordId":"u1","source":"crm",
  "data":{"name":"Alice","phone":"13800001111","idCard":"11010119900101001X"}}'

curl -s 'localhost:8080/api/gateway/records/u1?caller=guest&clearance=PUBLIC'
curl -s 'localhost:8080/api/gateway/records/u1?caller=guest&clearance=PUBLIC&raw=true'
curl -s -XPOST localhost:8080/api/gateway/keys/rotate
```
