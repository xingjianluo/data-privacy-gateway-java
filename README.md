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
store/      PolicyStore / KeyStore / RecordStore / AuditStore / GrantStore（内存、线程安全、版本化）
service/    IngestService / DecisionService / MaskingService / GrantService /
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
  批量入口点名访问时沿用同一口径做深层定位与裁剪（详见第 8 节）；点名却在任何层级都取不到
  的字段给出 `NOT_FOUND / FIELD_NOT_FOUND`，不用空结果冒充允许。
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

## 8. 批量访问与限时明文导出

### 批量访问 `batchAccess`

- 一次请求携带多条 `BatchItem{recordId, fields}`；`fields` 为空表示全部字段。
  **点名时按「逻辑字段名」做深层定位**，字段无论出现在记录的哪一层都能命中并返回：
  - 嵌套子对象任意深度的键（如 `profile.mobile`）；
  - 数组元素：普通对象元素内部的键、`{"value":x}` / `{"type":t,"value":x}`
    包装元素（继承数组父键逻辑名）；
  - 标量直接出现、以密文信封出现、以单键/双键包装出现、或以**别名键**
    （如 `mobile`/`telephone`→`phone`）出现。
  裁剪只保留命中字段本身以及通向它的**容器链**，未点名的兄弟内容绝不带出。
- 逐条返回 `BatchItemResult{outcome, view, decisions, policyVersion, keyVersion, auditEventId}`：
  允许 / 脱敏 / 拒绝 / 失败 / 字段不存在混在同一批里逐条可区分；**某一条被拒绝或失败不影响其他条目**，
  被拒绝的条目不携带任何字段视图（与单条入口相同的失败安全）。
- **每个点名字段都带独立判定依据**：命中字段的**每一处出现**都产出一条
  `FieldDecision(path, field, action, reason, caller, required, policyVersion)`，
  `path` 精确到嵌套路径 / 数组下标 / 包装位置；有规则字段由递归判定产出
  ALLOW/MASK/DENY，无规则字段按 PUBLIC 显式补一条 ALLOW；每条都钉在批次开始时的
  `(policyVersion, keyVersion)` 上。
- **点名字段不存在/取不到时如实体现**：若某逻辑字段在该记录的任何层级、包装、别名下
  都没有命中，则补一条 `action=NOT_FOUND, reason=FIELD_NOT_FOUND` 依据，条目结论为
  `FIELD_NOT_FOUND`（同批其余正常条目不受影响）；视图中只含确实取到的点名字段。
  **绝不允许返回空结果却报 ALLOW**。
- 密文信封按「该字段的标量值」参与字段级判定（脱敏对信封幂等不变形），
  不会因信封是对象而绕过规则。

### 限时明文导出 `batchExport`

- 导出必须先签发限时授权 `ExportGrant{grantId, caller, recordIds, fields, expiresAt}`：
  绑定具体调用方、记录范围、字段范围与明确有效期；撤销即原子移除，过期自动失效
  （校验时判定 + 定时清理）。
- 校验失败原因码彼此可区分并全部留审计：
  `GRANT_NOT_FOUND`（不存在/已撤销）、`GRANT_EXPIRED`（已过期）、
  `GRANT_CALLER_MISMATCH`（跨调用方使用）、`GRANT_SCOPE_VIOLATION`（记录/字段越范围，
  越范围按条目拒绝，不拖垮整批；字段范围同样做**别名归一**，用别名点名不能绕过）。
- **两入口口径完全一致**：导出沿用与普通批量访问**相同的调用方持证等级与相同 `raw`
  语义**做字段级判定。对同一份数据、同一批点名字段：高权限两处都 ALLOW、低权限普通读取
  两处都逐字段 MASK、`raw=true` 越权两处都整单 DENY、字段不存在两处都 FIELD_NOT_FOUND；
  返回的结构范围与逐字段判定依据（路径/动作/原因/所需持证等级/策略版本）逐项相同。
- **授权只收紧不放宽**：仅对判定为 ALLOW 的密文信封按信封版本解密（轮换后历史密文仍可
  解开）；低权限下被 MASK 的字段信封原样保留、**不会被解密**。明文只存在于返回视图，不落库。
- 点名字段的深层/数组/包装/别名匹配范围与普通批量访问完全相同；
  条目未点名字段时，导出范围自动收敛为授权字段范围（空选择 ≠ 全表导出）。

### 批量规模 / 耗时 / 并发

- `privacy-gateway.batch.max-items` 配置单批条数；超限按 `limits.mode` 既定约定：
  REJECT → 整批拒绝 `BATCH_LIMIT_EXCEEDED`（留审计）；TRUNCATE → 截断到上限并
  在响应标记 `truncated=true` 与 `requestedCount`。
- 处理时限复用 `limits.max-elapsed-millis`：超时 `REQUEST_TIMEOUT` **整批失败**，
  已处理/已解开的中间视图随异常丢弃，不留部分结果；读取无副作用，重试天然幂等，
  审计事件用随机 UUID，不存在重复计数。
- 批次开始时一次性固定「策略快照 + 密钥版本 + 授权快照」：并发撤销授权时，
  每批要么完整执行要么干净拒绝；策略/密钥并发更新不影响本批结论，无半新半旧。

### 与既有单条能力的兼容范围

单条入口（`access` / `decryptRecord` / `encryptFields`）行为完全不变；批量路径复用同一套
`DecisionService` / `MaskingService` / `CryptoService` 与同一递归处理器，仅新增：
批量编排、授权校验、点名字段的深层定位与裁剪（`FieldSelectionService`）、
无规则字段的显式 ALLOW 依据与点名字段缺失的 NOT_FOUND 依据（仅批量路径）。

## 9. REST 速览

```
POST /api/gateway/records                 接入（body: recordId, source, data, schema?）
GET  /api/gateway/records/{id}?caller=&clearance=&raw=   字段级判定访问
POST /api/gateway/policy/versions         发布新策略（完整规则数组）
POST /api/gateway/keys/rotate             密钥轮换
POST /api/gateway/records/{id}/encrypt    按逻辑字段名加密（body: {"fields":["phone"]}）
POST /api/gateway/records/{id}/decrypt?caller=ops        解密（明文不落库）
POST /api/gateway/batch/access            批量访问（body: caller, clearance, raw, items[]）
POST /api/gateway/grants                  签发限时导出授权（caller, recordIds, fields, ttlMillis?）
DELETE /api/gateway/grants/{id}           撤销授权
POST /api/gateway/batch/export?grantId=   批量明文导出（需有效授权）
```

错误响应统一为 `{"ok":false,"reason":"<ReasonCode>","message":"<受控消息>"}`。

## 10. 验证方法

```bash
mvn -o test                 # 离线全量测试（52 个用例）
mvn -o test -Dtest=NamedFieldSelectionTest # 只跑点名字段深层匹配
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
- `BatchAccessTest`：批量中允许/脱敏/拒绝混合、点名字段、单批条数超限（拒绝/截断）、
  超时整批失败无部分结果
- `NamedFieldSelectionTest`：点名字段位于嵌套子对象、数组元素（对象键 / 包装元素）、
  单键与双键包装、别名键下时，批量访问与批量导出都能拿到字段与逐处判定依据（高权限
  ALLOW / 低权限 MASK / raw DENY）；点名字段不存在返回 `FIELD_NOT_FOUND` 且不冒充允许；
  点名授权范围外字段（含用别名绕过）按条目拒绝；某条失败不拖累同批；两入口同口径一致；
  导出只解密 ALLOW 信封、脱敏信封保留、明文不落库
- `ExportGrantTest`：限时授权签发/越范围/过期/跨调用方/撤销、字段级口径与普通批量访问
  一致（同 raw 语义）、密钥轮换后批量解密历史密文、并发撤销下每批完整成功或干净拒绝

### curl 示例

```bash
curl -s -XPOST localhost:8080/api/gateway/records -H 'Content-Type: application/json' -d '{
  "recordId":"u1","source":"crm",
  "data":{"name":"Alice","phone":"13800001111","idCard":"11010119900101001X"}}'

curl -s 'localhost:8080/api/gateway/records/u1?caller=guest&clearance=PUBLIC'
curl -s 'localhost:8080/api/gateway/records/u1?caller=guest&clearance=PUBLIC&raw=true'
curl -s -XPOST localhost:8080/api/gateway/keys/rotate

# 批量访问：一次拿多条记录、每条点名字段
curl -s -XPOST localhost:8080/api/gateway/batch/access -H 'Content-Type: application/json' -d '{
  "caller":"guest","clearance":"PUBLIC","raw":false,
  "items":[{"recordId":"u1","fields":["name","phone"]}]}'

# 签发限时授权并批量明文导出
GRANT=$(curl -s -XPOST localhost:8080/api/gateway/grants -H 'Content-Type: application/json' -d '{
  "caller":"ops","recordIds":["u1"],"fields":["name","phone"],"ttlMillis":300000}' | jq -r .grantId)
curl -s -XPOST "localhost:8080/api/gateway/batch/export?grantId=$GRANT" \
  -H 'Content-Type: application/json' -d '{
  "caller":"ops","clearance":"RESTRICTED",
  "items":[{"recordId":"u1","fields":["name","phone"]}]}'
curl -s -XDELETE localhost:8080/api/gateway/grants/$GRANT
```
