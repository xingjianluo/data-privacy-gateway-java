# 本地敏感数据访问网关（data-privacy-gateway-java）

用内存存储模拟**策略、密钥、审计**三类控制面数据，在统一数据模型上提供
**接入归一 → 字段级访问判定 → 脱敏 / 加解密 → 审计留痕**的本地网关。
目标：在嵌套结构、策略变更与密钥轮换并发发生时，结论始终**一致、可解释、可复现**。

- Java 21 + Spring Boot 3.4，无外部数据库 / MQ 依赖
- 加密：AES-256 / GCM（96-bit IV，128-bit tag），密文自带密钥版本
- 25 个单测覆盖越权、嵌套脱敏、密钥轮换、并发更新、审计留存、规模/耗时上限

---

## 1. 统一数据模型

所有来源记录先归一为 `DataNode` 树（`model` 包）：

```
DataNode = Leaf(value:String, meta:FieldMeta) | Obj(fields: 有序 List<键,节点>) | Arr(items, truncated)
FieldMeta(classification, encrypted, masked)
```

- 标量统一序列化为字符串；密文以 `CipherToken` 字符串存放在叶子中，由 `meta.encrypted=true` 标识。
- **对象保持插入顺序并允许重复键名**（`Obj.of(k1,n1,k1,n2,...)`），重复字段不会因 Map 折叠而漏处理。
- **路径规则（关键一致性约定）**：叶子路径只由对象键名以 `.` 连接，**数组透明、不出现下标、也不保留数组字段名这一段**。
  因此根层 `name`、`aliases=[{name:a},{name:b}]` 中的每个 `name` 路径都归一为 `name`，
  在任何深度与包装形式下命中同一条策略、得到同一结论。深层对象路径如 `deep.layer.x.name` 仍逐级保留。

### 数据分类与许可

`DataClassification`：`PUBLIC < INTERNAL < PII < FINANCIAL < SECRET`。
`CallerIdentity` 持有一组分类许可；判定时按"字段所需最低许可 ∈ 调用方许可集"放行。

---

## 2. 接入与归一（ingest 包）

`SourceProfile` 描述每个来源的 ID 字段与字段规格 `FieldSpec(path, 分类, 必填, kind, 落库加密)`，
`IngestestionService` 递归校验并归一。违例**一次性全部收集**，绝不静默丢弃，且原因可区分：

| RejectionReason | 触发条件 |
|---|---|
| `MALFORMED_RECORD` | 来源未注册 / 载荷不是对象 / 适配器无法解析 / ID 缺失 |
| `MISSING_FIELD` | 必填字段不存在或为 null（数组透明：`a.b` 命中任意元素内 `b` 即存在） |
| `TYPE_MISMATCH` | 实际结构（SCALAR/OBJECT/ARRAY）与画像声明不符 |
| `SIZE_LIMIT_EXCEEDED` | 节点数超 `max-nodes-per-record`，或数组超长且配置为不截断 |
| `PROCESSING_FAILURE` | 落库加密等处理失败（整条拒绝，不留明文/密文混合状态） |

数组超长默认**截断**并在 `Arr.truncated=true` 显式打标；`truncate-oversize-arrays=false` 时改为整体拒绝。
`SourceAdapter` 支持多来源预处理（内置 JSON/Map 适配器与演示用 CSV 适配器），预处理后统一走同一归一流程。

---

## 3. 策略模型（policy 包）

`AccessPolicy(version, rules, updatedAt)` 为不可变快照，`PolicyStore` 以 `AtomicReference + CAS` 原子发布：

- 读者永远拿到某一完整版本，不会读到半更新规则集。
- 更新采用乐观版本号 `update(expectedBaseVersion, rules)`：
  基线过期（有人先更新）立即抛 `PolicyConflictException`，**旧策略不能覆盖新策略**，版本严格单调 +1。

规则匹配（`AccessGateway.resolveRule`）：

1. 字段路径显式规则优先（如 `idCard -> FINANCIAL + 落库加密`）；
2. 其次 `*` 缺省规则；
3. 缺省最低许可 = **字段自身分类**与缺省规则要求中的较高者——避免通配规则把高分类字段要求意外降低。

### 判定语义（access 包）

一次访问在入口同时抓取 `AccessPolicy` 与 `KeyRing` 两个快照，全程只基于这对确定版本：

| 调用方许可 vs 字段要求 | NORMAL 模式 | RAW 模式 |
|---|---|---|
| 足够 | 密文先解密返回明文（ALLOWED） | 同左（ALLOWED） |
| 不足 | **脱敏返回，不报错**（MASKED） | **拒绝原始读取**（DENIED，占位 `[DENIED]`） |

- 权限不足且字段为密文时，NORMAL 路径**不先解密**直接给固定脱敏标记，杜绝明文中间泄漏。
- 整体结论聚合优先级：`FAILED > DENIED > MASKED > ALLOWED`。
- 每个叶子产生一条 `FieldDecision(path, outcome, reason, policyVersion, keyVersion)`，即判定依据。
- 对已脱敏值再次脱敏**幂等**（脱敏产物以 `***` 前缀识别，原样返回，不叠加变形）；
  对已加密值再次加密同样幂等（合法令牌原样返回）。

---

## 4. 密钥轮换（crypto 包）

线路格式：

```
enc:v<密钥版本>:<Base64 IV>:<Base64 密文+GCM tag>
```

- `KeyStore` 持有不可变 `KeyRing(currentVersion, versions{1..n})`，CAS 原子轮换；
  轮换只新增版本，**全部历史版本永久保留**，历史密文按自带版本找密钥解密。
- 网关在请求入口抓取一次 `KeyRing` 快照，`CryptoService.decrypt(ct, ring)` 在该快照内解密；
  处理中途发生轮换也不会出现"密文按新版本、审计记旧版本"的错配。
- 错误严格区分，且只回传领域信息，JCE 底层异常不向外透出：
  - `NOT_A_CIPHERTEXT`：不是合法令牌
  - `KEY_VERSION_MISSING`：环中无该版本（轮换后旧密钥被误删等）
  - `DECRYPTION_FAILED`：GCM 认证失败（密文篡改 / 用错密钥）

---

## 5. 审计与留存（audit 包）

- 每次 ALLOW / MASK / DENY / FAIL 写一条 `AuditEvent`，含：调用方、记录 ID、总体结论、原因、
  **输入摘要**（`callerId|recordId|有序路径集` 的 SHA-256 前缀）、逐字段依据、策略与密钥环版本、过期时间。
- 审计**只存哈希摘要与路径依据，不存任何原始值 / 解密中间值**；相同输入摘要稳定可复现。
- `AuditStore.record()` **永不向主流程抛异常**：写入失败仅计数（`failedWriteCount()`），主流程结论不变。
- `purgeExpired(now)` 物理摘除过期记录，清除后无任何可识别信息残留。

---

## 6. 规模与耗时上限（config 包）

| 配置 | 行为 |
|---|---|
| `max-nodes-per-record` | 接入期节点预算，超限整体拒绝 |
| `max-array-length` / `truncate-oversize-arrays` | 数组截断打标 或 拒绝 |
| `max-leaves-per-response` | 访问期叶子上限，超限**整体 DENIED、data=null**，不返回部分结果 |
| `processing-timeout-millis` | 每处理一个叶子前检查 deadline，超时抛 `DeadlineExceededException`，**丢弃整棵已构建树**（含已解密明文），返回 FAILED |

失败路径（含解密失败）的叶子占位为 `[FAILED]`，不含原文与底层异常文本。

---

## 7. 验证方法

### 7.1 单元测试（推荐）

```bash
mvn test
```

25 个用例，关键分组：

| 测试类 | 覆盖点 |
|---|---|
| `CryptoRotationTest` | 轮换后旧密文可解、新密文用新版本；版本缺失/篡改/非密文三种错误可区分；加密幂等 |
| `IngestionTest` | 缺失 vs 类型不符可区分；未知来源/坏载荷拒绝；数组截断打标；禁止截断时拒绝；落库加密 |
| `AccessControlTest` | 越权 RAW 被拒且审计留痕；低权 NORMAL 脱敏不报错；嵌套/数组一致；版本依据确定 |
| `NestedMaskingTest` | 重复键 + 数组 + 深层字段全部脱敏无遗漏；脱敏幂等不叠加 |
| `ConcurrencyConsistencyTest` | 策略 CAS 线性化、旧基线拒绝；并发读+20 更新+20 轮换无混版/无明文窗口；并发轮换版本连续、历史密文全可解 |
| `AuditAndLimitsTest` | 审计写失败不改结论；摘要可复现不含原文；过期物理清除；叶子上限拒绝；deadline 失败不泄漏明文 |

单测日志统一打印**输入摘要**（如 `caller=guest, record=C-RAW, mode=RAW`、字段数量/规模）
与**判定依据**（如 `idCard=DENIED(policy-v1,key-v1):INSUFFICIENT_CLEARANCE...`），可用：

```bash
mvn test -Dtest=AccessControlTest | grep -E '输入摘要|判定依据'
```

### 7.2 HTTP 端到端冒烟

```bash
mvn spring-boot:run
```

预置调用方：`guest`（INTERNAL）、`analyst`（PII）、`auditor`（全许可）；预置来源：`crm`。

```bash
# 1) 接入（idCard 落库自动加密）
curl -s -XPOST localhost:8080/api/gateway/ingest -H 'Content-Type: application/json' -d '{
  "source":"crm","recordId":"C-1",
  "payload":{"customerId":"C-1","name":"张三","idCard":"110101199001011234",
             "aliases":[{"name":"小张"},{"name":"阿三"}]}}'

# 2) 低权访问：name/idCard 脱敏
curl -s -XPOST localhost:8080/api/gateway/access -H 'Content-Type: application/json' \
  -d '{"callerId":"guest","recordId":"C-1","mode":"NORMAL"}'

# 3) 越权读取原始值：被拒绝
curl -s -XPOST localhost:8080/api/gateway/access -H 'Content-Type: application/json' \
  -d '{"callerId":"guest","recordId":"C-1","mode":"RAW"}'

# 4) 高权访问：密文按版本解密
curl -s -XPOST localhost:8080/api/gateway/access -H 'Content-Type:application/json' \
  -d '{"callerId":"auditor","recordId":"C-1","mode":"NORMAL"}'

# 5) 轮换密钥；之后旧密文仍可解、新密文走新版本
curl -s -XPOST localhost:8080/api/gateway/keys/rotate

# 6) 审计依据 / 留存清除
curl -s localhost:8080/api/gateway/audit/C-1
curl -s -XPOST localhost:8080/api/gateway/audit/purge
```

### 7.3 关键一致性结论速查

- 同名字段无论在根层、嵌套对象还是数组内，路径相同、策略相同、脱敏结果相同，重复键不漏处理。
- 任一访问结果中 `policyVersion / keyRingVersion` 与每个 `FieldDecision` 的版本完全一致。
- 策略并发更新后版本只增不减，旧基线提交得到明确 `PolicyConflictException`。
- 并发轮换后密钥环版本连续且历史版本齐全，轮换前产生的全部密文仍可解密。
