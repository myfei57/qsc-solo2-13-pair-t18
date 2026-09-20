# 离线核验包（attest）

解决的问题：车间断网时也要能**只读查**当前状态和一段流水；回联后能**一条条对回来**，
直接指出「哪条被改过、哪段缺了」，而且离线看到的记录事后能**证明没被动过**。

## 1. 信任模型

* 一对 **Ed25519** 密钥是唯一的信任根：
  * 私钥只留在线上服务器，建议进 HSM，**绝不带进车间**；
  * 公钥预置（钉住）在车间核验机上，例如 `/etc/flashsmelter/attest.pub`。
* 包内虽然附带 `public.pem` 方便分发，但正式核验必须用车间预置公钥。
  用包内公钥验包内签名等于让包裹自证清白，CLI 在这种情况下会输出 `warning`。
* 签名算法通过系统 `openssl pkeyutl` 调用（OpenSSL 3），平台本身零新增依赖。

## 2. 包结构

```
manifest.json        清单（被签名）：序号边界、哈希链头/前驱、状态默克尔根、各文件 SHA-256
manifest.sig         对 manifest.json 原始字节的 Ed25519 签名
public.pem           签名公钥（仅用于分发，不可作为信任依据）
chain.json           导出区间的逐环哈希链，供人工抽查
journal/<流>.jsonl   导出区间的流水原文
data/records.jsonl   导出时刻文档库当前状态（envelope 原文）
```

输出目录以 `.zip` 结尾时自动打成单个 zip，便于 U 盘摆渡。

## 3. 防篡改原理

在原有「逐行校验和」之上，导出时额外重算一条**前向哈希链**：

```
link[i] = SHA256(domain | stream | seq | written_at | checksum | SHA256(payload) | link[i-1])
```

* 改任意一行的内容或时间 → 该行校验和失效，且从该行起链头全变；
* 抽掉中间任意一段 → 序号断号 + 链无法接上；
* 调换顺序 → 序号与链对不上；
* 区间切片导出时，`prev` 锚住更早的历史链头，「保留区间原样、重写更早历史」也会被抓到；
* 哈希输入带 `stream` 名，不能把别的流的链嫁接到本流。

当前状态对每个文档计算叶子（key、version、written_at、checksum、payload），
组织成 **默克尔根**写进清单：删一个键、改一个值（哪怕只是 version 增加）都会改变根。

清单（含链头、序号边界、状态根、全部文件 SHA-256）整体被私钥签名，
因此任何篡改都无法在没有私钥的情况下重新封口。

## 4. 使用流程

### 线上（有网，一次性准备）

```bash
flashsmelter attest-keygen --key /etc/flashsmelter/sign.pem \
                           --public-key /etc/flashsmelter/sign.pub
# sign.pem 权限 0600，只留服务器；sign.pub 下发到车间核验机
```

### 导出（摆渡前）

```bash
# 整段导出
flashsmelter --root /var/lib/flashsmelter attest-export ./H-901-floor1.zip \
    --stream audit/events --key /etc/flashsmelter/sign.pem

# 只导出某段（例如本班次 1201..1488），历史链头自动锚定
flashsmelter --root /var/lib/flashsmelter attest-export ./shift3.zip \
    --stream audit/events --from 1201 --to 1488 --key /etc/flashsmelter/sign.pem
```

导出是只读操作。**整库 `verify` 不通过或流水有断号时直接拒签**，
不会把已经损坏的库封进「可信」包里。

### 车间（断网，只读核验）

```bash
flashsmelter attest-verify ./H-901-floor1.zip \
    --public-key /etc/flashsmelter/sign.pub
# 退出码：0 整包可信；3 发现问题（problems 逐条列出）
```

这一步不读线上库、不访问网络，只需要一个 zip、一份预置公钥和系统 openssl。

### 回联后（逐条对账）

```bash
flashsmelter --root /var/lib/flashsmelter attest-reconcile ./H-901-floor1.zip \
    --public-key /etc/flashsmelter/sign.pub
```

对账先重新验签（包不可信直接拒绝，结论 `bundle-invalid`），然后：

| findings.kind | 含义 |
| --- | --- |
| `altered` | 指定 `seq` 的条目被改，`fields` 指出 payload / written_at / checksum |
| `missing` | 指定 `seq` 在线上库缺失；连续出现即「哪段缺了」 |
| `prefix-rewritten` | 导出区间之前的历史被重写或缺段 |
| `chain-fork` | 字段一致但链头分叉（重新计算过校验和） |
| `state-changed` | 指定状态 key 在导出后被改写（含版本号） |
| `state-missing` | 指定状态 key 已被删除 |
| `unparseable-line` | 线上流水有无法解析的行（文件被破坏） |

导出之后**正常新增**的流水计入 `appended_entries`、新增状态键计入 `state_added`，
不算异常——对账区分「旧账被动过」和「系统正常增长」。

## 5. 命令退出码

| 命令 | 0 | 2 | 3 |
| --- | --- | --- | --- |
| `attest-verify` | 整包可信 | — | 验签/链/根任一失败 |
| `attest-reconcile` | 完全一致（或仅有正常增长） | — | 包不可信或存在差异 |

## 6. 边界与生产建议

* 本方案证明的是「自导出时刻起包没被动过、线上库相对导出点是否一致」。
  若要证明「写入那一刻起就没动过」，应在**写入路径**上定期签名/锚定链头，
  或把链头发往外部仅追加存储（WORM）/时间戳服务；当前导出签名覆盖的是导出时点。
* 时钟可信是另一个前提：`written_at` 防改但不防「服务器时钟本身被调」，
  有合规要求时应对时（NTP 认证）或把时间戳服务的回执一并入包。
* 删除属于业务操作时，不要物理删行：追加一条带原因的删除事件（墓碑），
  物理删除永远会表现为缺段。
* 多产线按 `stream` / `namespace` 各自独立成链，流名已绑定进哈希。
* 相关代码：`flashsmelter/attest/`（`chain.py` 原语、`crypto.py` 签名、
  `bundle.py` 导出/验包/对账），测试见 `tests/test_attest.py`。
