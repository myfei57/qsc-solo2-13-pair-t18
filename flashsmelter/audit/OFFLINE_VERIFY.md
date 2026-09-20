# 离线核验包：断网可查、事后可证

满足车间断网期间**能查当前状态与一段流水**、回到线上**能逐条对回**，并能直接指出
**哪条被改过、哪段缺失**的需求。全部基于 Python 标准库实现，离线机无需安装任何东西。

## 它防住了什么

旧版审计流水每行只有「自校验和」`sha256(seq, 时间, 内容)`，**条与条之间没有链接、
也没有签名**。因此「改掉某条、再按改后的内容重算校验和」就能瞒过 `verify`。
离线核验包在不改动任何现有写入路径的前提下，补了三层证据：

1. **哈希链（tamper-evident log）**
   每条事件 `chain_hash = SHA256(prev_hash || 行原始字节)`，段首锚住它在流水里
   前一条的链哈希（*predecessor*）。改任一字节 → 该行及其后所有链哈希全部失效，
   分叉点就是被改的序号；删一段 → 序号不连续且前置锚点对不上。
2. **Merkle 根**
   事件段与状态快照各压成一个 32 字节根，签名只需覆盖根。
3. **Ed25519 签名**
   根、文件哈希、范围、导出时间写进 `manifest.json`，由产线私钥签名。离线机凭预置
   公钥确认「导出当时确实如此」。

> 信任边界：私钥只放在**线上导出主机**（文件权限 600，建议进一步放进 HSM）。
> 车间离线机只携带 `public.pub`。首次分发公钥时请线下核对指纹（清单与 README 里
> 都印有指纹）。**即使私钥日后泄露，攻击者也无法伪造已经签出去的旧段**——重签
> 只能签新内容，盖不住旧段已固定的链与根。

## 命令一览

```bash
# 线上主机执行一次：生成签名密钥（私钥留在 var/keys，分发 .pub 到离线机）
flashsmelter keychain-init --keys-dir var/keys

# 导出核验包（当前状态快照 + 审计流水，默认从第 1 条到最新）
flashsmelter pack-export visits/visit-2026-09-19 --keys-dir var/keys
flashsmelter pack-export visits/visit.zip --zip --since 100   # 也可打单个 zip / 截区间

# 断网车间：不需要控制系统，两种方式任选
python3 verifier.py visit-2026-09-19 --pubkey public.pub      # 随包自带，纯标准库
# 或双击 verifier.html，把整个目录 / zip 选进去（用浏览器 Web Crypto 验签）

# 回到线上：逐条对账，列出被改 / 缺失 / 插入 / 状态变更
flashsmelter pack-reconcile visits/visit-2026-09-19 --pubkey var/keys/line1.pub
```

退出码：`0` 通过、`2` 核验未通过（证据被破坏或来源不可信）、`1` 用法/读取错误。

## 核验包内容

| 文件 | 作用 |
| --- | --- |
| `manifest.json` | 清单：范围、前置锚点、链尖、两棵 Merkle 根、各文件哈希、导出时间、签名指纹 |
| `manifest.sig` | 产线私钥对清单字节的 Ed25519 签名 |
| `public.pub` | 对应公钥（首次仍需线下核对指纹） |
| `events.jsonl` | 审计流水导出段，**逐行原始字节**（哈希链的输入） |
| `chain.jsonl` | 每行的 `prev_hash`/`chain_hash`，用于离线时把断链精确定位到序号 |
| `state.jsonl` | 导出时刻的状态快照（每条落盘信封的规范 JSON） |
| `verifier.py` / `verifier.html` | 离线核验脚本 / 浏览器页，随包携带 |

## 对账报告怎么读

- `events.altered[]`：同序号线上与包不一致。
  - `live-corrupt`：线上自校验和都对不上（直接破坏）；
  - `live-rewritten`：**自校验和正常但哈希链对不上**——改完重算了旧校验和，
    这正是旧 `verify` 看不破、而本系统能抓到的隐蔽改写；并给出字段级新旧值。
- `events.missing_seqs`：包里有、线上没有（被删除/缺段），同时给压缩区间如 `3-4`。
- `events.inserted_seqs`：导出区间内线上多出来、包里没有（事后插入）。
- `anchor`：导出段前置锚点是否仍在、链哈希是否一致（检测「整段被截断/早期被删」）。
- `state.changed/deleted/added`：状态快照差异，含版本号与字段级 diff。
- 总判定 `verdict`：`ok` / `mismatch` / `journal-tampered` / `pack-invalid`。

## 设计要点（跨语言一致性）

- 事件链哈希的输入是 `events.jsonl` 的**落盘原始字节**，核验端不重新序列化，
  因此 Python、浏览器 JS、独立脚本结论必然一致。
- 状态 Merkle 叶直接对 `state.jsonl` 的**整行字节**取哈希，避免不同语言对数字
  序列化不同（Python 的 `5200.0` 与 JS 的 `5200`）导致根分歧。
- 域分隔前缀（`FS1\x01event` / `FS1\x01state` / `FS1\x02node`）防止事件叶、
  状态叶与 Merkle 内部节点之间被人为构造碰撞。
