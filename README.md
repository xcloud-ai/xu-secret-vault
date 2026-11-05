# 密钥保险库

> [!NOTE]
> **密钥保险库**：在本地加密保存密码、API 密钥与私钥。

这是一个把敏感凭据集中存放在单个加密文件里的 Obsidian 插件。插件打开一个侧边栏面板，首次使用时设置主密码；之后所有条目以整体加密的形式写入 `xu-secrets.enc`，明文只存在于内存与界面中，锁定后立即从内存清除。插件不发起任何网络请求，也不把主密码、派生密钥或明文写入 `data.json`、笔记或其它明文文件。

> English description below for review purposes. / 以下为英文说明，用于过审。

XU Secret Vault keeps passwords, API keys and private keys in a single locally encrypted file. On first use it asks for a master password; the whole entry set is then encrypted as one blob and written to `xu-secrets.enc`. Plaintext exists only in memory and the UI, and is cleared as soon as the vault is locked. The plugin makes no network requests and never writes the master password, derived key or plaintext to `data.json`, notes or any plaintext file.

## 功能特性

- 单文件加密保险库：默认 `xu-secrets.enc`，路径可在设置中修改，非 `.enc` 后缀会自动补全。
- PBKDF2-HMAC-SHA512（600,000 次）派生 AES-256-GCM 密钥，随机 16 字节盐与每次写盘随机 12 字节 IV。
- 信封头参数（版本、KDF 算法、迭代数、盐）参与 GCM 认证（AAD），篡改文件头会导致解密失败。
- 会话密钥为 non-extractable CryptoKey，仅驻留内存；锁定、关闭插件或自动锁定后立即丢弃。
- 列表默认只显示名称、类型与标签；内容需点击「显示」才出现在界面上，备注仅在编辑弹窗中可见。
- 支持密码、API 密钥、私钥、备注四种条目类型，支持标签与搜索。
- 新增/编辑使用弹窗；编辑写回前比对原值，无变化不写盘；删除需二次确认。
- 复制到剪贴板后按设定秒数自动清空；若剪贴板已被替换则不会误删新内容。
- 自动锁定（默认 5 分钟无操作）；锁定时清空面板明文、关闭正在编辑的弹窗、清空本插件复制的剪贴板内容并丢弃密钥。
- 界面支持中文（默认）与 English。

### Features

- A single encrypted vault file (default `xu-secrets.enc`, path configurable).
- PBKDF2-HMAC-SHA512 (600,000 iterations) derives an AES-256-GCM key, with a random 16-byte salt and a fresh 12-byte IV on every write.
- Envelope header parameters (version, KDF algorithm, iterations, salt) are authenticated as AES-GCM additional data, so header tampering breaks decryption.
- The session key is a non-extractable CryptoKey kept only in memory and dropped on lock, unload or auto-lock.
- The list shows only name, type and tags; content appears only after clicking "Show", while the note is visible in the edit modal.
- Password, API key, private key and note entry types, with tags and search.
- Add/edit via modal; unchanged edits are not written; deletion requires confirmation.
- Clipboard is cleared automatically after a configurable delay, and only if it still holds the copied secret.
- Auto-lock after an idle period; locking clears on-screen plaintext, closes open edit modals, clears the plugin's clipboard content and discards the key.

## 安装

### 方式一：从 Obsidian 社区目录安装

当前版本 0.1.0 为本地开发版，尚未提交社区目录。上架后可在「设置 → 社区插件 → 浏览」中搜索 `XU Secret Vault` 安装并启用。

### 方式二：手动安装

1. 打开 vault 的 `.obsidian/plugins/` 目录。
2. 新建 `xu-secret-vault/` 文件夹，放入 `main.js`、`manifest.json`、`styles.css`。
3. 重启 Obsidian，在「设置 → 社区插件」中关闭安全模式并启用「XU Secret Vault」。

### Installation

1. Open the `.obsidian/plugins/` directory of your vault.
2. Create a folder named `xu-secret-vault/` and put `main.js`, `manifest.json` and `styles.css` inside.
3. Restart Obsidian, disable Restricted Mode under Settings → Community plugins, then enable "XU Secret Vault".

## 使用方法

### 基本流程

1. 点击左侧功能区的锁图标，或按 `Cmd/Ctrl+P` 执行「打开密钥保险库」。
2. 首次使用：在侧边栏输入两次主密码，点击「创建保险库」。主密码不会写入磁盘，忘记后无法恢复。
3. 解锁后点击「新增」，填写名称、类型、标签、内容与备注并保存。
4. 需要查看内容时点击条目上的「显示」；点击「复制」可复制内容，剪贴板会在设定秒数后自动清空。
5. 点击「编辑」修改条目；点击「删除」并在确认弹窗中确认。
6. 点击「锁定」或执行「锁定保险库」命令；无操作超过设定分钟数也会自动锁定。

### 首次使用

主密码只用于在本机派生加密密钥。请使用足够长且唯一的密码，并自行做好备份。保险库文件损坏或主密码遗失时，插件无法恢复数据。

### 日常使用

保持面板锁定是默认安全状态。查看或复制后建议手动锁定；自动锁定会在无操作达到设定时长后触发，并立即清除界面与内存中的明文。

## 设置说明

| 设置项 | 默认值 | 说明 |
| --- | --- | --- |
| 界面语言 | 中文 | 切换中文 / English。 |
| 保险库文件路径 | `xu-secrets.enc` | 相对 vault 根目录；必须以 `.enc` 结尾，缺失时自动补全。 |
| 自动锁定（分钟） | 5 | 无操作超过该时长后自动锁定并清除内存明文。 |
| 剪贴板清空（秒） | 30 | 复制密钥后自动清空剪贴板；剪贴板已被替换时不会覆盖。 |
| 立即锁定 | — | 清除内存中的密钥与明文，需要重新输入主密码。 |

## 命令列表

| 命令 | ID | 说明 |
| --- | --- | --- |
| 打开密钥保险库 | `open-vault` | 打开或聚焦侧边栏面板。 |
| 锁定保险库 | `lock-vault` | 立即锁定并清除内存中的密钥与明文。 |
| 新增条目 | `new-entry` | 打开新增条目弹窗（需先解锁）。 |

## 安全说明

### 加密设计

- 密钥派生：PBKDF2-HMAC-SHA512，600,000 次迭代，随机 16 字节盐；盐与迭代数写入信封头并参与 GCM 认证。
- 数据加密：AES-256-GCM，每次写盘生成新的随机 12 字节 IV；整个条目集合作为整体加密。
- 认证：`formatVersion`、KDF 算法、迭代数与盐拼成规范化字符串作为 `additionalData`，任何头字段被篡改都会导致解密失败，避免把迭代数改小或替换盐的降级攻击。
- 密钥生命周期：派生密钥为 non-extractable，仅保存在内存；锁定、自动锁定、插件卸载时置空。主密码、密钥、明文均不写入 `data.json` 或任何配置文件。
- 落盘校验：每次写盘后立即读回比对全文，不一致则报错且不更新内存数据。

### 锁定的实际动作

触发锁定（手动、自动或命令）时，插件会同步执行：丢弃 CryptoKey 与内存中的条目集合、清空面板中所有已显形的明文、关闭所有正在编辑的弹窗、清除本插件写入剪贴板的内容（仅当剪贴板仍是该密钥时）。随后面板回到锁定态，需要重新输入主密码。

### 明文可能残留的其他位置

插件只能保证自身不把明文写入 `.md`、明文文件或配置文件。以下位置不由本插件控制，请按需自行清理：

- 系统剪贴板：复制后的设定秒数内为明文；系统剪贴板历史/管理器可能长期保留。
- 输入法：主密码或内容输入时的输入法联想、候选词与云同步历史。
- Obsidian 与操作系统的编辑历史、撤销栈、崩溃转储、交换文件、屏幕录制或截图工具。
- 本插件运行期间的内存：解锁到锁定之间，条目明文存在于进程内存中；锁定时主动置空，但操作系统层面的内存快照不受插件控制。

### 已知限制

- 手机端 WebView 的 `crypto.subtle` 兼容性尚未实测；插件会在不可用时明确报错并拒绝启动加解密，而不是静默降级。
- 大保险库（数千条目或超大私钥）每次保存都要整体重加密与全文读回校验，保存耗时随数据量增长。
- 不做明文导出/另存为明文、不做主密码提示、不提供密码找回；这些是刻意的安全取舍。
- 保险库文件被外部程序同时改写时，写回校验会报错并保留内存中的旧数据，需重新解锁再操作。

## 技术说明（纯中文）

- 文件格式：单个 JSON 信封，字段为 `formatVersion`、`kdf { algo, iterations, salt }`、`cipher { algo, iv }`、`updatedAt`、`payload`（base64 密文）。密文内容为 `{ version, entries }` 的 JSON。
- 每次保存都会重新生成 IV，盐在保险库生命周期内保持不变；创建新保险库时才生成新盐。
- 写盘使用 Obsidian 的 vault adapter，先确保父目录存在，写入后立即读回并做 JSON 结构校验。
- 自动锁定由 15 秒一次的后台检查触发，实际精度取决于检查周期；任意面板交互会重置空闲计时。
- 插件不注册网络请求、不访问外部服务，日志统一使用 `[xu-secret-vault]` 前缀。

## 许可证

MIT License - Copyright (c) 2026 旭说
