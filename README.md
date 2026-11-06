# 密钥保险库

> [!NOTE]
> **密钥保险库**：在本地加密保存密码、API 密钥与私钥。

这是一个把敏感凭据集中存放在单个加密文件里的 Obsidian 桌面端插件。插件打开一个侧边栏面板，首次使用时设置主密码；之后所有条目以整体加密的形式写入 `xu-secrets.enc`，明文只存在于内存与界面中，锁定后立即从内存清除。插件不发起任何网络请求，也不把主密码、派生密钥或明文写入 `data.json`、笔记或其它明文文件。

> English description below for review purposes. / 以下为英文说明，用于过审。

XU Secret Vault keeps passwords, API keys and private keys in a single locally encrypted file. It is a desktop-only plugin: on first use it asks for a master password, then the whole entry set is encrypted as one blob and written to `xu-secrets.enc`. Plaintext exists only in memory and the UI, and is cleared as soon as the vault is locked. The plugin makes no network requests and never writes the master password, derived key or plaintext to `data.json`, notes or any plaintext file.

## 功能特性

- 单文件加密保险库：默认 `xu-secrets.enc`，路径可在设置中修改，非 `.enc` 后缀会自动补全。
- PBKDF2-HMAC-SHA512（600,000 次）派生 AES-256-GCM 密钥，随机 16 字节盐与每次写盘随机 12 字节 IV。
- 信封头参数（版本、KDF 算法、迭代数、盐）与加密算法一起参与 GCM 认证（AAD），篡改文件头或算法名会导致解密失败。
- 会话密钥为 non-extractable CryptoKey，仅驻留内存；锁定、关闭插件或自动锁定后立即丢弃。
- 列表默认只显示名称、类型与标签；内容需点击「显示」才出现在界面上，备注仅在编辑弹窗中可见；编辑弹窗的明文同样默认掩码。
- 支持密码、API 密钥、私钥、备注四种条目类型，支持标签与搜索。
- 新增/编辑使用弹窗；编辑写回前比对原值，无变化不写盘；删除需二次确认。
- 复制到剪贴板后按设定秒数自动清空；若剪贴板已被替换则不会误删新内容。
- 「表格 / 笔记」双视图：表格保留原有条目管理；笔记视图可用 Markdown 手写账号表与说明，支持标题、列表、粗体、行内代码、管道表格、http/https 链接，以及 `{{条目名.密码}}` 引用（点击引用即复制，沿用 30 秒剪贴板清空）。
- 自动锁定（默认 15 分钟无操作）；切到后台或窗口失焦立即加遮罩并清屏，后台超过 60 秒直接锁定；锁定时清空面板明文、关闭正在编辑的弹窗、清空本插件复制的剪贴板内容并丢弃密钥。
- 写盘采用「写唯一 `.tmp` → 读回解密比对 → 留 `.bak` → rename 原子替换 → 终检 → 删 `.bak`」；任一步失败都保留或回滚旧文件，启动时清理本插件遗留的 `*.tmp*`。检测到文件被外部修改时拒绝覆盖，并另存 `*.conflict-时间戳.enc` 副本，冲突后必须先「重新加载」才能继续编辑。
- 回到前台后的重新验证与解锁同等强度：重新付出完整 KDF 成本并解开会话挑战密文，不使用无盐哈希比对；连续错误复用同一套指数退避。
- 信封格式升级为 v2，并保留 v1 兼容读取：旧信封解密成功后提示并自动升级为 v2；未知版本明确提示「版本不支持」，不会被误读成密码错误。
- 连续解锁失败按指数退避（上限 30 秒），计数只在内存，重启清零。
- 界面支持中文（默认）与 English。

### Features

- A single encrypted vault file (default `xu-secrets.enc`, path configurable).
- PBKDF2-HMAC-SHA512 (600,000 iterations) derives an AES-256-GCM key, with a random 16-byte salt and a fresh 12-byte IV on every write.
- Envelope header parameters (version, KDF algorithm, iterations, salt) are authenticated together with the cipher algorithm as AES-GCM additional data, so header tampering breaks decryption.
- The session key is a non-extractable CryptoKey kept only in memory and dropped on lock, unload or auto-lock.
- The list shows only name, type and tags; content appears only after clicking "Show", while the note is visible in the edit modal and entry content is masked by default there too.
- Password, API key, private key and note entry types, with tags and search.
- Add/edit via modal; unchanged edits are not written; deletion requires confirmation.
- Clipboard is cleared automatically after a configurable delay, and only if it still holds the copied secret.
- "Table / Notes" dual view: the table keeps the existing entry management; the notes view lets you write Markdown account tables and docs with headings, lists, bold, inline code, pipe tables, http/https links, and `{{entry.password}}` references (click a reference to copy it, using the same 30-second clipboard clearing).
- Auto-lock after 15 minutes idle by default; backgrounding or losing window focus masks the panel immediately, and more than 60 seconds in the background locks it.
- Writes use "write a unique .tmp, decrypt-verify, keep .bak, atomic rename, final verify, delete .bak"; any failure keeps or rolls back the old file, and stale `*.tmp*` files are cleaned at startup. External modifications are never overwritten and are saved as a `*.conflict-<timestamp>.enc` copy, which requires "Reload" before editing continues.
- Re-verifying after returning to the foreground costs a full KDF derivation and decrypts an in-session challenge ciphertext; it never compares an unsalted hash, and repeated failures reuse the same exponential backoff.
- The envelope format is now v2 with v1 compatibility reads: legacy envelopes are decrypted, announced and upgraded to v2 automatically; unknown versions report "unsupported version" instead of a password error.
- Repeated unlock failures use exponential backoff capped at 30 seconds, kept in memory only.
- UI language: Chinese (default) and English.

## 笔记与表格

面板顶部可在「表格」与「笔记」之间切换。表格保留原有的条目管理；笔记视图像写 Markdown 笔记一样维护一张账号总表，正文整体随保险库一起加密落盘。

- 笔记编辑：点击「编辑笔记」进入等宽 textarea，直接写 Markdown 源码，「保存笔记」走与条目相同的原子写链路。
- 渲染范围：标题、段落、无序/有序列表、粗体、行内代码、管道表格、链接。表格的 `:---` / `---:` / `:---:` 会按列渲染为左/右/居中。
- 链接：仅 `http`/`https` 可点击，点击后用系统浏览器打开；`javascript:`、`file://` 等其它 scheme 一律按纯文本显示。
- 引用：`{{条目名}}` 取该条目的密码/内容，`{{条目名.密码}}` 取密码，`{{条目名.账号}}` 取条目名本身。引用渲染为掩码按钮，点击复制对应值，沿用 30 秒剪贴板清空；条目不存在时显示灰色「引用缺失: xxx」。
- 安全提醒：表格里直接写明文账号密码也能显示，但**写引用更安全**——锁屏截图、误粘贴或分享屏幕时不会带出明文。引用值不会进入 DOM 文本，只在点击时写入剪贴板。

可复制的第一张表：

```markdown
# 我的密钥

## 常用账号

| 名称 | 账号 | 密码 |
| :--- | :--- | :--- |
| GitHub | {{GitHub.账号}} | {{GitHub.密码}} |
| 阿里云 | {{阿里云.账号}} | {{阿里云.密码}} |

- 官网：[GitHub](https://github.com)
- 备注：`仅限工作使用`
```

先在「表格」里新增名为 `GitHub`、`阿里云` 的条目，再粘贴上面的内容到笔记编辑器保存即可。

### 笔记模式怎么进

1. 打开保险库面板并解锁。
2. 面板顶部有两个切换按钮：左侧「▦ 表格」、右侧「✎ 笔记」。当前选中的按钮会高亮。
3. 点「✎ 笔记」即可进入笔记模式。第一次切到空笔记时会出现一次性提示；笔记为空时页面会显示引导块和「插入示例表格」按钮。
4. 点「插入示例表格」会把三列示例（名称 / 账号 / 密码）直接写进编辑器并进入编辑态，**不会自动保存**，确认后点「保存笔记」。
5. 如果当前笔记已有内容，再点「插入示例表格」会先让你选择「追加到末尾」或「替换全文」，不会静默插入第二份。

### 引用名怎么对齐

- 引用里的条目名必须与「表格」中的条目名完全一致：`{{GitHub.密码}}` 对应名称是 `GitHub` 的条目，写成 `GitHub ` 或 `github` 都会匹配失败。
- 笔记编辑态的下方会列出「可用条目名」（只显示名称，不含任何密码），可以直接对照拼写；条目超过 8 个时折叠为「共 N 个，展开查看」。
- 渲染态里灰色的「引用缺失: xxx」可以点击；确认后会打开现有的新增条目表单并预填该名称（`.账号` / `.密码` 只取前面的条目名），用户取消则什么都不做，不会自动创建或写入。
- 条目内容也走同一套 Markdown 渲染：把表格误粘到条目「内容」里时，点「显示」仍然能看到表格；但条目里不能引用自身，自引用会显示为灰色「引用缺失」并注明不能引用自身。
- 保存条目时，如果内容里检测到管道表格或 `{{...}}` 引用，会提示一次「这段看起来是笔记内容，笔记模式里会渲染成表格」。同一会话只提示一次，不阻塞保存。

## 安装

### 方式一：从 Obsidian 社区目录安装

当前版本 0.2.1 为本地开发版（桌面端限定），尚未提交社区目录。上架后可在「设置 → 社区插件 → 浏览」中搜索 `XU Secret Vault` 安装并启用。

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
5. 点击「编辑」修改条目（内容默认掩码，点「显示」后才呈现）；点击「删除」并在确认弹窗中确认。
6. 点击「锁定」或执行「锁定保险库」命令；无操作超过设定分钟数也会自动锁定。切换到其它应用会立即加遮罩，后台超过 60 秒会自动锁定。

### 首次使用

主密码只用于在本机派生加密密钥。请使用足够长且唯一的密码，并自行做好备份。保险库文件损坏或主密码遗失时，插件无法恢复数据。

### 日常使用

保持面板锁定是默认安全状态。查看或复制后建议手动锁定；自动锁定会在无操作达到设定时长后触发，并立即清除界面与内存中的明文。

## 设置说明

| 设置项 | 默认值 | 说明 |
| --- | --- | --- |
| 界面语言 | 中文 | 切换中文 / English。 |
| 保险库文件路径 | `xu-secrets.enc` | 相对 vault 根目录；必须以 `.enc` 结尾，缺失时自动补全。 |
| 自动锁定（分钟） | 15 | 无操作超过该时长后自动锁定并清除内存明文；切后台超过 60 秒也会锁定。 |
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

- 密钥派生：PBKDF2-HMAC-SHA512，600,000 次迭代，随机 16 字节盐；盐与迭代数写入信封头并参与 GCM 认证。主密码在派生前先做 Unicode NFC 归一化，不同平台/输入法下的等价字符会得到一致结果；因此请保持输入法不做额外的全半角或形近字符改写。
- 数据加密：AES-256-GCM，认证标签长度显式设为 128 位，每次写盘生成新的随机 12 字节 IV；整个条目集合作为整体加密。
- 认证：`formatVersion`、KDF 算法、迭代数、盐与 `cipher.algo` 拼成规范化字符串作为 `additionalData`，任何头字段或算法名被篡改都会导致解密失败，避免把迭代数改小、替换盐或降级算法的攻击。
- 密钥生命周期：派生密钥为 non-extractable，仅保存在内存；锁定、自动锁定、关闭面板或插件卸载时置空。主密码、密钥、明文均不写入 `data.json` 或任何配置文件。
- 落盘校验：先写唯一命名的 `*.tmp`（内容仍是密文），读回后解密并逐字段比对，留 `.bak` 后 `rename` 原子替换，终检通过再删 `.bak`；任一步失败都会清理 tmp；若 rename 后终检失败，则用 `.bak` 回滚并同步修正哈希记录。启动时清理本插件遗留的 `*.tmp*`。
- 同步冲突：记录上次读写的文件哈希；`rename` 前还会重取一次哈希复核（缩小 TOCTOU 窗口）。发现外部修改（或凭空出现/消失）时拒绝覆盖，把本次改动另存为 `xu-secrets.conflict-<时间戳>.enc`；内存快照标记为过期，弹窗与入口禁止继续编辑，必须点「重新加载」后才恢复。
- 抗爆破：连续解锁失败按指数退避（0.5 秒起，上限 30 秒），成功或重启后清零，计数只在内存。回到前台后的重新验证同样付出完整 KDF 成本并受同一套退避约束，不使用无盐哈希比对。
- 统一失败口径：文件缺失、JSON 畸形、base64 损坏、密码错误对外都只给一条「解锁失败」文案，不向界面抛原始异常；文件缺失单独显示「找不到保险库」错误态，且不会引导重新创建。仅「未知信封版本」单独提示「版本不支持」。
- 版本兼容：信封格式为 v2（`xsv-aad-v2`）。读取时对 v1 信封先按 v2 AAD、再按 `xsv-aad-v1` 尝试；解密成功后提示并自动重写为 v2。未知版本直接拒绝并提示「版本不支持」。
- 容量上限：保险库文件超过 8 MB 时拒绝读取与写入，避免超大文件导致解密与整体重加密卡死。
- 笔记渲染：自带的极简 Markdown 渲染器全程用 DOM API 构建节点，不使用 `innerHTML`/`insertAdjacentHTML`；Markdown 中的 HTML 标签一律按文本转义显示。笔记源码与条目明文一起放在同一个加密载荷里，落盘只有密文。

### 锁定的实际动作

触发锁定（手动、自动、命令、关闭面板或在后台超过 60 秒）时，插件会同步执行：丢弃 CryptoKey、内存中的条目集合与笔记正文、清空面板中所有已显形的明文与笔记渲染区/编辑器、关闭所有正在编辑的弹窗（弹窗内容与条目对象一并丢弃）、清除本插件写入剪贴板的内容（仅当剪贴板仍是该密钥时）。窗口失焦或切到后台时会先关闭所有本插件弹窗、加全屏遮罩并清屏，回到前台后必须重新输入主密码才能继续查看；遮罩期间所有命令入口、写入与复制一律拒绝。

### 明文可能残留的其他位置

插件只能保证自身不把明文写入 `.md`、明文文件或配置文件。以下位置不由本插件控制，请按需自行清理：

- 系统剪贴板：复制后的设定秒数内为明文；系统剪贴板历史/管理器可能长期保留。
- 输入法：主密码或内容输入时的输入法联想、候选词与云同步历史。
- Obsidian 与操作系统的编辑历史、撤销栈、崩溃转储、交换文件、屏幕录制或截图工具。
- 本插件运行期间的内存：解锁到锁定之间，条目明文存在于进程内存中；锁定时主动置空，但操作系统层面的内存快照不受插件控制。

### 已知限制

- 桌面端限定（`isDesktopOnly: true`）：手机端 WebView 的 `crypto.subtle` 与剪贴板 `readText` 均未实测，因此不宣称移动端可用；后续实测通过再放开。
- 大保险库（数千条目或超大私钥）每次保存都要整体重加密、解密比对与全文读回，保存耗时随数据量增长；超过 8 MB 直接拒绝。
- 自动锁定由 15 秒一次的后台检查触发，实际精度取决于检查周期；任意面板交互会重置空闲计时。
- 不做明文导出/另存为明文、不做主密码提示、不提供密码找回；这些是刻意的安全取舍。
- 保险库文件被外部程序同时改写时，插件拒绝覆盖并生成 conflict 副本，不会自动合并；冲突后进入只读态，必须「重新加载」才能继续编辑，需要用户自行比对两份文件。
- v1 兼容读取并升级为 v2 后，旧版插件将无法再读取该文件；升级前请先备份副本。
- 备份方式就是复制 `xu-secrets.enc` 这个密文文件本身；不需要也不应该导出明文。恢复时把该文件放回原路径即可。

## 版本记录

### 0.2.1

- 笔记模式入口强化：顶部切换按钮带「▦ / ✎」图标，选中态使用强调色；首次切到空笔记时给一次性提示；空态显示引导块与「插入示例表格」按钮。
- 示例表格：空笔记直接插入并进入编辑态、不自动保存；笔记已有内容时先让用户选择「追加到末尾」或「替换全文」，不再静默插入第二份。
- 条目内容也走同一 Markdown 渲染器：把表格误粘到条目「内容」后，点「显示」仍能看到真实表格；编辑态内容框保持源码纯文本。条目内容引用自身时降级为灰色「引用缺失」并注明不能引用自身，避免递归。
- 保存条目时若检测到管道表格或 `{{...}}` 引用，保存成功后提示一次「这段看起来是笔记内容，笔记模式里会渲染成表格」，同一会话只弹一次、不阻塞保存。
- 引用缺失可点击补建：渲染态的灰色「引用缺失」点击后先确认，确认才打开现有新增条目表单并预填名称，取消则什么都不做，不自动创建、不静默写入。
- 笔记编辑态列出「可用条目名」（仅名称、不含值），超过 8 个折叠为「共 N 个，展开查看」；引用缺失提示条帮助对齐拼写。

### 0.2.0

- 新增「笔记」视图：顶部在「表格 / 笔记」之间切换；笔记列表默认包含一篇「我的密钥」，可在等宽 textarea 中直接编辑 Markdown 源码，保存复用既有的串行化原子写链路。
- 加密载荷新增 `notes: [{ id, title, body, updatedAt }]` 与 `contentVersion`；现有 `entries` 结构不变，信封版本不变。读取只有 `entries` 的旧数据时自动补一篇默认笔记，下次保存时写入新结构。
- 笔记渲染支持标题、段落、无序/有序列表、粗体、行内代码、管道表格（按 `:---`/`---:`/`:---:` 列对齐）与链接；仅 `http`/`https` 链接可点击并用系统浏览器打开，其它 scheme 按纯文本渲染。
- 引用语法 `{{条目名}}` / `{{条目名.密码}}` / `{{条目名.账号}}` 渲染为掩码按钮，点击复制对应值并沿用 30 秒剪贴板清空；条目不存在时显示灰色「引用缺失: xxx」。
- 安全：渲染全程使用 DOM API，禁用 `innerHTML`/`insertAdjacentHTML`，Markdown 中的 HTML 标签按文本转义；锁定、挂起、关闭面板时一并清空笔记列表、渲染区、编辑器与草稿；只读冲突副本下笔记只能查看，保存被拒。
- 测试补充：表格渲染与列对齐、链接白名单（`javascript:`/`file://` 被拒）、引用复制、引用缺失、锁定后笔记区无明文、只读副本笔记写入被拒、旧数据自动补默认笔记。

### 0.1.5

- 修复首次保存条目报 `Destination file already exists!`：Obsidian 的 `DataAdapter.rename` 在目标已存在时会直接抛错（不会覆盖），原实现 `rename(tmp, 正式库)` 因此必然失败。现在改为「旧库改名到 `.bak` → tmp 落位 → 终检 → 删除 `.bak`」，目标存在也能安全替换。
- 回滚改为把 `.bak` 改名回原位；rename 或 remove 失败时旧库始终可从 `.bak` 恢复，不会留下半截文件或丢库。
- 写盘失败不再把适配器的英文原串抛到界面，统一为中文 `err_save_failed`；创建时若目标意外存在仍提示「保险库已存在」。

### 0.1.4

- 冲突副本改为只读：解锁界面选中副本后，顶部显示「正在查看冲突副本（只读）」横幅，隐藏新增/编辑/删除入口，仅保留查看与复制；所有写操作以同一文案拒绝，避免在副本上的改动于锁定时静默丢弃。锁定后选择复位，只读态随之解除，回到正式库后可正常编辑。
- 冲突副本枚举支持嵌套命名：`xxx.conflict-A.conflict-B.enc` 也能进入候选列表；正式库固定第一，其余按最后一次冲突时间倒序。
- 回滚失败时仅在确实写出了 `.bak` 的情况下才在错误文案中给出该恢复路径，原文件本不存在时不再指向不存在的文件。

### 0.1.3

- 跨休眠计时：空闲与后台 60 秒判定同时记录墙钟死线与单调钟死线，取两者较大值。合盖休眠期间 `performance.now()` 不前进，唤醒后由墙钟兜底触发锁定；系统时间被回拨时由单调钟兜底。
- 多面板隔离：已有解锁态面板时，新开面板一律以挂起态打开并要求重新验证主密码，不再共享会话。
- 冲突副本显式选择：解锁前枚举同 stem 的 `*.conflict-*.enc`，在解锁界面列出候选文件；默认仍选正式库，绝不自动挑选，选定后从所选文件加载。
- 临时文件清理收紧：只匹配本插件生成的 `*.tmp-YYYYMMDD-HHMMSS-<1~8位随机>` 命名，且只清理超过 1 小时的残留，避免误删用户文件或另一实例正在写的 tmp。
- 回滚改为「先写 tmp 再 rename」；回滚失败时保留 `.bak`，并在错误文案中给出恢复路径。
- 冲突副本写盘不再更新 `knownBlobHash` 基线，避免后续读写指向副本。
- 重新验证在 KDF 返回后复查会话 generation，KDF 期间被锁定不会误清挂起态。
- 超限文件（> 8 MB）使用独立错误文案，不计入失败次数、不触发退避。
- 剪贴板无法读取或内容已被替换时不再清空，只提示手动检查；仅当读到的内容确为本插件写入值时才清。
- v1 升级失败只提示一次「升级失败，继续使用旧格式」，不再每次解锁重复打扰。
- 删除确认弹窗关闭时释放持有的条目对象。

### 0.1.2

- 遮罩加固：失焦/切后台时关闭本插件所有弹窗，确保已揭示明文立刻不可见；遮罩期间命令入口、写入与复制全部拒绝（`suspended` 校验）。
- 重新验证改为与解锁同强度：用会话盐重新派生密钥并解开会话挑战密文，复用失败计数与指数退避，不再使用无盐哈希比对。
- 信封升级为 v2（`xsv-aad-v2`）；支持 v1 兼容读取并自动升级；未知版本提示「版本不支持」而非密码错误。
- 写入加固：rename 前复查 generation 与文件哈希（TOCTOU）；rename 前留 `.bak`，终检失败自动回滚并修正哈希记录；`.tmp` 改唯一命名并在启动时清理残留。
- 冲突分支改为只读冲突态：明确提示「已另存副本、原文件未覆盖」，内存快照不更新，必须「重新加载」才能继续编辑。
- 创建保险库在 rename 前再次检查文件是否存在，避免 exists→rename 竞态覆盖旧库。
- 编辑弹窗关闭后释放条目对象；揭示后提供「再次隐藏」；退避与空闲计时改用单调时钟；列表内容阻止拖拽；剪贴板清空前再确认一次。

### 0.1.1

- 实证审计加固：信封参数（含 `cipher.algo`）纳入 AAD，显式 128 位认证标签。
- 原子写与并发串行化：写 `.tmp` → 读回解密逐字段比对 → `rename`；两次快速保存不再互相覆盖。
- 外部修改检测：哈希不一致时拒绝覆盖并另存 conflict 副本。
- 切后台遮罩、失焦遮罩、后台 60 秒自动锁定、回到前台需重新验证主密码；关闭面板即锁定。
- 锁定/写盘失败不再误报「已保存」；解锁失败统一文案并加入指数退避；密码 NFC 归一化。
- 编辑弹窗内容默认掩码；输入框关闭拼写检查与自动填充，并阻止拖拽。
- 保险库缺失改为错误态，不再引导重新创建；加入 8 MB 上限；`updatedAt` 移入加密载荷。
- 自动锁定默认改为 15 分钟；插件改为桌面端限定。

## 技术说明（纯中文）

- 文件格式：单个 JSON 信封，字段为 `formatVersion`（当前 2）、`kdf { algo, iterations, salt }`、`cipher { algo, iv }`、`payload`（base64 密文）。`updatedAt` 与条目一起放在加密载荷内，不在信封头明文暴露。
- 每次保存都会重新生成 IV，盐在保险库生命周期内保持不变；创建新保险库时才生成新盐。v1 信封读取成功后会自动重写为 v2。
- 写盘使用 Obsidian 的 vault adapter：确保父目录存在 → 写唯一命名的 `*.tmp` → 读回解密逐字段比对 → 写 `.bak` → `rename` 原子替换 → 再次读回校验 → 删除 `.bak`；失败时按需回滚并清理。
- 写盘前与 `rename` 前都会用 SHA-256 哈希比对当前磁盘内容；与上次读写记录不一致即判定外部修改。
- 自动锁定由 15 秒一次的后台检查触发；任意面板交互（含弹窗输入）会重置空闲计时。
- 插件不注册网络请求、不访问外部服务，日志统一使用 `[xu-secret-vault]` 前缀。

## 许可证

MIT License - Copyright (c) 2026 旭说
