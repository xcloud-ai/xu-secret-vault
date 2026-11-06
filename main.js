/* XU Secret Vault — 本地加密密钥保险库（明文不落盘） */
'use strict';

const { ItemView, Modal, Notice, Plugin, PluginSettingTab, Setting } = require('obsidian');

const PLUGIN_ID = 'xu-secret-vault';
const VIEW_TYPE = 'xu-secret-vault-page';
const LEGACY_VIEW_TYPE = 'xu-secret-vault-view';
const REPO_URL = 'https://github.com/xcloud-ai/xu-secret-vault';
const DEFAULT_VAULT_PATH = 'xu-secrets.enc';
// 0.4.0 起：默认存储目录与默认文件名；旧的 <vault>/xu-secrets.enc 作为兼容文件继续可用
const DEFAULT_VAULT_DIR = 'xu-secrets';
const DEFAULT_FILE_NAME = '我的密钥';
const FILE_NAME_MAX = 64;
const GROUP_NAME_MAX = 64;
const GROUP_UNGROUPED = '';
// 冲突副本不进入普通文件列表：它们是同一文件的只读快照
const CONFLICT_COPY_RE = /\.conflict-[0-9]{8}-[0-9]{6}(?:-[0-9]+)?\.enc$/i;
const FORMAT_VERSION = 3;
const V2_FORMAT_VERSION = 2;
const LEGACY_FORMAT_VERSION = 1;
const KDF_ALGO = 'PBKDF2-SHA512';
const KDF_HASH = 'SHA-512';
const KDF_ITERATIONS = 600000;
// 密保答案派生包裹密钥；恢复码是高熵随机值，迭代数可低一些
const RECOVERY_KDF_ITERATIONS = 1000000;
const RECOVERY_CODE_KDF_ITERATIONS = 100000;
const AAD_PREFIX = 'xsv-aad-v2';
const AAD_PREFIX_V1 = 'xsv-aad-v1';
const AAD_PREFIX_V3 = 'xsv-aad-v3';
const REVERIFY_MARKER = 'xsv-reverify-challenge-v3|';
const CIPHER_ALGO = 'AES-256-GCM';
const TAG_LENGTH = 128;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const FILE_ID_BYTES = 16;
const DEK_BYTES = 32;
const MASTER_KEY_BYTES = 32;
const RECOVERY_QUESTIONS_COUNT = 3;
const SECURITY_ANSWER_MIN = 12;
const MIN_MASTER_PASSWORD_LENGTH = 8;
const MAX_VAULT_BYTES = 8 * 1024 * 1024;
const HIDDEN_LOCK_MS = 60000;
const BACKGROUND_LOCK_CHOICES = [0, 5, 10, 30, 60, 120];
const DEFAULT_BACKGROUND_LOCK_SECONDS = 30;
const COLUMN_RULE_LIMIT = 50;
const COLUMN_RULE_NAME_MAX = 40;
const COLUMN_RULE_MODES = ['plain', 'secret'];
// 列显示规则默认是空表：不做任何按列名自动推断，所有单元格一律按原文显示。
// 只有用户手动把某列设为「密文」才会遮挡；精确匹配 > 包含匹配 > 未命中按明文，名字大小写不敏感。
// 0.3.1 的预置规则（8 密文 + 4 明文）：仅用于升级时识别，命中则视为未自定义并清空
const LEGACY_DEFAULT_COLUMN_RULES = [
  { name: '密码', mode: 'secret' },
  { name: '口令', mode: 'secret' },
  { name: 'password', mode: 'secret' },
  { name: 'pwd', mode: 'secret' },
  { name: 'token', mode: 'secret' },
  { name: 'secret', mode: 'secret' },
  { name: '密钥', mode: 'secret' },
  { name: '私钥', mode: 'secret' },
  { name: '名称', mode: 'plain' },
  { name: '账号', mode: 'plain' },
  { name: '网址', mode: 'plain' },
  { name: '备注', mode: 'plain' },
];

function isLegacyDefaultColumnRules(rules) {
  if (!Array.isArray(rules) || rules.length !== LEGACY_DEFAULT_COLUMN_RULES.length) return false;
  const expected = new Map(LEGACY_DEFAULT_COLUMN_RULES.map((rule) => [rule.name.toLowerCase(), rule.mode]));
  if (expected.size !== rules.length) return false;
  return rules.every((rule) => expected.get(rule.name.toLowerCase()) === rule.mode);
}

const DEFAULT_COLUMN_RULES = [];
const MASK_PLACEHOLDER = '••••••';
const BACKOFF_BASE_MS = 500;
const BACKOFF_MAX_MS = 30000;
const ENTRY_TYPES = ['password', 'api-key', 'private-key', 'note'];
const CONTENT_VERSION = 2;
const DEFAULT_NOTE_ID = 'note-primary';

const DEFAULT_SETTINGS = {
  language: 'zh',
  // vaultPath 仅保留给旧版 <vault>/xu-secrets.enc；新文件都在 vaultDir 下
  vaultPath: DEFAULT_VAULT_PATH,
  vaultDir: DEFAULT_VAULT_DIR,
  // 当前文件与折叠的分组只算界面偏好，不含任何笔记内容
  selectedFile: '',
  collapsedGroups: [],
  autoLockMinutes: 15,
  clipboardClearSeconds: 30,
  backgroundLockSeconds: DEFAULT_BACKGROUND_LOCK_SECONDS,
  columnRules: DEFAULT_COLUMN_RULES,
  initializedPath: '',
};

const I18N = {
  zh: {
    cmd_open: '打开密钥保险库',
    cmd_lock: '锁定保险库',
    view_title: '密钥保险库',
    subtitle_locked: '保险库已锁定',
    subtitle_unlocked: '已解锁 · 笔记模式',
    setup_title: '创建主密码',
    setup_desc: '首次使用请设置主密码。主密码不会写入磁盘，只用于在本机派生加密密钥。请自行妥善保管，忘记后无法恢复数据。',
    unlock_desc: '输入主密码解锁保险库。解锁后明文只存在于内存与界面中。',
    label_password: '主密码',
    label_confirm_password: '确认主密码',
    btn_create: '创建保险库',
    btn_unlock: '解锁',
    btn_lock: '锁定',
    btn_add: '新增',
    btn_edit: '编辑',
    btn_delete: '删除',
    btn_copy: '复制',
    btn_reveal: '显示',
    btn_hide: '隐藏',
    btn_hide_again: '再次隐藏',
    btn_mode_table: '表格',
    btn_mode_notes: '笔记',
    btn_note_edit: '编辑笔记',
    btn_note_save: '保存笔记',
    btn_note_cancel: '取消编辑',
    note_default_title: '我的密钥',
    note_ref_missing: '引用缺失: {name}',
    note_ref_copy: '复制引用 {name}',
    note_ref_self: '（不能引用自身）',
    note_editor_ref_hint: '引用缺失: {missing}。请对照下方「可用条目名」核对拼写。',
    note_ref_names: '可用条目名: {names}',
    note_ref_names_more: '可用条目名: 共 {count} 个',
    btn_ref_names_expand: '展开查看',
    btn_ref_names_collapse: '收起',
    note_ref_create_confirm: '该条目不存在，是否创建同名条目「{name}」？',
    btn_create_entry: '创建条目',
    note_ref_create_title: '点击创建同名条目',
    note_no_entries: '（暂无条目）',
    btn_note_sample: '插入示例表格',
    note_sample_choice: '当前笔记已有内容：要追加到末尾，还是替换全文？',
    notice_sample_exists: '示例表格已在笔记中，无需重复插入。',
    btn_sample_append: '追加到末尾',
    btn_sample_replace: '替换全文',
    note_guide_title: '从这里开始写账号表',
    note_guide_desc: '笔记模式会像 Markdown 笔记一样渲染表格与链接；表格单元格按纯文本显示，不做行内 Markdown 或引用解析。点「插入示例表格」会把四列示例写进编辑器，不会自动保存；表格默认全部按原文显示，不自动遮挡。',
    notice_notes_mode_hint: '这里是笔记模式：可以像写 Markdown 一样维护账号表，保存后表格会渲染出来。',
    notice_note_content_hint: '这段看起来是笔记内容，笔记模式里会渲染成表格。',
    notice_cell_copied: '已复制',
    note_empty: '这篇笔记还没有内容，点击「编辑笔记」开始写 Markdown。',
    note_editor_hint: '支持 Markdown：标题、列表、粗体、行内代码、管道表格、链接（仅 http/https）。表格单元格按纯文本显示与复制，可用 \\| 表示单元格内的竖线、\\\\ 表示反斜杠，其它反斜杠保持原样。',
    files_title: '文件',
    btn_new_file: '新建文件',
    files_empty: '还没有文件，点击「新建文件」创建第一个保险库。',
    files_loading: '正在打开文件并校验密钥…',
    group_ungrouped: '未分组',
    group_file_count: '{count} 个',
    file_mtime: '修改于 {time}',
    new_file_title: '新建保险库文件',
    new_file_name: '文件名',
    new_file_name_hint: '可写成「组/名字」层级；会自动补 .enc，同名会被拒绝。',
    new_file_group: '分组',
    new_file_group_new: '＋ 新建分组…',
    new_file_group_name: '新分组名（可用 / 分层）',
    new_file_plaintext_warn: '文件名与分组名在文件系统中是明文可见的，只有内容加密。',
    rename_file_title: '重命名 / 移动文件',
    btn_rename_file: '重命名',
    btn_delete_file: '删除',
    confirm_delete_file: '删除文件「{name}」？此操作不可撤销，文件内容会一起删除。',
    notice_file_created: '已创建文件「{name}」。',
    notice_file_renamed: '已重命名文件「{name}」。',
    notice_file_deleted: '文件已删除。',
    err_file_wrong_password: '该文件不是用当前主密码加密，已保持当前文件不变。',
    err_file_name_exists: '同名文件已存在，请换一个名字或分组。',
    err_file_name_invalid: '文件名为空，或清洗后没有可用字符。',
    err_group_name_invalid: '分组名为空，或清洗后没有可用字符。',
    err_session_password_lost: '会话中缺少主密码，请重新解锁后再打开这个文件。',
    err_note_missing: '笔记不存在或已被移除。',
    btn_cancel: '取消',
    btn_save: '保存',
    btn_confirm_delete: '确认删除',
    search_placeholder: '搜索名称、类型或标签…',
    empty_entries: '暂无条目，点击「新增」创建第一条。',
    empty_search: '没有匹配的条目。',
    content_hidden: '内容已隐藏',
    hint_encrypted: '明文仅存活于内存与界面；落盘内容为 AES-256-GCM 密文。锁定后会从内存清除。',
    hint_locked_state: '保险库已锁定，内存中的密钥与明文已清除。',
    field_name: '名称',
    field_type: '类型',
    field_tags: '标签',
    field_content: '内容',
    field_note: '备注',
    tags_placeholder: '用逗号分隔，例如：工作, 云服务',
    title_new_entry: '新增条目',
    title_edit_entry: '编辑条目',
    delete_title: '删除条目',
    delete_desc: '确定删除「{name}」吗？此操作不可撤销。',
    type_password: '密码',
    type_api_key: 'API 密钥',
    type_private_key: '私钥',
    type_note: '备注',
    notice_vault_created: '保险库已创建。',
    notice_saved: '条目已保存。',
    notice_unchanged: '内容未变化，未写入磁盘。',
    notice_deleted: '条目已删除。',
    notice_copied: '已复制，{seconds} 秒后自动清空剪贴板。',
    notice_clipboard_cleared: '剪贴板中的密钥已清空。',
    notice_auto_locked: '长时间未操作，保险库已自动锁定。',
    notice_locked: '保险库已锁定。',
    notice_unlock_first: '请先解锁保险库。',
    notice_name_required: '请填写条目名称。',
    notice_locked_done: '保险库已锁定，明文已从内存清除。',
    err_password_required: '请输入主密码。',
    err_password_mismatch: '两次输入的主密码不一致。',
    err_unlock_failed: '主密码错误，或保险库文件已损坏。',
    err_crypto_unavailable: '当前环境不支持 WebCrypto（crypto.subtle），无法加解密。请使用桌面版，或改用支持 WebCrypto 的 WebView。',
    err_vault_corrupt: '保险库文件格式无效，已中止读取。',
    err_write_verify: '写入校验失败：磁盘内容与预期不一致，未更新内存数据。',
    err_clipboard_unavailable: '当前环境不支持剪贴板 API，无法自动复制。',
    err_view_open_failed: '无法打开整页视图，请稍后重试或重启 Obsidian。',
    err_generic: '操作失败：{msg}',
    setting_title: 'XU Secret Vault（密钥保险库）',
    setting_header_desc: '在本地加密保存密码、API 密钥与私钥；明文不写入任何笔记或明文文件。',
    setting_group_vault: '保险库',
    setting_group_security: '安全',
    setting_group_about: '关于',
    setting_language: '界面语言',
    setting_language_desc: '切换中文 / English。',
    setting_vault_path: '旧版保险库文件路径（仅兼容）',
    setting_vault_path_desc: '仅用于兼容 0.3.x 的 <vault>/xu-secrets.enc。存在时启动会作为默认文件加载，不会迁移、不会删除；新文件都创建在下方目录里。',
    setting_vault_directory: '保险库目录',
    setting_vault_directory_desc: '相对 vault 根目录，默认 xu-secrets。目录下所有 .enc（含子目录）都会出现在左侧文件列表；文件名与分组名在文件系统中是明文可见的，只有内容加密。',
    setting_auto_lock: '自动锁定（分钟）',
    setting_auto_lock_desc: '无操作超过该时长后自动锁定（默认 15 分钟）；切到后台超过 60 秒也会立即锁定，并清除内存中的密钥与已显形的明文。',
    setting_bg_lock: '失焦锁定倒计时',
    setting_bg_lock_desc: '窗口失焦或切到后台时立即加遮罩，倒计时结束后才锁定并清屏。倒计时内回到窗口会自动解除遮罩，不要求重输主密码；默认 30 秒。选「立即」等于原来的严格行为：立刻锁定，必须重新输入主密码。',
    setting_bg_lock_immediate: '立即（严格）',
    setting_bg_lock_seconds: '{n} 秒',
    setting_column_rules: '列显示规则',
    setting_column_rules_desc: '默认全部按明文显示，不做任何自动推断。只有在这里手动把列名设为「密文」的列才显示 ••••••；精确匹配优先，其次列名包含规则名，未命中按明文。改动会立即重新渲染当前笔记。',
    column_rule_name_placeholder: '列名，例如 手机号',
    column_rule_mode_plain: '明文',
    column_rule_mode_secret: '密文',
    btn_add_column_rule: '添加自定义列名',
    btn_restore_default_rules: '清空全部规则（全明文）',
    confirm_restore_rules: '清空全部列显示规则？清空后所有列都按明文显示。',
    notice_rule_name_empty: '列名不能为空，未保存。',
    notice_rule_limit: '最多 {limit} 条列显示规则，已忽略新增。',
    notice_rules_restored: '已清空全部规则，所有列按明文显示。',
    setting_clipboard_clear: '剪贴板清空（秒）',
    setting_clipboard_clear_desc: '复制密钥后经过该时长自动清空剪贴板；若期间剪贴板已被替换则不会覆盖新内容。',
    setting_lock_now: '立即锁定',
    setting_lock_now_desc: '清除内存中的密钥与明文，需要重新输入主密码才能查看。',
    setting_version: '版本',
    setting_docs: '使用文档',
    setting_docs_desc: '在 GitHub 查看完整使用与安全说明。',
    btn_github: 'GitHub',
    status_loading: '正在读取保险库状态…',
    btn_retry: '重试',
    err_vault_missing: '找不到保险库文件。请在设置中检查路径，或从备份恢复；插件不会自动创建新库，以免覆盖同名旧文件。',
    err_vault_unreadable: '无法读取保险库文件（可能是权限或磁盘错误）。请检查文件后再试。',
    err_vault_too_large: '保险库文件超过 8 MB 上限，已拒绝读取。请拆分条目或改用更小的文件。',
    err_vault_exists: '目标路径已存在保险库文件，已拒绝创建以免覆盖。请先备份或改名。',
    err_unlock_backoff: '尝试次数过多，请在 {seconds} 秒后重试。',
    err_save_discarded: '保险库已锁定或写入被丢弃，本次修改未保存。',
    notice_conflict: '检测到保险库文件被外部修改，原文件未被覆盖；本次改动已另存为副本 {path}。',
    notice_conflict_saved: '已另存副本：{path}。原文件未被覆盖，请先点「重新加载」再继续编辑。',
    conflict_banner: '检测到外部修改：本次改动已另存为 {path}，原文件未被覆盖。为保证不基于过期快照编辑，请先重新加载保险库。',
    btn_reload: '重新加载',
    notice_reloaded: '保险库已重新加载，可以继续编辑。',
    notice_upgraded_v1: '检测到旧版（v1）保险库，已按兼容模式读取，并已自动升级为 v3 信封（DEK + KEK），原文件已保留 .bak 备份。',
    err_version_unsupported: '保险库文件版本不受支持（可能由更新版本的插件创建）。已中止读取，未做任何修改。',
    err_suspended: '保险库已因切到后台或窗口失焦而挂起，请先在面板中重新验证主密码。',
    err_conflict_editing_blocked: '检测到外部修改，原文件未被覆盖且本次改动已另存副本；请先「重新加载」再继续编辑。',
    notice_clipboard_unverified: '无法读取剪贴板，请手动检查其中是否仍残留密钥。',
    notice_upgrade_failed: 'v1 旧格式升级失败，本次继续使用旧格式；不影响本次解锁。',
    label_vault_source: '选择要加载的保险库文件',
    hint_vault_source: '检测到冲突副本。插件不会自动挑选，请确认要解锁的是哪一个文件。',
    err_rollback_kept: '自动回滚未成功，已保留旧密文备份：{path}',
    err_rollback_prefix: '自动回滚未成功，已保留旧密文备份：',
    err_conflict_copy_readonly: '正在查看冲突副本（只读）。它不会写回正式保险库；如需采用其中的内容，请先备份正式库并手动重命名该副本。',
    readonly_copy_path: '当前文件：{path}',
    err_save_failed: '无法写入保险库文件，请检查文件写入权限后重试。',
    notice_background_locked: '插件在后台超过 60 秒，保险库已自动锁定。',
    notice_reverify_failed: '验证失败，请重新输入主密码。',
    mask_title: '内容已隐藏',
    mask_desc: '窗口失去焦点或切到后台，面板已加上遮罩并清除已显形的明文。倒计时结束前回到窗口会自动恢复，无需重输主密码；倒计时结束将锁定。',
    mask_countdown: '将在 {seconds} 秒后锁定',
    mask_return_hint: '回到窗口会自动解除遮罩；倒计时归零则必须重新输入主密码。',
    btn_reverify: '验证并继续',
    btn_eye_show: '临时显示密码',
    btn_eye_hide: '隐藏密码',
    notice_sensitive_columns: '本表 {count} 列按密码处理：单元格显示掩码，点击复制真实值，眼睛按钮切换显示。',
    notice_countdown_locked: '失焦倒计时结束，保险库已锁定。',
    err_session_expired: '会话已失效，请重新解锁。',
    err_new_password_short: '新主密码至少 8 位。',
    err_old_password_wrong: '当前主密码错误。',
    err_current_password_wrong: '当前主密码错误。',
    err_recovery_questions_count: '必须填写 3 个密保问题。',
    err_recovery_questions_empty: '密保问题不能为空。',
    err_recovery_answers_required: '必须填写 3 个密保答案。',
    err_recovery_answer_short: '密保答案至少 12 个字符（归一化后）。',
    err_recovery_code_invalid: '恢复码格式无效。',
    err_recovery_failed: '恢复失败：恢复码或密保答案不正确，无法找回。',
    err_recovery_unavailable: '该保险库没有可用的恢复通道。',
    err_recovery_unavailable_hint: '未设置密保问题，也没有恢复码时，忘记主密码后数据无法恢复。',
    err_batch_busy: '正在批量处理文件（{current}/{total}），期间不能切换文件或编辑。',
    err_batch_empty: '没有可处理的保险库文件。',
    err_batch_interrupted: '批量操作被锁定或挂起中断，已回滚全部已处理文件。',
    err_external_change: '批量处理期间文件被外部改动，已中止并回滚。',
    err_legacy_needs_upgrade: '有旧格式文件尚未迁移，请先用当前主密码解锁一次再操作。',
    notice_upgraded_v2: '检测到 v2 保险库，已自动迁移到 v3 信封（DEK + KEK），原文件已保留 .bak 备份。',
    notice_password_changed: '主密码已更新。',
    notice_recovery_reset: '已重置主密码，请务必牢记。',
    notice_recovery_saved: '密保问题已保存。',
    security_change_password: '修改主密码',
    security_change_password_desc: '改密码只重新包裹 DEK；快速改密秒级完成，彻底轮换会重加密全部内容。',
    btn_change_password: '修改主密码',
    change_pw_title: '修改主密码',
    change_pw_current: '当前主密码',
    change_pw_new: '新主密码',
    change_pw_confirm: '确认新主密码',
    change_pw_mode: '改密方式',
    change_pw_mode_quick: '快速改密（默认，秒级；旧备份仍可用旧密码解开）',
    change_pw_mode_full: '彻底轮换（重新生成 DEK 并重加密内容，耗时更久；旧密码对旧备份仍有效，但对新文件无效）',
    change_pw_quick_note: '快速改密后，旧备份仍可用旧密码解开其中内容。如需让旧密码彻底失效，请用彻底轮换。',
    change_pw_full_note: '彻底轮换会为每个文件生成新 DEK 并重加密内容；旧备份从此无法用旧密码解出当前内容。',
    change_pw_progress: '正在处理第 {current}/{total} 个文件…',
    security_recovery_questions: '密保问题',
    security_recovery_questions_desc: '设置 3 个只有你知道答案的问题；忘记主密码时可作为弱恢复通道。',
    btn_set_recovery: '设置/修改密保问题',
    recovery_title: '设置密保问题',
    recovery_desc: '答案至少 12 字符；会做 NFC、去首尾空白、大小写不敏感、折叠连续空白归一化。答案原文不会存盘。',
    recovery_question_label: '问题 {index}',
    recovery_answer_label: '答案 {index}',
    recovery_answer_hint: '建议写成只有自己知道的长句；少于 12 字符会提示偏弱。',
    btn_save_recovery: '保存密保问题',
    btn_skip_recovery: '暂不设置',
    confirm_skip_recovery: '不设置密保问题，忘记主密码时数据将无法恢复。仍要继续？',
    setup_next: '下一步',
    setup_back: '上一步',
    setup_questions_title: '第二步：设置密保问题（可选）',
    setup_questions_desc: '选择或填写 3 个问题。答案至少 12 字符；不设置则忘记主密码时无法恢复。',
    setup_questions_skip_hint: '你可以暂不设置，但必须二次确认；之后可在设置中补充。',
    setup_code_title: '请保存你的恢复码',
    setup_code_desc: '恢复码只显示这一次，不落盘、不写日志、不进入 data.json。请复制并存入密码管理器或离线保存。',
    btn_copy_recovery_code: '复制恢复码',
    btn_saved_recovery_code: '我已保存',
    recovery_code_warning: '未点「我已保存」前不能跳过；关闭此窗口后恢复码将不再显示。',
    btn_forgot_password: '忘记主密码？',
    forgot_title: '忘记主密码',
    forgot_risk: '只能用恢复码或三道密保问题找回；三道题全对才能恢复，答错不可找回。',
    forgot_choose_code: '使用恢复码（推荐）',
    forgot_choose_questions: '使用三道密保问题',
    forgot_code_label: '恢复码',
    forgot_code_hint: '可带或不带分隔符；不区分大小写。',
    forgot_answer_label: '答案 {index}',
    btn_recover_now: '开始恢复',
    forgot_new_password_title: '设置新主密码',
    forgot_new_password_desc: '恢复成功后必须设置新主密码，并会把全部文件重包为新密码。',
    btn_reset_password: '重置主密码',
    strength_title: '强度与离线破解估算',
    strength_danger: '危险（秒级）',
    strength_general: '一般（小时到天）',
    strength_safe: '安全（年以上）',
    strength_single_gpu: '单张高端显卡（约 5,000 次/秒）',
    strength_cluster: '多卡/集群（约 1,000,000 次/秒）',
    strength_note: '基于 600,000 次 PBKDF2-SHA512，且假设攻击者已拿到加密文件、可离线无限制尝试。',
    strength_boundary_offline: '这是离线爆破估算；如果这个密码在别处泄露过、或被重复使用，攻击者不需要爆破。',
    strength_boundary_params: '估算基于当前算法参数，参数调整后时间会变。',
    strength_short_numeric_hint: '短数字密码（≤6 位纯数字）只适合防身边的人，挡不住离线破解。',
    strength_confirm_title: '这个密码很弱',
    strength_confirm_desc: '预估单卡破解时间约 {single}，集群约 {cluster}。仍要使用吗？',
    security_boundary_title: '安全边界（务必知悉）',
    security_boundary_desc:
      '1) 忘记主密码且未设置恢复码 / 密保问题：无法恢复，插件没有后门。2) 密保问题把安全强度降到「答案有多难猜」，恢复码才是强通道，请存进密码管理器或离线介质；同时设置两者时，取最弱的一环。3) 插件 JS 可读、可反编译，安全来自密钥而非代码隐藏。4) 解锁期间明文在内存与界面中；同进程其他插件、剪贴板历史、崩溃转储、截图或录屏工具不在防护范围内。',
    batch_title: '批量处理中',
    batch_progress: '正在处理第 {current}/{total} 个文件：{name}',
    question_preset_1: '你最喜欢的一本书是什么？',
    question_preset_2: '你小学时最好的朋友叫什么？',
    question_preset_3: '你给自己起的第一个网名是什么？',
    question_custom: '自定义问题…',
    btn_continue: '继续',
    btn_choose_placeholder: '请选择问题…',
  },
  en: {
    cmd_open: 'Open secret vault',
    cmd_lock: 'Lock secret vault',
    view_title: 'Secret Vault',
    subtitle_locked: 'Vault is locked',
    subtitle_unlocked: 'Unlocked · notes mode',
    setup_title: 'Create master password',
    setup_desc: 'Set a master password on first use. It is never written to disk and is only used locally to derive the encryption key. Keep it safe: data cannot be recovered without it.',
    unlock_desc: 'Enter the master password to unlock. After unlocking, plaintext lives only in memory and the UI.',
    label_password: 'Master password',
    label_confirm_password: 'Confirm master password',
    btn_create: 'Create vault',
    btn_unlock: 'Unlock',
    btn_lock: 'Lock',
    btn_add: 'Add',
    btn_edit: 'Edit',
    btn_delete: 'Delete',
    btn_copy: 'Copy',
    btn_reveal: 'Show',
    btn_hide: 'Hide',
    btn_hide_again: 'Hide again',
    btn_mode_table: 'Table',
    btn_mode_notes: 'Notes',
    btn_note_edit: 'Edit note',
    btn_note_save: 'Save note',
    btn_note_cancel: 'Cancel editing',
    note_default_title: 'My secrets',
    note_ref_missing: 'Missing reference: {name}',
    note_ref_copy: 'Copy reference {name}',
    note_ref_self: ' (self-reference is not allowed)',
    note_editor_ref_hint: 'Missing reference: {missing}. Check spelling against "Available entries" below.',
    note_ref_names: 'Available entries: {names}',
    note_ref_names_more: 'Available entries: {count} total',
    btn_ref_names_expand: 'Show all',
    btn_ref_names_collapse: 'Collapse',
    note_ref_create_confirm: 'This entry does not exist. Create an entry named "{name}"?',
    btn_create_entry: 'Create entry',
    note_ref_create_title: 'Click to create this entry',
    note_no_entries: '(no entries)',
    btn_note_sample: 'Insert sample table',
    note_sample_choice: 'This note already has content: append to the end, or replace everything?',
    notice_sample_exists: 'The sample table is already in this note; no need to insert it again.',
    btn_sample_append: 'Append',
    btn_sample_replace: 'Replace all',
    note_guide_title: 'Start your account table here',
    note_guide_desc: 'Notes mode renders tables and links like a Markdown note. Table cells are shown as literal text, with no inline Markdown or reference parsing. "Insert sample table" writes a four-column example into the editor and does not save automatically; table cells stay plain by default with no automatic masking.',
    notice_notes_mode_hint: 'This is notes mode: maintain an account table like a Markdown note; tables render after saving.',
    notice_note_content_hint: 'This looks like note content; notes mode will render it as a table.',
    notice_cell_copied: 'Copied',
    note_empty: 'This note is empty. Click "Edit note" to start writing Markdown.',
    note_editor_hint: 'Markdown support: headings, lists, bold, inline code, pipe tables and links (http/https only). Table cells are shown and copied as literal text; use \\| for a pipe inside a cell and \\\\ for a backslash; other backslash sequences stay as-is.',
    files_title: 'Files',
    btn_new_file: 'New file',
    files_empty: 'No files yet. Click "New file" to create the first vault.',
    files_loading: 'Opening file and verifying the key…',
    group_ungrouped: 'Ungrouped',
    group_file_count: '{count} files',
    file_mtime: 'Modified {time}',
    new_file_title: 'New vault file',
    new_file_name: 'File name',
    new_file_name_hint: 'You can use "group/name"; .enc is appended automatically and duplicates are rejected.',
    new_file_group: 'Group',
    new_file_group_new: '+ New group…',
    new_file_group_name: 'New group name (may use / for nesting)',
    new_file_plaintext_warn: 'File and group names are visible in plaintext on disk; only contents are encrypted.',
    rename_file_title: 'Rename / move file',
    btn_rename_file: 'Rename',
    btn_delete_file: 'Delete',
    confirm_delete_file: 'Delete file "{name}"? This cannot be undone and its contents will be deleted too.',
    notice_file_created: 'Created file "{name}".',
    notice_file_renamed: 'Renamed file "{name}".',
    notice_file_deleted: 'File deleted.',
    err_file_wrong_password: 'This file is not encrypted with the current master password. The current file was left unchanged.',
    err_file_name_exists: 'A file with that name already exists. Choose another name or group.',
    err_file_name_invalid: 'The file name is empty or has no usable characters after sanitizing.',
    err_group_name_invalid: 'The group name is empty or has no usable characters after sanitizing.',
    err_session_password_lost: 'The session has no master password. Unlock again before opening this file.',
    err_note_missing: 'The note does not exist or has been removed.',
    btn_cancel: 'Cancel',
    btn_save: 'Save',
    btn_confirm_delete: 'Delete',
    search_placeholder: 'Search name, type or tags…',
    empty_entries: 'No entries yet. Click "Add" to create the first one.',
    empty_search: 'No matching entries.',
    content_hidden: 'Content hidden',
    hint_encrypted: 'Plaintext lives only in memory and the UI; the file on disk is AES-256-GCM ciphertext. Locking clears it from memory.',
    hint_locked_state: 'The vault is locked. Keys and plaintext have been cleared from memory.',
    field_name: 'Name',
    field_type: 'Type',
    field_tags: 'Tags',
    field_content: 'Content',
    field_note: 'Note',
    tags_placeholder: 'Comma separated, e.g. work, cloud',
    title_new_entry: 'New entry',
    title_edit_entry: 'Edit entry',
    delete_title: 'Delete entry',
    delete_desc: 'Delete "{name}"? This cannot be undone.',
    type_password: 'Password',
    type_api_key: 'API key',
    type_private_key: 'Private key',
    type_note: 'Note',
    notice_vault_created: 'Vault created.',
    notice_saved: 'Entry saved.',
    notice_unchanged: 'No changes, nothing written.',
    notice_deleted: 'Entry deleted.',
    notice_copied: 'Copied. Clipboard will be cleared in {seconds}s.',
    notice_clipboard_cleared: 'Secret cleared from clipboard.',
    notice_auto_locked: 'Vault auto-locked after inactivity.',
    notice_locked: 'Vault is locked.',
    notice_unlock_first: 'Unlock the vault first.',
    notice_name_required: 'Entry name is required.',
    notice_locked_done: 'Vault locked. Plaintext cleared from memory.',
    err_password_required: 'Please enter the master password.',
    err_password_mismatch: 'The two passwords do not match.',
    err_unlock_failed: 'Wrong master password, or the vault file is corrupted.',
    err_crypto_unavailable: 'WebCrypto (crypto.subtle) is unavailable, so encryption cannot start. Use the desktop app or a WebView with WebCrypto support.',
    err_vault_corrupt: 'The vault file format is invalid. Reading aborted.',
    err_write_verify: 'Write verification failed: content on disk differs from what was written. In-memory data was not updated.',
    err_clipboard_unavailable: 'Clipboard API is unavailable in this environment.',
    err_view_open_failed: 'Could not open the full-page view. Try again or restart Obsidian.',
    err_generic: 'Operation failed: {msg}',
    setting_title: 'XU Secret Vault',
    setting_header_desc: 'Encrypt passwords, API keys and private keys locally; plaintext is never written to notes or plaintext files.',
    setting_group_vault: 'Vault',
    setting_group_security: 'Security',
    setting_group_about: 'About',
    setting_language: 'Language',
    setting_language_desc: 'Switch between Chinese and English.',
    setting_vault_path: 'Legacy vault file path (compat only)',
    setting_vault_path_desc: 'Kept for 0.3.x <vault>/xu-secrets.enc compatibility. If present it is loaded as the default file and is never migrated or deleted; new files are created in the directory below.',
    setting_vault_directory: 'Vault directory',
    setting_vault_directory_desc: 'Relative to the vault root, default xu-secrets. Every .enc under it (including subfolders) appears in the file list. File and group names are visible in plaintext on disk; only contents are encrypted.',
    setting_auto_lock: 'Auto-lock (minutes)',
    setting_auto_lock_desc: 'Lock automatically after this idle period (default 15 minutes). Moving to the background for more than 60 seconds also locks immediately and clears keys and revealed plaintext from memory.',
    setting_bg_lock: 'Blur lock countdown',
    setting_bg_lock_desc: 'When the window loses focus or moves to the background, the page is masked immediately and the vault locks only after the countdown. Returning within the countdown unmask automatically without the master password; default 30 seconds. "Immediate" is the old strict behavior: lock at once and require the master password again.',
    setting_bg_lock_immediate: 'Immediate (strict)',
    setting_bg_lock_seconds: '{n} seconds',
    setting_column_rules: 'Column display rules',
    setting_column_rules_desc: 'Everything is plain by default, with no automatic inference. Only columns you explicitly mark as "Secret" here are masked with ••••••; exact matches win, then a column name containing the rule name, and unmatched columns are plain. Changes re-render the current note immediately.',
    column_rule_name_placeholder: 'Column name, e.g. phone',
    column_rule_mode_plain: 'Plain',
    column_rule_mode_secret: 'Secret',
    btn_add_column_rule: 'Add custom column name',
    btn_restore_default_rules: 'Clear all rules (all plain)',
    confirm_restore_rules: 'Clear all column display rules? Every column will be shown as plain text.',
    notice_rule_name_empty: 'Column name cannot be empty; nothing was saved.',
    notice_rule_limit: 'At most {limit} column display rules; the new one was ignored.',
    notice_rules_restored: 'All rules cleared; every column is plain now.',
    setting_clipboard_clear: 'Clipboard clear (seconds)',
    setting_clipboard_clear_desc: 'Clear the clipboard after copying a secret. If the clipboard has been replaced meanwhile, the new content is left untouched.',
    setting_lock_now: 'Lock now',
    setting_lock_now_desc: 'Clear keys and plaintext from memory. The master password is required to view entries again.',
    setting_version: 'Version',
    setting_docs: 'Documentation',
    setting_docs_desc: 'View the full usage and security guide on GitHub.',
    btn_github: 'GitHub',
    status_loading: 'Reading vault state…',
    btn_retry: 'Retry',
    err_vault_missing: 'Vault file not found. Check the path in settings or restore from a backup. The plugin will not create a new vault automatically, to avoid overwriting an existing file with the same name.',
    err_vault_unreadable: 'The vault file could not be read (permissions or disk error). Check the file and try again.',
    err_vault_too_large: 'The vault file exceeds the 8 MB limit and was not read. Split the entries or use a smaller file.',
    err_vault_exists: 'A vault file already exists at the target path; creation was refused to avoid overwriting it. Back it up or rename it first.',
    err_unlock_backoff: 'Too many attempts. Try again in {seconds}s.',
    err_save_discarded: 'The vault is locked or the write was discarded, so this change was not saved.',
    notice_conflict: 'The vault file was modified externally, so the original was not overwritten. This change was saved as {path}.',
    notice_conflict_saved: 'Copy saved as {path}. The original file was not overwritten; click "Reload" before editing again.',
    conflict_banner: 'External modification detected: this change was saved as {path} and the original was not overwritten. Reload the vault before editing further, so edits do not start from a stale snapshot.',
    btn_reload: 'Reload',
    notice_reloaded: 'Vault reloaded. You can continue editing.',
    notice_upgraded_v1: 'A legacy (v1) vault was read in compatibility mode and upgraded to the v2 format automatically.',
    err_version_unsupported: 'This vault file version is not supported (it may have been created by a newer version of the plugin). Reading was aborted and nothing was modified.',
    err_suspended: 'The vault is suspended because the window lost focus or moved to the background. Re-enter the master password in the panel first.',
    err_conflict_editing_blocked: 'An external modification was detected; the original was not overwritten and this change was saved as a copy. Click "Reload" before editing again.',
    notice_clipboard_unverified: 'The clipboard could not be read. Check manually whether the secret is still there.',
    notice_upgrade_failed: 'Upgrading the legacy v1 format failed; this session continues on the old format. Unlock still succeeded.',
    label_vault_source: 'Vault file to load',
    hint_vault_source: 'Conflict copies were found. Nothing is picked automatically — choose the file you want to unlock.',
    err_rollback_kept: 'Automatic rollback failed; the previous ciphertext backup was kept at {path}.',
    err_rollback_prefix: 'Automatic rollback failed; the previous ciphertext backup was kept at ',
    err_conflict_copy_readonly: 'You are viewing a conflict copy (read-only). Changes are never written back to the official vault; to adopt its contents, back up the official vault first and rename this copy manually.',
    readonly_copy_path: 'Current file: {path}',
    err_save_failed: 'Could not write the vault file. Check file write permissions and try again.',
    notice_background_locked: 'The plugin was in the background for over 60 seconds, so the vault was locked.',
    notice_reverify_failed: 'Verification failed. Enter the master password again.',
    mask_title: 'Content hidden',
    mask_desc: 'The window lost focus or moved to the background, so the panel is masked and revealed plaintext was cleared. Returning within the countdown restores the view without the master password; when the countdown ends the vault locks.',
    mask_countdown: 'Locks in {seconds}s',
    mask_return_hint: 'Returning to the window removes the mask automatically; once the countdown hits zero the master password is required.',
    btn_reverify: 'Verify and continue',
    btn_eye_show: 'Reveal password temporarily',
    btn_eye_hide: 'Hide password',
    notice_sensitive_columns: '{count} column(s) in this table are treated as passwords: cells are masked, clicking copies the real value, and the eye button toggles display.',
    notice_countdown_locked: 'The blur countdown ended, so the vault was locked.',
    err_session_expired: 'The session has expired. Unlock again.',
    err_new_password_short: 'The new master password must be at least 8 characters.',
    err_old_password_wrong: 'The current master password is wrong.',
    err_current_password_wrong: 'The current master password is wrong.',
    err_recovery_questions_count: 'Exactly 3 security questions are required.',
    err_recovery_questions_empty: 'Security questions cannot be empty.',
    err_recovery_answers_required: 'Exactly 3 security answers are required.',
    err_recovery_answer_short: 'Each security answer must be at least 12 characters after normalization.',
    err_recovery_code_invalid: 'The recovery code format is invalid.',
    err_recovery_failed: 'Recovery failed: the recovery code or answers are incorrect. Nothing can be recovered.',
    err_recovery_unavailable: 'This vault has no usable recovery channel.',
    err_recovery_unavailable_hint: 'Without security questions or a recovery code, data cannot be recovered after forgetting the master password.',
    err_batch_busy: 'A batch operation is running ({current}/{total}); file switching and editing are disabled.',
    err_batch_empty: 'There are no vault files to process.',
    err_batch_interrupted: 'The batch was interrupted by lock/suspension; every processed file was rolled back.',
    err_external_change: 'A file changed externally during the batch; the batch was aborted and rolled back.',
    err_legacy_needs_upgrade: 'Some legacy files have not been migrated yet. Unlock them once with the current master password first.',
    notice_upgraded_v2: 'A v2 vault was migrated to the v3 envelope (DEK + KEK). The original file was kept as a .bak backup.',
    notice_password_changed: 'Master password updated.',
    notice_recovery_reset: 'The master password was reset. Be sure to remember it.',
    notice_recovery_saved: 'Security questions saved.',
    security_change_password: 'Change master password',
    security_change_password_desc: 'Changing the password only rewraps the DEK. Quick mode finishes in seconds; full rotation re-encrypts all content.',
    btn_change_password: 'Change master password',
    change_pw_title: 'Change master password',
    change_pw_current: 'Current master password',
    change_pw_new: 'New master password',
    change_pw_confirm: 'Confirm new master password',
    change_pw_mode: 'Mode',
    change_pw_mode_quick: 'Quick (default, seconds; old backups still open with the old password)',
    change_pw_mode_full: 'Full rotation (new DEK and re-encrypt all content; slower; old password still opens old backups but not new files)',
    change_pw_quick_note: 'After quick change, old backups still open with the old password. Use full rotation to invalidate the old password.',
    change_pw_full_note: 'Full rotation generates a new DEK per file and re-encrypts content; old backups can no longer decrypt current content with the old password.',
    change_pw_progress: 'Processing file {current}/{total}…',
    security_recovery_questions: 'Security questions',
    security_recovery_questions_desc: 'Set 3 questions only you can answer; they are a weak recovery channel if you forget the master password.',
    btn_set_recovery: 'Set/modify security questions',
    recovery_title: 'Set security questions',
    recovery_desc: 'Answers need at least 12 characters. They are normalized with NFC, trim, case-insensitive, and whitespace collapsing. Answers are never stored.',
    recovery_question_label: 'Question {index}',
    recovery_answer_label: 'Answer {index}',
    recovery_answer_hint: 'Use a long sentence only you know; fewer than 12 characters is flagged as weak.',
    btn_save_recovery: 'Save security questions',
    btn_skip_recovery: 'Not now',
    confirm_skip_recovery: 'Without security questions, forgetting the master password means the data cannot be recovered. Continue?',
    setup_next: 'Next',
    setup_back: 'Back',
    setup_questions_title: 'Step 2: security questions (optional)',
    setup_questions_desc: 'Choose or write 3 questions. Answers need at least 12 characters; without them, a forgotten master password cannot be recovered.',
    setup_questions_skip_hint: 'You may skip, but you must confirm; you can add them later in settings.',
    setup_code_title: 'Save your recovery code',
    setup_code_desc: 'The recovery code is shown only once and is never written to disk, logs, or data.json. Copy it into a password manager or offline storage.',
    btn_copy_recovery_code: 'Copy recovery code',
    btn_saved_recovery_code: 'I have saved it',
    recovery_code_warning: 'You cannot skip before confirming. Once this window closes, the code is no longer shown.',
    btn_forgot_password: 'Forgot master password?',
    forgot_title: 'Forgot master password',
    forgot_risk: 'Only the recovery code or all 3 security questions can restore access. All 3 answers must be correct; wrong answers cannot be recovered.',
    forgot_choose_code: 'Use recovery code (recommended)',
    forgot_choose_questions: 'Use 3 security questions',
    forgot_code_label: 'Recovery code',
    forgot_code_hint: 'Dashes are optional; case-insensitive.',
    forgot_answer_label: 'Answer {index}',
    btn_recover_now: 'Recover',
    forgot_new_password_title: 'Set a new master password',
    forgot_new_password_desc: 'After recovery you must set a new master password; all files will be rewrapped to it.',
    btn_reset_password: 'Reset master password',
    strength_title: 'Strength and offline crack estimate',
    strength_danger: 'Danger (seconds)',
    strength_general: 'Fair (hours to days)',
    strength_safe: 'Safe (years+)',
    strength_single_gpu: 'Single high-end GPU (~5,000 guesses/s)',
    strength_cluster: 'Multi-GPU / cluster (~1,000,000 guesses/s)',
    strength_note: 'Based on 600,000 PBKDF2-SHA512 iterations, assuming the attacker already has the encrypted file and unlimited offline attempts.',
    strength_boundary_offline: 'This is an offline cracking estimate; if this password has leaked elsewhere or is reused, the attacker does not need to crack it.',
    strength_boundary_params: 'The estimate uses the current algorithm parameters; if those change, the times change.',
    strength_short_numeric_hint: 'A short numeric password (≤6 digits) only keeps people near you out; it cannot stop offline cracking.',
    strength_confirm_title: 'This password is weak',
    strength_confirm_desc: 'Estimated crack time is about {single} on one GPU and {cluster} on a cluster. Use it anyway?',
    security_boundary_title: 'Security boundaries (read this)',
    security_boundary_desc:
      '1) Forgotten master password with no recovery code or security questions: unrecoverable; there is no backdoor. 2) Security questions weaken security to "how hard are your answers to guess"; the recovery code is the strong channel, so store it in a password manager or offline. If you set both, the weakest link decides. 3) Plugin JavaScript is readable and decompilable; security comes from keys, not from hiding code. 4) While unlocked, plaintext exists in memory and on screen; other same-process plugins, clipboard history, crash dumps, screenshots and screen recorders are outside the protection scope.',
    batch_title: 'Batch operation in progress',
    batch_progress: 'Processing file {current}/{total}: {name}',
    question_preset_1: 'What is your favorite book?',
    question_preset_2: 'What was your best friend’s name in primary school?',
    question_preset_3: 'What was the first online nickname you gave yourself?',
    question_custom: 'Custom question…',
    btn_continue: 'Continue',
    btn_choose_placeholder: 'Choose a question…',
  },
};

function getWebCrypto() {
  if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) return globalThis.crypto;
  if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) return window.crypto;
  return null;
}

function utf8Encode(text) {
  return new TextEncoder().encode(String(text));
}

function utf8Decode(buffer) {
  return new TextDecoder('utf-8').decode(buffer);
}

function bytesToBase64(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < arr.length; i += chunk) {
    binary += String.fromCharCode.apply(null, arr.subarray(i, Math.min(i + chunk, arr.length)));
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(String(value || ''));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

function randomBytes(cryptoObj, length) {
  const bytes = new Uint8Array(length);
  cryptoObj.getRandomValues(bytes);
  return bytes;
}

// 信封头参数（含 cipher.algo）参与 AES-GCM 认证，防止篡改迭代数 / salt / 版本 / 算法实现降级攻击
function buildAad(prefix, formatVersion, kdfAlgo, iterations, saltBase64, cipherAlgo) {
  return utf8Encode(
    [prefix, formatVersion, kdfAlgo, String(iterations), saltBase64, cipherAlgo].join('|')
  );
}

// v3 包裹层 AAD：formatVersion | kdf.algo | iterations | salt | cipher.algo + 用途标识
// 用途：password（主密码 KEK）、master（主密钥）、recovery（密保答案）、recovery-code（恢复码）
// recovery 额外绑定三个问题文本的 SHA-256；篡改问题文本会导致解包失败。
function buildWrapAadV3(purpose, formatVersion, kdfAlgo, iterations, saltBase64, cipherAlgo, extra) {
  const parts = [
    AAD_PREFIX_V3,
    purpose,
    String(formatVersion),
    kdfAlgo,
    String(iterations),
    saltBase64,
    cipherAlgo,
  ];
  if (extra) parts.push(extra);
  return utf8Encode(parts.join('|'));
}

// v3 内容层 AAD 只绑定 formatVersion | fileId | cipher.algo。
// 绝不能绑定主密码 salt/iterations，否则改密码/恢复后内容无法解密。
function buildPayloadAadV3(formatVersion, fileIdBase64, cipherAlgo) {
  return utf8Encode(
    [AAD_PREFIX_V3, 'payload', String(formatVersion), fileIdBase64, cipherAlgo].join('|')
  );
}

// 主密钥包裹 DEK 的 AAD 绑定 fileId，避免包裹块在文件之间被移植
function buildMasterDekAad(fileIdBase64, cipherAlgo) {
  return utf8Encode(
    [AAD_PREFIX_V3, 'master-dek', String(FORMAT_VERSION), fileIdBase64, cipherAlgo].join('|')
  );
}

async function importAesGcmKey(cryptoObj, rawKey) {
  return cryptoObj.subtle.importKey(
    'raw',
    rawKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function wrapRawKey(cryptoObj, wrappingKey, rawKey, aad) {
  const iv = randomBytes(cryptoObj, IV_BYTES);
  const ciphertext = await cryptoObj.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad, tagLength: TAG_LENGTH },
    wrappingKey,
    rawKey
  );
  return { iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(ciphertext)) };
}

async function unwrapRawKey(cryptoObj, wrappingKey, blob, aad) {
  const plaintext = await cryptoObj.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: base64ToBytes(blob.iv),
      additionalData: aad,
      tagLength: TAG_LENGTH,
    },
    wrappingKey,
    base64ToBytes(blob.ciphertext)
  );
  return new Uint8Array(plaintext);
}

// 单调时钟：系统时间被回拨/校准时不会让退避与空闲计时提前失效
function monotonicNow() {
  if (typeof performance !== 'undefined' && performance && typeof performance.now === 'function') {
    return performance.now();
  }
  return Date.now();
}

function escapeRegExp(text) {
  return String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// 解析本插件临时文件命名中的本地时间戳（YYYYMMDD + HHMMSS），用于判断残留年龄
function parseFileStamp(datePart, timePart) {
  const year = Number(datePart.slice(0, 4));
  const month = Number(datePart.slice(4, 6));
  const day = Number(datePart.slice(6, 8));
  const hour = Number(timePart.slice(0, 2));
  const minute = Number(timePart.slice(2, 4));
  const second = Number(timePart.slice(4, 6));
  const stamp = new Date(year, month - 1, day, hour, minute, second, 0).getTime();
  return Number.isNaN(stamp) ? 0 : stamp;
}


function delay(ms) {
  return new Promise((resolve) => {
    globalThis.setTimeout(resolve, ms);
  });
}

function errorMessage(error) {
  if (!error) return 'unknown error';
  return String(error.message || error);
}

// 主密码先做 Unicode NFC 归一化，避免同一密码在不同输入法/平台下派生结果不一致
function normalizePassword(value) {
  return String(value == null ? '' : value).normalize('NFC');
}

// 密保答案归一化：NFC + trim + 大小写不敏感 + 折叠连续空白。
// 只用于派生包裹密钥；答案原文永不写盘、永不写日志。
function normalizeSecurityAnswer(value) {
  return String(value == null ? '' : value)
    .normalize('NFC')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ');
}

function normalizeQuestionText(value) {
  return String(value == null ? '' : value)
    .normalize('NFC')
    .trim()
    .replace(/\s+/g, ' ');
}

function joinSecurityAnswers(answers) {
  return (Array.isArray(answers) ? answers : []).map(normalizeSecurityAnswer).join('\n');
}

// 128 位恢复码 → RFC 4648 Base32（26 字符）+ 30 位 CRC 校验（6 字符）
// 展示为 32 字符 / 每 4 字符一组（8 组），校验位只用于输入纠错，不参与密钥派生
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function recoveryCodeCrc(text) {
  let crc = 0xffffffff;
  for (let index = 0; index < text.length; index += 1) {
    crc ^= text.charCodeAt(index);
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function recoveryCodeChecksum(text) {
  const value = recoveryCodeCrc(text) & 0x3fffffff;
  let out = '';
  for (let shift = 25; shift >= 0; shift -= 5) out += BASE32_ALPHABET[(value >>> shift) & 31];
  return out;
}

function formatRecoveryCode(code) {
  const secret = String(code || '').toUpperCase();
  const text = secret + recoveryCodeChecksum(secret);
  const groups = [];
  for (let index = 0; index < text.length; index += 4) groups.push(text.slice(index, index + 4));
  return groups.join('-');
}

function normalizeRecoveryCode(value) {
  const text = String(value == null ? '' : value)
    .normalize('NFC')
    .toUpperCase()
    .replace(/[^A-Z2-7]/g, '');
  if (text.length === 32) {
    if (recoveryCodeChecksum(text.slice(0, 26)) !== text.slice(26)) return '';
    return text.slice(0, 26);
  }
  if (text.length === 26) return text;
  return text;
}

// 强度估算内置词表：常见英文密码 / 键盘口令 / 常见中文拼音口令
const COMMON_PASSWORD_WORDS = [
  'password', 'passwd', 'pass', 'admin', 'administrator', 'root', 'guest', 'login',
  'qwerty', 'qwertyuiop', 'asdfgh', 'asdf', 'zxcvbn', 'abc123', '123456', '12345678',
  'iloveyou', 'letmein', 'welcome', 'secret', 'master', 'hello', 'monkey', 'dragon',
  'football', 'sunshine', 'princess', 'flower', 'shadow', 'superman', 'batman',
  'woaini', 'woshishui', 'zhanghao', 'mima', 'mima123', 'qq123456', '5201314',
  'woaini1314', 'aaa123', 'abc123456', '1q2w3e4r', '1qaz2wsx', 'qazwsx',
  'p@ssw0rd', 'password1', 'password123', 'password123!', 'admin123', 'admin123!',
  'qwerty123', 'iloveyou1', 'letmein1', 'welcome1', 'abc123!', '000000', '111111',
  '666666', '888888', 'correct', 'horse', 'battery', 'staple', 'apple', 'orange',
  'banana', 'summer', 'winter', 'spring', 'autumn', 'coffee', 'chocolate', 'computer',
  'internet', 'security', 'system', 'manager', 'office', 'school', 'college',
  'family', 'mother', 'father', 'brother', 'sister', 'friend', 'love', 'happy',
  'money', 'gold', 'silver', 'star', 'moon', 'sun', 'rain', 'snow', 'wind',
  'water', 'fire', 'earth', 'light', 'dark', 'blue', 'green', 'black', 'white',
  'red', 'yellow', 'purple', 'orange', 'purple', 'silence', 'freedom', 'truth',
  'power', 'future', 'dream', 'hope', 'peace', 'trust', 'strong', 'simple',
  'quick', 'brown', 'lazy', 'jumps', 'over', 'the', 'and', 'for', 'with',
];
const COMMON_PASSWORD_SET = new Set(COMMON_PASSWORD_WORDS.map((word) => word.toLowerCase()));
const COMMON_PASSWORD_EXACT = new Set([
  'password', 'password1', 'password123', 'password123!', 'p@ssw0rd', 'admin',
  'admin123', 'admin123!', 'qwerty', 'qwerty123', 'abc123', 'abc123!', '123456',
  '12345678', '123456789', 'iloveyou', 'iloveyou1', 'letmein', 'letmein1', 'welcome',
  'welcome1', '000000', '111111', '666666', '888888', '1q2w3e4r', '1qaz2wsx',
  'qazwsx', 'woaini', 'woaini1314', '5201314', 'mima123', 'qq123456',
]);

const KEYBOARD_SEQUENCES = [
  'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890', 'abcdefghijklmnopqrstuvwxyz',
];

function passwordCharsetSize(password) {
  let size = 0;
  if (/[a-z]/.test(password)) size += 26;
  if (/[A-Z]/.test(password)) size += 26;
  if (/[0-9]/.test(password)) size += 10;
  if (/[^A-Za-z0-9]/.test(password)) size += 33;
  if (/[^\x00-\x7F]/.test(password)) size += 100;
  return Math.max(size, 1);
}

function sequenceMask(password) {
  const lower = password.toLowerCase();
  const mask = new Array(lower.length).fill(false);
  for (const row of KEYBOARD_SEQUENCES) {
    for (const sequence of [row, row.split('').reverse().join('')]) {
      for (let start = 0; start < lower.length; start += 1) {
        let length = 0;
        while (
          start + length < lower.length &&
          sequence.indexOf(lower[start + length]) >= 0 &&
          (length === 0 || sequence.indexOf(lower[start + length]) === sequence.indexOf(lower[start + length - 1]) + 1)
        ) {
          length += 1;
        }
        if (length >= 3) {
          for (let index = start; index < start + length; index += 1) mask[index] = true;
        }
      }
    }
  }
  // 重复字符（aaaa / 1111）同样视为可预测模式
  const repeatRe = /(.)\1{2,}/g;
  let match;
  while ((match = repeatRe.exec(password))) {
    for (let index = match.index; index < match.index + match[0].length; index += 1) mask[index] = true;
  }
  return mask;
}

function passwordBitsToSeconds(bits, rate) {
  const guesses = Math.min(Math.pow(2, Math.max(0, bits)), 2 ** 200);
  return guesses / rate;
}

// 纯本地估算：不记录、不打印、不持久化密码；不做任何网络调用。
// 返回 { tier, bits, guesses, secondsSingle, secondsCluster, reasons }
function estimatePasswordStrength(password) {
  const raw = String(password == null ? '' : password);
  const reasons = [];
  const length = raw.length;
  if (!length) {
    return { tier: 'danger', bits: 0, guesses: 0, secondsSingle: 0, secondsCluster: 0, reasons: ['empty'] };
  }
  const lower = raw.toLowerCase();
  const charset = passwordCharsetSize(raw);
  let bits = Math.min(200, length * Math.log2(charset));
  let guesses = Math.pow(2, bits);
  let forcedDanger = false;
  let exactCommon = false;

  if (COMMON_PASSWORD_EXACT.has(lower)) {
    forcedDanger = true;
    exactCommon = true;
    guesses = Math.min(guesses, COMMON_PASSWORD_WORDS.indexOf(lower) + 2);
    reasons.push('common-password');
  }

  // 纯数字短密码：搜索空间本来就小；即使长度到 8 位也按危险处理
  if (/^[0-9]+$/.test(raw) && length <= 8) {
    forcedDanger = true;
    guesses = Math.min(guesses, Math.pow(10, length));
    reasons.push('short-numeric');
  }

  // 纯日期（YYYYMMDD / YYYY-MM-DD / YYYY/MM/DD）
  if (/^(19|20)[0-9]{2}[-/. ]?(0[1-9]|1[0-2])[-/. ]?(0[1-9]|[12][0-9]|3[01])$/.test(raw)) {
    forcedDanger = true;
    guesses = Math.min(guesses, 366 * 200);
    reasons.push('date');
  }

  // 手机号形态：11 位、以 1 开头、第二位 3-9
  if (/^1[3-9][0-9]{9}$/.test(raw)) {
    guesses = Math.min(guesses, 1.3 * Math.pow(10, 10));
    reasons.push('phone-number');
  }

  const tokens = lower.match(/[a-z]+/g) || [];
  const allDictionaryWords = tokens.length >= 2 && tokens.every((token) => COMMON_PASSWORD_SET.has(token));
  if (allDictionaryWords && tokens.join('').length >= 12) {
    // 口令式（correct horse battery staple）：按 7776 词的口令空间估算
    guesses = Math.min(guesses, Math.pow(7776, tokens.length));
    reasons.push('passphrase');
  } else if (tokens.length === 1 && COMMON_PASSWORD_SET.has(tokens[0]) && tokens[0].length >= 3) {
    const suffixLength = Math.max(0, length - tokens[0].length);
    const caseVariation = /[A-Z]/.test(raw) ? 2 : 1;
    const dictGuesses = 7776 * caseVariation * Math.pow(charset, suffixLength);
    guesses = Math.min(guesses, dictGuesses);
    reasons.push('dictionary-word');
  }

  const mask = sequenceMask(raw);
  const covered = mask.filter(Boolean).length;
  if (covered >= 4 && covered >= Math.ceil(length * 0.6)) {
    guesses = Math.min(guesses, Math.pow(10, Math.max(2, length - covered + 2)));
    reasons.push('sequence');
  }

  const effectiveBits = Math.min(200, Math.log2(Math.max(1, guesses)));
  const secondsSingle = Math.max(0, guesses / 5000);
  const secondsCluster = Math.max(0, guesses / 1000000);
  let tier = 'safe';
  if (forcedDanger || exactCommon || secondsSingle < 3600) tier = 'danger';
  else if (secondsSingle < 31557600) tier = 'general';
  return {
    tier,
    bits: effectiveBits,
    guesses,
    secondsSingle,
    secondsCluster,
    reasons,
  };
}

function formatDuration(seconds, lang) {
  const en = lang === 'en';
  if (!Number.isFinite(seconds) || seconds > 1e18) return en ? 'astronomical' : '天文数字';
  if (seconds < 1) return en ? 'instantly' : '瞬间';
  if (seconds < 10) return (Math.round(seconds * 10) / 10) + (en ? ' seconds' : ' 秒');
  if (seconds < 60) return Math.round(seconds) + (en ? ' seconds' : ' 秒');
  if (seconds < 3600) return Math.round(seconds / 60) + (en ? ' minutes' : ' 分钟');
  if (seconds < 86400) return Math.round(seconds / 3600) + (en ? ' hours' : ' 小时');
  if (seconds < 31557600) return Math.round(seconds / 86400) + (en ? ' days' : ' 天');
  if (seconds < 31557600 * 10000) return Math.round(seconds / 31557600) + (en ? ' years' : ' 年');
  return Math.round(seconds / 31557600 / 10000) + (en ? ' ×10k years' : ' 万年');
}

// 创建与修改密码共用的强度组件：200ms 防抖，纯本地，不渲染密码值本身
function attachStrengthMeter(container, plugin, input) {
  const t = (key, params) => plugin.t(key, params);
  const wrap = container.createDiv({ cls: 'xsv-strength' });
  wrap.createDiv({ cls: 'xsv-strength-title', text: t('strength_title') });
  const head = wrap.createDiv({ cls: 'xsv-strength-head' });
  const tierEl = head.createDiv({ cls: 'xsv-strength-tier' });
  const bar = wrap.createDiv({ cls: 'xsv-strength-bar' });
  const fill = bar.createDiv({ cls: 'xsv-strength-fill' });
  const grid = wrap.createDiv({ cls: 'xsv-strength-grid' });
  const singleLabel = grid.createDiv({ cls: 'xsv-strength-cell' });
  singleLabel.createDiv({ cls: 'xsv-strength-label', text: t('strength_single_gpu') });
  const singleValue = singleLabel.createDiv({ cls: 'xsv-strength-value' });
  const clusterLabel = grid.createDiv({ cls: 'xsv-strength-cell' });
  clusterLabel.createDiv({ cls: 'xsv-strength-label', text: t('strength_cluster') });
  const clusterValue = clusterLabel.createDiv({ cls: 'xsv-strength-value' });
  const shortHint = wrap.createDiv({ cls: 'xsv-hint xsv-strength-short-hint' });
  const note = wrap.createDiv({ cls: 'xsv-hint', text: t('strength_note') });
  wrap.createDiv({ cls: 'xsv-hint', text: t('strength_boundary_offline') });
  wrap.createDiv({ cls: 'xsv-hint', text: t('strength_boundary_params') });
  let timer = null;
  let result = plugin.evaluatePasswordStrength('');
  const update = () => {
    result = plugin.evaluatePasswordStrength(String(input.value || ''));
    tierEl.className = 'xsv-strength-tier xsv-strength-' + result.tier;
    tierEl.setText(result.tierLabel);
    fill.className = 'xsv-strength-fill xsv-strength-' + result.tier;
    singleValue.setText(result.singleText);
    clusterValue.setText(result.clusterText);
    const shortNumeric = /^[0-9]{1,6}$/.test(String(input.value || ''));
    shortHint.setText(shortNumeric ? t('strength_short_numeric_hint') : '');
    shortHint.className = 'xsv-hint xsv-strength-short-hint' + (shortNumeric ? '' : ' xsv-hidden');
  };
  const schedule = () => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(update, 200);
  };
  input.addEventListener('input', schedule);
  input.addEventListener('change', update);
  update();
  return {
    update,
    schedule,
    get result() {
      return result;
    },
  };
}

function sameJson(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

// 列显示规则归一化：只保留 { name, mode }，去空、去重、限长、限行数
function normalizeRuleName(value) {
  return String(value == null ? '' : value).trim().slice(0, COLUMN_RULE_NAME_MAX);
}

function cloneDefaultColumnRules() {
  return DEFAULT_COLUMN_RULES.map((rule) => ({ name: rule.name, mode: rule.mode }));
}

function normalizeColumnRules(value) {
  if (!Array.isArray(value)) return cloneDefaultColumnRules();
  const names = new Set();
  const rules = [];
  for (const item of value) {
    // 兼容旧格式：字符串条目视为密文规则
    const legacy = typeof item === 'string';
    if (!legacy && (!item || typeof item !== 'object')) continue;
    const name = normalizeRuleName(legacy ? item : item.name);
    if (!name) continue;
    const key = name.toLowerCase();
    const rawMode = legacy ? 'secret' : item.mode;
    const mode = COLUMN_RULE_MODES.indexOf(rawMode) >= 0 ? rawMode : 'plain';
    if (names.has(key)) {
      // 重复列名合并为一条：后出现的模式覆盖先前的
      const existing = rules.filter((rule) => rule.name.toLowerCase() === key)[0];
      if (existing) existing.mode = mode;
      continue;
    }
    names.add(key);
    rules.push({ name, mode });
    if (rules.length >= COLUMN_RULE_LIMIT) break;
  }
  // 非空数组全是脏数据时回到默认（空表）；显式清空数组同样得到空表（全部按明文）
  if (value.length > 0 && !rules.length) return cloneDefaultColumnRules();
  return rules;
}

function normalizeBackgroundSeconds(value) {
  const seconds = Number(value);
  return BACKGROUND_LOCK_CHOICES.indexOf(seconds) >= 0 ? seconds : DEFAULT_BACKGROUND_LOCK_SECONDS;
}

// 文件系统路径归一化：去掉空段与 . / ..，统一正斜杠
function normalizeRelativePath(rawValue) {
  return String(rawValue == null ? '' : rawValue)
    .replace(/\\/g, '/')
    .split('/')
    .filter((part) => part && part !== '.' && part !== '..')
    .join('/');
}

function normalizeVaultDir(rawValue) {
  const dir = normalizeRelativePath(rawValue);
  return dir || DEFAULT_VAULT_DIR;
}

function normalizeCollapsedGroups(value) {
  if (!Array.isArray(value)) return [];
  const seen = new Set();
  const out = [];
  for (const item of value) {
    const group = normalizeRelativePath(item).slice(0, GROUP_NAME_MAX);
    if (!group || seen.has(group)) continue;
    seen.add(group);
    out.push(group);
    if (out.length >= 200) break;
  }
  return out;
}

// 文件/分组名清洗：禁止路径分隔与系统保留字符，去掉首尾空白和结尾的点
function sanitizePathSegment(value, maxLength) {
  let text = String(value == null ? '' : value).normalize('NFC');
  text = text.replace(/[\u0000-\u001f\u007f]/g, '');
  text = text.replace(/[\\/:*?"<>|]/g, '-');
  text = text.replace(/\s+/g, ' ').trim();
  text = text.replace(/\.+$/g, '');
  return text.slice(0, maxLength || FILE_NAME_MAX);
}

// 输入 "组/名字" 或 名称 + 分组：最后一段是文件名，前面都是分组；返回 null 表示非法
function parseVaultFileInput(rawName, rawGroup) {
  const nameText = String(rawName == null ? '' : rawName).trim();
  const groupText = String(rawGroup == null ? '' : rawGroup).trim();
  const combined = groupText ? groupText + '/' + nameText : nameText;
  const parts = combined.split('/').filter((part) => part && part.trim());
  if (!parts.length) return null;
  const fileName = sanitizePathSegment(parts.pop().replace(/\.enc$/i, ''), FILE_NAME_MAX);
  if (!fileName) return null;
  const groupParts = [];
  for (const part of parts) {
    const clean = sanitizePathSegment(part, GROUP_NAME_MAX);
    if (!clean) return null;
    groupParts.push(clean);
  }
  return { name: fileName, group: groupParts.join('/') };
}

function fileMtimeText(mtime) {
  const stamp = Number(mtime);
  if (!stamp) return '';
  const date = new Date(stamp);
  if (Number.isNaN(date.getTime())) return '';
  const pad = (value) => String(value).padStart(2, '0');
  return (
    date.getFullYear() +
    '-' +
    pad(date.getMonth() + 1) +
    '-' +
    pad(date.getDate()) +
    ' ' +
    pad(date.getHours()) +
    ':' +
    pad(date.getMinutes())
  );
}

// 单元格解转义：只还原 \| 与 \\，其它反斜杠序列保持原样
function unescapeCellText(text) {
  const source = String(text == null ? '' : text);
  let out = '';
  let index = 0;
  while (index < source.length) {
    const char = source[index];
    if (char === '\\' && index + 1 < source.length) {
      const next = source[index + 1];
      if (next === '|' || next === '\\') {
        out += next;
        index += 2;
        continue;
      }
    }
    out += char;
    index += 1;
  }
  return out;
}

function fileStamp(date) {
  const pad = (value) => String(value).padStart(2, '0');
  return (
    date.getFullYear() +
    pad(date.getMonth() + 1) +
    pad(date.getDate()) +
    '-' +
    pad(date.getHours()) +
    pad(date.getMinutes()) +
    pad(date.getSeconds())
  );
}

function sanitizeTags(input) {
  let raw = [];
  if (Array.isArray(input)) raw = input;
  else if (typeof input === 'string') raw = input.split(/[,，、]/);
  const seen = new Set();
  const out = [];
  for (const item of raw) {
    const tag = String(item == null ? '' : item).trim();
    if (!tag) continue;
    const key = tag.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(tag);
  }
  return out;
}

function normalizeEntryInput(input) {
  const source = input || {};
  return {
    name: String(source.name == null ? '' : source.name).trim(),
    type: ENTRY_TYPES.indexOf(source.type) >= 0 ? source.type : 'note',
    tags: sanitizeTags(source.tags),
    content: String(source.content == null ? '' : source.content),
    note: String(source.note == null ? '' : source.note),
  };
}

function normalizeStoredEntry(raw, fallbackId) {
  if (!raw || typeof raw !== 'object') throw new Error('invalid entry');
  const base = normalizeEntryInput(raw);
  return {
    ...raw,
    id: String(raw.id || fallbackId),
    name: base.name,
    type: base.type,
    tags: base.tags,
    content: base.content,
    note: base.note,
    createdAt: String(raw.createdAt || ''),
    updatedAt: String(raw.updatedAt || ''),
  };
}

function createDefaultNote() {
  return { id: DEFAULT_NOTE_ID, title: '我的密钥', body: '', updatedAt: new Date().toISOString() };
}

function normalizeStoredNote(raw, fallbackId) {
  if (!raw || typeof raw !== 'object') throw new Error('invalid note');
  return {
    id: String(raw.id || fallbackId),
    title: String(raw.title == null ? '' : raw.title).trim() || '未命名笔记',
    body: String(raw.body == null ? '' : raw.body),
    updatedAt: String(raw.updatedAt || ''),
  };
}

// 兼容旧载荷（只有 entries 数组）与 0.2.0 起的 { contentVersion, entries, notes }
function decodePayload(data) {
  if (Array.isArray(data)) {
    return { contentVersion: 1, entries: data, notes: [] };
  }
  if (data && typeof data === 'object' && Array.isArray(data.entries)) {
    return {
      contentVersion: Number(data.contentVersion) || 1,
      entries: data.entries,
      notes: Array.isArray(data.notes) ? data.notes : [],
    };
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* 设置页（1.13 声明式 Path A：仅 getSettingDefinitions，无 display）      */
/* ------------------------------------------------------------------ */
class SecretVaultSettingTab extends PluginSettingTab {
  getSettingDefinitions() {
    const plugin = this.plugin;
    // 必须转发 vars，否则 {n} / {seconds} 等占位符会原样显示
    const t = (key, vars) => plugin.t(key, vars);
    return [
      {
        name: t('setting_title'),
        desc: t('setting_header_desc'),
        searchable: false,
      },
      {
        name: t('setting_language'),
        desc: t('setting_language_desc'),
        render: (setting) => {
          setting.addDropdown((dropdown) => {
            dropdown
              .addOption('zh', '中文')
              .addOption('en', 'English')
              .setValue(plugin.settings.language)
              .onChange(async (value) => {
                plugin.settings.language = value === 'en' ? 'en' : 'zh';
                await plugin.saveSettings();
                plugin.refreshViews();
                if (typeof this.update === 'function') this.update();
              });
          });
        },
      },
      {
        type: 'group',
        heading: t('setting_group_vault'),
        items: [
          {
            name: t('setting_vault_directory'),
            desc: t('setting_vault_directory_desc'),
            control: { type: 'text', key: 'vaultDir' },
          },
          {
            name: t('setting_vault_path'),
            desc: t('setting_vault_path_desc'),
            control: { type: 'text', key: 'vaultPath' },
          },
        ],
      },
      {
        type: 'group',
        heading: t('setting_group_security'),
        items: [
          {
            name: t('setting_auto_lock'),
            desc: t('setting_auto_lock_desc'),
            control: { type: 'slider', key: 'autoLockMinutes', min: 1, max: 60, step: 1 },
          },
          {
            name: t('setting_bg_lock'),
            desc: t('setting_bg_lock_desc'),
            render: (setting) => {
              setting.addDropdown((dropdown) => {
                for (const seconds of BACKGROUND_LOCK_CHOICES) {
                  dropdown.addOption(
                    String(seconds),
                    seconds === 0
                      ? t('setting_bg_lock_immediate')
                      : t('setting_bg_lock_seconds', { n: seconds })
                  );
                }
                dropdown.setValue(String(normalizeBackgroundSeconds(plugin.settings.backgroundLockSeconds)));
                dropdown.onChange(async (value) => {
                  plugin.settings.backgroundLockSeconds = normalizeBackgroundSeconds(value);
                  await plugin.saveSettings();
                });
              });
            },
          },
          {
            name: t('setting_column_rules'),
            desc: t('setting_column_rules_desc'),
            render: (setting) => {
              this.renderColumnRulesEditor(setting);
            },
          },
          {
            name: t('setting_clipboard_clear'),
            desc: t('setting_clipboard_clear_desc'),
            control: { type: 'slider', key: 'clipboardClearSeconds', min: 5, max: 120, step: 5 },
          },
          {
            name: t('security_change_password'),
            desc: t('security_change_password_desc'),
            render: (setting) => {
              setting.addButton((button) => {
                button.setButtonText(t('btn_change_password')).onClick(() => {
                  if (!plugin.isUnlocked()) {
                    new Notice(t('notice_unlock_first'), 3000);
                    return;
                  }
                  new ChangePasswordModal(plugin.app, plugin).open();
                });
              });
            },
          },
          {
            name: t('security_recovery_questions'),
            desc: t('security_recovery_questions_desc'),
            render: (setting) => {
              setting.addButton((button) => {
                button.setButtonText(t('btn_set_recovery')).onClick(() => {
                  if (!plugin.isUnlocked()) {
                    new Notice(t('notice_unlock_first'), 3000);
                    return;
                  }
                  new RecoveryQuestionsModal(plugin.app, plugin).open();
                });
              });
            },
          },
          {
            name: t('security_boundary_title'),
            desc: t('security_boundary_desc'),
          },
          {
            name: t('setting_lock_now'),
            desc: t('setting_lock_now_desc'),
            render: (setting) => {
              setting.addButton((button) => {
                button.setButtonText(t('btn_lock')).onClick(() => {
                  plugin.lock();
                  if (plugin.isUnlocked() === false) new Notice(t('notice_locked_done'), 3000);
                });
              });
            },
          },
        ],
      },
      {
        type: 'group',
        heading: t('setting_group_about'),
        items: [
          {
            name: t('setting_version'),
            desc: plugin.manifest.version,
            searchable: false,
          },
          {
            name: t('setting_docs'),
            desc: t('setting_docs_desc'),
            render: (setting) => {
              setting.addButton((button) => {
                button.setButtonText(t('btn_github')).onClick(() => {
                  if (typeof window !== 'undefined' && typeof window.open === 'function') {
                    window.open(REPO_URL, '_blank');
                  }
                });
              });
            },
          },
        ],
      },
    ];
  }

  // 动态增删行只在本地容器内重绘，避免声明式设置整页重排抖动；
  // rulesBusy 做重入保护，保存期间忽略重复点击
  renderColumnRulesEditor(setting) {
    const plugin = this.plugin;
    const t = (key, vars) => plugin.t(key, vars);
    const host = setting.settingEl || setting.controlEl;
    if (!host || typeof host.createDiv !== 'function') return;
    const container = host.createDiv({ cls: 'xsv-rule-editor' });
    let draft = null;

    const refresh = () => {
      container.empty();
      const rules = plugin.getColumnRules();
      const rows = rules.map((rule, index) => ({ rule, index }));
      if (draft) rows.push({ rule: draft, index: -1, draft: true });

      for (const row of rows) {
        const rowEl = container.createDiv({ cls: 'xsv-rule-row' });
        const input = rowEl.createEl('input', { cls: 'xsv-rule-name' });
        input.setAttribute('type', 'text');
        input.setAttribute('maxlength', String(COLUMN_RULE_NAME_MAX));
        input.setAttribute('placeholder', t('column_rule_name_placeholder'));
        input.value = row.rule.name;
        input.addEventListener('change', () => {
          if (this.rulesBusy) return;
          const value = String(input.value == null ? '' : input.value).trim();
          if (row.draft) {
            if (!value) {
              new Notice(t('notice_rule_name_empty'), 3000);
              draft = null;
              refresh();
              return;
            }
            this.rulesBusy = true;
            void plugin
              .addColumnRule(value, row.rule.mode)
              .then((result) => {
                this.rulesBusy = false;
                if (result.ok) draft = null;
                refresh();
              });
            return;
          }
          this.rulesBusy = true;
          void plugin
            .updateColumnRule(row.index, { name: value })
            .then((result) => {
              this.rulesBusy = false;
              if (!result.ok) input.value = row.rule.name;
              refresh();
            });
        });

        // 模式控件用下拉框：当前值直接显示在框内，不再依赖分段按钮的选中态高亮
        const modeSelect = rowEl.createEl('select', { cls: 'dropdown xsv-rule-select' });
        for (const mode of COLUMN_RULE_MODES) {
          const option = modeSelect.createEl('option', {
            text: t(mode === 'secret' ? 'column_rule_mode_secret' : 'column_rule_mode_plain'),
          });
          option.value = mode;
        }
        modeSelect.value = row.rule.mode;
        modeSelect.addEventListener('change', () => {
          if (this.rulesBusy) return;
          const mode = COLUMN_RULE_MODES.indexOf(modeSelect.value) >= 0 ? modeSelect.value : 'plain';
          if (row.draft) {
            draft.mode = mode;
            return;
          }
          if (row.rule.mode === mode) return;
          this.rulesBusy = true;
          void plugin
            .updateColumnRule(row.index, { mode })
            .then(() => {
              this.rulesBusy = false;
              refresh();
            });
        });

        const remove = rowEl.createEl('button', { cls: 'xsv-rule-remove', text: '×' });
        remove.setAttribute('type', 'button');
        remove.setAttribute('title', t('btn_delete'));
        remove.addEventListener('click', () => {
          if (this.rulesBusy) return;
          if (row.draft) {
            draft = null;
            refresh();
            return;
          }
          this.rulesBusy = true;
          void plugin
            .deleteColumnRule(row.index)
            .then(() => {
              this.rulesBusy = false;
              refresh();
            });
        });

        if (row.draft) {
          // 新增空行并聚焦，未输入名称前不落盘
          if (typeof input.focus === 'function') input.focus();
        }
      }

      const actions = container.createDiv({ cls: 'xsv-rule-actions' });
      const addButton = actions.createEl('button', { cls: 'xsv-btn xsv-btn-small', text: t('btn_add_column_rule') });
      addButton.setAttribute('type', 'button');
      addButton.addEventListener('click', () => {
        if (this.rulesBusy || draft) return;
        if (plugin.getColumnRules().length >= COLUMN_RULE_LIMIT) {
          new Notice(t('notice_rule_limit', { limit: COLUMN_RULE_LIMIT }), 4000);
          return;
        }
        draft = { name: '', mode: 'plain' };
        refresh();
      });
      const restoreButton = actions.createEl('button', {
        cls: 'xsv-btn xsv-btn-small',
        text: t('btn_restore_default_rules'),
      });
      restoreButton.setAttribute('type', 'button');
      restoreButton.addEventListener('click', () => {
        plugin.requestRestoreDefaultColumnRules(() => {
          draft = null;
          refresh();
        });
      });
    };

    this.rulesBusy = false;
    refresh();
  }

  async setControlValue(key, value) {
    if (typeof super.setControlValue === 'function') await super.setControlValue(key, value);
    else {
      this.plugin.settings[key] = value;
      await this.plugin.saveSettings();
    }
    if (key === 'autoLockMinutes') this.plugin.resetIdleTimer();
    if (key === 'vaultPath') {
      this.plugin.vaultState = 'unknown';
      this.plugin.refreshViews();
    }
    if (key === 'vaultDir') {
      this.plugin.settings.vaultDir = normalizeVaultDir(this.plugin.settings.vaultDir);
      await this.plugin.scanVaultFiles();
      this.plugin.vaultState = this.plugin.vaultFiles.length ? 'present' : 'absent';
      this.plugin.refreshViews();
    }
  }
}

/* ------------------------------------------------------------------ */
/* 整页视图                                                            */
/* ------------------------------------------------------------------ */
class SecretVaultView extends ItemView {
  constructor(leaf, plugin) {
    super(leaf);
    this.plugin = plugin;
    this.uiError = '';
    this.detecting = false;
    this.masked = false;
    this.noteId = '';
    this.noteEditing = false;
    this.noteDraft = null;
    this.revealedCells = new Set();
    this.maskCountdownEl = null;
    this.setupStep = 'password';
    this.setupPassword = '';
    this.setupQuestions = ['', '', ''];
    this.setupAnswers = ['', '', ''];
    this.setupRecoveryCode = '';
    this.setupBusy = false;
  }

  getViewType() {
    return VIEW_TYPE;
  }

  getDisplayText() {
    return this.plugin.t('view_title');
  }

  getIcon() {
    return 'lock';
  }

  async onOpen() {
    this.registerDomEvent(this.containerEl, 'click', () => this.plugin.touchActivity());
    this.registerDomEvent(this.containerEl, 'keydown', () => this.plugin.touchActivity());
    this.registerDomEvent(this.containerEl, 'input', () => this.plugin.touchActivity());
    // 已有解锁态面板时，新的面板一律以挂起态打开，必须重新验证，避免多面板共享会话
    const additionalPanel = this.plugin.isUnlocked() && this.plugin.openViews.size > 0;
    this.plugin.openViews.add(this);
    if (additionalPanel) {
      this.masked = true;
      // 多面板挂起不走倒计时，必须重新验证主密码
      this.plugin.suspendForBackground('panel');
    }
    this.render();
    void this.ensureVaultState();
  }

  // 关闭面板即清屏并锁定，避免"关了但视图仍缓存明文"
  async onClose() {
    this.plugin.openViews.delete(this);
    this.clearSensitive();
    this.masked = false;
    this.plugin.lock();
  }

  // 锁定时同步清屏：立即移除已显形的明文，而不是只丢缓存
  clearSensitive() {
    this.uiError = '';
    this.masked = false;
    // 笔记编辑草稿与渲染区一并丢弃，避免锁屏后仍能从视图或闭包里拿到明文
    this.noteEditing = false;
    this.noteDraft = null;
    this.revealedCells.clear();
    this.maskCountdownEl = null;
    this.setupStep = 'password';
    this.setupPassword = '';
    this.setupQuestions = ['', '', ''];
    this.setupAnswers = ['', '', ''];
    this.setupRecoveryCode = '';
    this.setupBusy = false;
    if (this.contentEl) this.contentEl.empty();
  }

  // 切后台/失焦：立刻加遮罩并清屏；是否需重新验证由插件按倒计时决定
  maskSensitive() {
    if (!this.plugin.isUnlocked()) return;
    this.masked = true;
    // 挂起时同样丢弃笔记草稿，避免遮罩后仍残留明文副本
    this.noteEditing = false;
    this.noteDraft = null;
    // 已临时显形的密文列立即回到掩码态，不把明文留在 DOM 或集合里
    this.revealedCells.clear();
    this.maskCountdownEl = null;
    if (this.contentEl) this.contentEl.empty();
    this.render();
  }

  // 倒计时内回到前台：直接恢复可读，不重验主密码
  resumeSensitive() {
    this.masked = false;
    this.revealedCells.clear();
    this.maskCountdownEl = null;
    this.render();
  }

  updateMaskCountdown(seconds) {
    if (!this.maskCountdownEl) return;
    this.maskCountdownEl.setText(this.plugin.t('mask_countdown', { seconds }));
  }

  async ensureVaultState() {
    if (this.plugin.vaultState !== 'unknown' || this.detecting) return;
    this.detecting = true;
    try {
      await this.plugin.detectVaultExists();
    } finally {
      this.detecting = false;
      this.render();
    }
  }

  createPasswordField(parent, labelText, onSubmit) {
    const wrap = parent.createDiv({ cls: 'xsv-field' });
    wrap.createDiv({ cls: 'xsv-label', text: labelText });
    const input = wrap.createEl('input', { cls: 'xsv-input', attr: { type: 'password' } });
    input.type = 'password';
    input.autocomplete = 'off';
    input.spellcheck = false;
    input.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        onSubmit();
      }
    });
    return input;
  }

  renderError(parent) {
    if (!this.uiError) return;
    parent.createDiv({ cls: 'xsv-error', text: this.uiError });
  }

  render() {
    if (!this.contentEl) return;
    const el = this.contentEl;
    el.empty();
    if (!this.plugin.isUnlocked()) {
      this.masked = false;
    }

    const root = el.createDiv({ cls: 'xsv-view xsv-page' });
    if (!this.plugin.cryptoApi) {
      root.createDiv({ cls: 'xsv-title', text: this.plugin.t('view_title') });
      root.createDiv({ cls: 'xsv-error', text: this.plugin.t('err_crypto_unavailable') });
      return;
    }

    // 创建后的恢复码一次性展示步骤优先于解锁态（未点「我已保存」不得进入主界面）
    if (this.setupStep === 'recoveryCode') {
      this.renderSetup(root);
      return;
    }

    if (this.plugin.isUnlocked()) {
      if (this.masked) {
        this.renderMask(root);
        return;
      }
      this.renderUnlocked(root);
      return;
    }

    const state = this.plugin.vaultState;
    if (state === 'unknown') {
      root.createDiv({ cls: 'xsv-title', text: this.plugin.t('view_title') });
      root.createDiv({ cls: 'xsv-desc', text: this.plugin.t('status_loading') });
      void this.ensureVaultState();
      return;
    }

    if (state === 'present') {
      this.renderUnlock(root);
      return;
    }

    if (state === 'error') {
      this.renderStateError(root, this.plugin.t('err_vault_unreadable'));
      return;
    }

    // 曾经初始化过的路径现在文件缺失：显示错误态，绝不引导用户重新创建（否则会覆盖同名旧库）
    if (state === 'absent' && this.plugin.settings.initializedPath === this.plugin.getVaultPath()) {
      this.renderStateError(root, this.plugin.t('err_vault_missing'));
      return;
    }

    this.renderSetup(root);
  }

  renderStateError(root, message) {
    this.renderHeader(root, this.plugin.t('subtitle_locked'));
    root.createDiv({ cls: 'xsv-error', text: message });
    const actions = root.createDiv({ cls: 'xsv-actions xsv-actions-start' });
    const retryButton = actions.createEl('button', { cls: 'xsv-btn', text: this.plugin.t('btn_retry') });
    retryButton.addEventListener('click', () => {
      this.plugin.vaultState = 'unknown';
      void this.ensureVaultState();
    });
  }

  // 失焦遮罩：只保留验证入口，DOM 中不渲染任何条目内容
  renderMask(root) {
    const mask = root.createDiv({ cls: 'xsv-mask' });
    const card = mask.createDiv({ cls: 'xsv-mask-card' });
    card.createDiv({ cls: 'xsv-title', text: this.plugin.t('mask_title') });
    card.createDiv({ cls: 'xsv-desc', text: this.plugin.t('mask_desc') });
    this.maskCountdownEl = null;
    const remaining = this.plugin.getCountdownRemaining();
    if (remaining >= 0) {
      const countdown = card.createDiv({ cls: 'xsv-mask-countdown' });
      this.maskCountdownEl = countdown;
      countdown.setText(this.plugin.t('mask_countdown', { seconds: Math.max(0, Math.ceil(remaining / 1000)) }));
      card.createDiv({ cls: 'xsv-hint', text: this.plugin.t('mask_return_hint') });
    }
    const password = this.createPasswordField(card, this.plugin.t('label_password'), () => submit());
    const errorEl = card.createDiv({ cls: 'xsv-error' });
    errorEl.setText('');
    const actions = card.createDiv({ cls: 'xsv-actions xsv-actions-start' });
    const verifyButton = actions.createEl('button', {
      cls: 'xsv-btn xsv-btn-primary',
      text: this.plugin.t('btn_reverify'),
    });

    const submit = async () => {
      errorEl.setText('');
      const ok = await this.plugin.reverify(password.value);
      if (!ok) {
        errorEl.setText(this.plugin.lastReverifyError || this.plugin.t('notice_reverify_failed'));
        password.value = '';
        return;
      }
      this.masked = false;
      this.render();
    };

    verifyButton.addEventListener('click', () => void submit());
    if (typeof password.focus === 'function') password.focus();
  }

  renderHeader(root, subtitle) {
    const header = root.createDiv({ cls: 'xsv-header' });
    const text = header.createDiv({ cls: 'xsv-header-text' });
    text.createDiv({ cls: 'xsv-title', text: this.plugin.t('view_title') });
    text.createDiv({ cls: 'xsv-subtitle', text: subtitle });
    return header;
  }

  renderSetup(root) {
    const card = root.createDiv({ cls: 'xsv-page-card' });
    card.createDiv({ cls: 'xsv-title', text: this.plugin.t('setup_title') });
    card.createDiv({ cls: 'xsv-desc', text: this.plugin.t('setup_desc') });
    if (this.setupStep === 'questions') {
      this.renderSetupQuestions(card);
      return;
    }
    if (this.setupStep === 'recoveryCode') {
      this.renderSetupRecoveryCode(card);
      return;
    }
    const password = this.createPasswordField(card, this.plugin.t('label_password'), () => next());
    const confirm = this.createPasswordField(card, this.plugin.t('label_confirm_password'), () => next());
    if (this.setupPassword) password.value = this.setupPassword;
    attachStrengthMeter(card, this.plugin, password);
    this.renderError(card);
    const actions = card.createDiv({ cls: 'xsv-actions xsv-actions-start' });
    const nextButton = actions.createEl('button', { cls: 'xsv-btn xsv-btn-primary', text: this.plugin.t('setup_next') });

    const next = () => {
      const value = password.value;
      if (!value) {
        this.uiError = this.plugin.t('err_password_required');
        this.render();
        return;
      }
      if (value.length < MIN_MASTER_PASSWORD_LENGTH) {
        this.uiError = this.plugin.t('err_new_password_short');
        this.render();
        return;
      }
      if (value !== confirm.value) {
        this.uiError = this.plugin.t('err_password_mismatch');
        this.render();
        return;
      }
      const go = () => {
        this.setupPassword = value;
        this.uiError = '';
        this.setupStep = 'questions';
        this.render();
      };
      const estimate = this.plugin.evaluatePasswordStrength(value);
      if (estimate.tier === 'danger') {
        new ConfirmModal(
          this.app,
          this.plugin.t('strength_confirm_title'),
          this.plugin.t('strength_confirm_desc', { single: estimate.singleText, cluster: estimate.clusterText }),
          this.plugin.t('btn_continue'),
          this.plugin.t('btn_cancel'),
          go
        ).open();
        return;
      }
      go();
    };

    nextButton.addEventListener('click', () => next());
    card.createDiv({ cls: 'xsv-hint', text: this.plugin.t('hint_locked_state') });
  }

  renderSetupQuestions(card) {
    card.createDiv({ cls: 'xsv-title xsv-setup-step-title', text: this.plugin.t('setup_questions_title') });
    card.createDiv({ cls: 'xsv-desc', text: this.plugin.t('setup_questions_desc') });
    const rows = card.createDiv({ cls: 'xsv-question-list' });
    for (let index = 0; index < RECOVERY_QUESTIONS_COUNT; index += 1) {
      const row = rows.createDiv({ cls: 'xsv-question-row' });
      row.createDiv({ cls: 'xsv-label', text: this.plugin.t('recovery_question_label', { index: index + 1 }) });
      const select = row.createEl('select', { cls: 'xsv-input' });
      select.createEl('option', { value: '', text: this.plugin.t('btn_choose_placeholder') });
      for (let preset = 1; preset <= 3; preset += 1) {
        select.createEl('option', {
          value: this.plugin.t('question_preset_' + preset),
          text: this.plugin.t('question_preset_' + preset),
        });
      }
      select.createEl('option', { value: '__custom__', text: this.plugin.t('question_custom') });
      const customInput = row.createEl('input', { cls: 'xsv-input xsv-question-custom', type: 'text' });
      customInput.placeholder = this.plugin.t('question_custom');
      customInput.classList.add('xsv-hidden');
      const answerInput = row.createEl('input', {
        cls: 'xsv-input',
        type: 'text',
        placeholder: this.plugin.t('recovery_answer_label', { index: index + 1 }),
      });
      answerInput.value = this.setupAnswers[index] || '';
      const existing = this.setupQuestions[index] || '';
      if (existing) {
        const presetMatch = [1, 2, 3].find((preset) => this.plugin.t('question_preset_' + preset) === existing);
        if (presetMatch) select.value = existing;
        else {
          select.value = '__custom__';
          customInput.classList.remove('xsv-hidden');
          customInput.value = existing;
        }
      }
      select.addEventListener('change', () => {
        customInput.classList.toggle('xsv-hidden', select.value !== '__custom__');
      });
      this.setupQuestionControls = this.setupQuestionControls || [];
      this.setupQuestionControls[index] = { select, customInput, answerInput };
    }
    card.createDiv({ cls: 'xsv-hint', text: this.plugin.t('setup_questions_skip_hint') });
    this.renderError(card);
    const actions = card.createDiv({ cls: 'xsv-actions xsv-actions-start' });
    const back = actions.createEl('button', { cls: 'xsv-btn', text: this.plugin.t('setup_back') });
    const skip = actions.createEl('button', { cls: 'xsv-btn', text: this.plugin.t('btn_skip_recovery') });
    const create = actions.createEl('button', { cls: 'xsv-btn xsv-btn-primary', text: this.plugin.t('btn_create') });
    back.addEventListener('click', () => {
      this.setupStep = 'password';
      this.uiError = '';
      this.render();
    });
    skip.addEventListener('click', () => {
      new ConfirmModal(
        this.app,
        this.plugin.t('btn_skip_recovery'),
        this.plugin.t('confirm_skip_recovery'),
        this.plugin.t('btn_continue'),
        this.plugin.t('btn_cancel'),
        () => void this.finishSetup(false)
      ).open();
    });
    create.addEventListener('click', () => void this.finishSetup(true));
  }

  collectSetupQuestions() {
    const questions = [];
    const answers = [];
    let filledQuestions = 0;
    for (let index = 0; index < RECOVERY_QUESTIONS_COUNT; index += 1) {
      const controls = (this.setupQuestionControls || [])[index] || {};
      const select = controls.select;
      const customInput = controls.customInput;
      const answerInput = controls.answerInput;
      let question = '';
      if (select && select.value && select.value !== '__custom__') question = select.value;
      else if (select && select.value === '__custom__' && customInput) question = customInput.value;
      const answer = answerInput ? answerInput.value : '';
      if (question) filledQuestions += 1;
      questions.push(question);
      answers.push(answer);
    }
    return { questions, answers, filledQuestions };
  }

  async finishSetup(withQuestions) {
    if (this.setupBusy) return;
    if (withQuestions) {
      const collected = this.collectSetupQuestions();
      if (collected.filledQuestions !== RECOVERY_QUESTIONS_COUNT) {
        this.uiError = this.plugin.t('err_recovery_questions_count');
        this.render();
        return;
      }
      if (collected.answers.some((answer) => normalizeSecurityAnswer(answer).length < SECURITY_ANSWER_MIN)) {
        this.uiError = this.plugin.t('err_recovery_answer_short');
        this.render();
        return;
      }
      this.setupQuestions = collected.questions;
      this.setupAnswers = collected.answers;
    }
    this.setupBusy = true;
    this.uiError = '';
    try {
      const result = await this.plugin.createVault(
        this.setupPassword,
        withQuestions ? { questions: this.setupQuestions, answers: this.setupAnswers } : {}
      );
      this.plugin.vaultState = 'present';
      this.setupRecoveryCode = result && result.recoveryCode ? result.recoveryCode : '';
      this.setupStep = 'recoveryCode';
      this.setupBusy = false;
      new Notice(this.plugin.t('notice_vault_created'), 3000);
      this.render();
    } catch (error) {
      this.setupBusy = false;
      console.error('[' + PLUGIN_ID + '] create vault failed:', error);
      this.uiError = this.plugin.t('err_generic', { msg: errorMessage(error) });
      this.render();
    }
  }

  renderSetupRecoveryCode(card) {
    card.createDiv({ cls: 'xsv-title xsv-setup-step-title', text: this.plugin.t('setup_code_title') });
    card.createDiv({ cls: 'xsv-desc', text: this.plugin.t('setup_code_desc') });
    const codeEl = card.createDiv({ cls: 'xsv-recovery-code', text: this.setupRecoveryCode });
    card.createDiv({ cls: 'xsv-hint', text: this.plugin.t('recovery_code_warning') });
    const actions = card.createDiv({ cls: 'xsv-actions xsv-actions-start' });
    const copy = actions.createEl('button', { cls: 'xsv-btn', text: this.plugin.t('btn_copy_recovery_code') });
    const saved = actions.createEl('button', { cls: 'xsv-btn xsv-btn-primary', text: this.plugin.t('btn_saved_recovery_code') });
    copy.addEventListener('click', async () => {
      const code = this.setupRecoveryCode;
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(code);
          new Notice(this.plugin.t('notice_cell_copied'), 3000);
        }
      } catch (error) {
        console.error('[' + PLUGIN_ID + '] copy recovery code failed:', error);
      }
    });
    saved.addEventListener('click', () => {
      // 一次性展示结束：立即从视图状态中清除，之后无法再从插件取回
      this.setupRecoveryCode = '';
      this.setupPassword = '';
      this.setupQuestions = ['', '', ''];
      this.setupAnswers = ['', '', ''];
      this.setupStep = 'password';
      this.render();
    });
  }

  renderUnlock(root) {
    const card = root.createDiv({ cls: 'xsv-page-card' });
    this.renderHeader(card, this.plugin.t('subtitle_locked'));
    card.createDiv({ cls: 'xsv-desc', text: this.plugin.t('unlock_desc') });
    // 存在冲突副本时必须由用户显式选择，禁止自动挑选
    if (this.plugin.vaultSources.length > 1) this.renderVaultSources(card);
    const password = this.createPasswordField(card, this.plugin.t('label_password'), () => submit());
    this.renderError(card);
    const actions = card.createDiv({ cls: 'xsv-actions xsv-actions-start' });
    const unlockButton = actions.createEl('button', { cls: 'xsv-btn xsv-btn-primary', text: this.plugin.t('btn_unlock') });
    const forgotButton = actions.createEl('button', { cls: 'xsv-btn', text: this.plugin.t('btn_forgot_password') });
    forgotButton.addEventListener('click', () => {
      new ForgotPasswordModal(this.app, this.plugin, () => {
        this.masked = false;
        this.plugin.vaultState = 'present';
        this.render();
      }).open();
    });

    const submit = async () => {
      const value = password.value;
      if (!value) {
        this.uiError = this.plugin.t('err_password_required');
        this.render();
        return;
      }
      this.uiError = '';
      try {
        const ok = await this.plugin.unlock(value);
        if (!ok) {
          this.uiError = this.plugin.lastUnlockError || this.plugin.t('err_unlock_failed');
          this.render();
          return;
        }
        this.plugin.vaultState = 'present';
        this.render();
      } catch (error) {
        console.error('[' + PLUGIN_ID + '] unlock failed:', error);
        this.uiError = this.plugin.t('err_unlock_failed');
        this.render();
      }
    };

    unlockButton.addEventListener('click', () => void submit());
    card.createDiv({ cls: 'xsv-hint', text: this.plugin.t('hint_locked_state') });
  }

  renderVaultSources(root) {
    root.createDiv({ cls: 'xsv-label', text: this.plugin.t('label_vault_source') });
    const selected = this.plugin.getVaultPath();
    const list = root.createDiv({ cls: 'xsv-source-list' });
    for (const source of this.plugin.vaultSources) {
      const isSelected = source === selected;
      const button = list.createEl('button', {
        cls: 'xsv-btn xsv-btn-small' + (isSelected ? ' xsv-btn-primary' : ''),
        text: source,
      });
      button.addEventListener('click', () => {
        this.plugin.selectedVaultPath = source;
        this.render();
      });
    }
    root.createDiv({ cls: 'xsv-hint', text: this.plugin.t('hint_vault_source') });
  }

  renderUnlocked(root) {
    const header = this.renderHeader(root, this.plugin.t('subtitle_unlocked'));
    const lockButton = header.createEl('button', { cls: 'xsv-btn xsv-btn-small', text: this.plugin.t('btn_lock') });
    lockButton.addEventListener('click', () => this.plugin.lock());

    // 冲突后内存快照已过期：必须重载才能继续编辑，避免基于旧数据再次另存副本
    // 查看冲突副本时同样只读：副本上的改动不会写回正式库
    const copyReadOnly = this.plugin.isReadOnlyCopy();
    const readOnly = !!this.plugin.conflictPending || copyReadOnly || !!this.plugin.batchActive;
    if (this.plugin.batchActive && this.plugin.batch) {
      const banner = root.createDiv({ cls: 'xsv-batch-banner' });
      banner.createDiv({
        cls: 'xsv-batch-title',
        text: this.plugin.t('batch_title') + ' ' + this.plugin.batch.current + '/' + this.plugin.batch.total,
      });
      banner.createDiv({
        cls: 'xsv-hint',
        text: this.plugin.t('batch_progress', {
          current: this.plugin.batch.current,
          total: this.plugin.batch.total,
          name: this.plugin.batch.path || '',
        }),
      });
    }
    if (copyReadOnly) this.renderCopyReadonlyBanner(root);
    else if (!this.plugin.batchActive && readOnly) this.renderConflictBanner(root);

    // 0.3.0 起界面只有笔记：条目列表与 CRUD 入口全部下线；0.3.1 起引用语法取消，entries 仅原样保留
    const layout = root.createDiv({ cls: 'xsv-layout' });
    this.renderFilePanel(layout);
    const main = layout.createDiv({ cls: 'xsv-note-panel' });
    this.renderNotes(main, readOnly);
  }

  renderFilePanel(layout) {
    const panel = layout.createDiv({ cls: 'xsv-file-panel' });
    const bar = panel.createDiv({ cls: 'xsv-file-panel-head' });
    bar.createDiv({ cls: 'xsv-file-panel-title', text: this.plugin.t('files_title') });
    const newButton = bar.createEl('button', {
      cls: 'xsv-btn xsv-btn-small xsv-btn-primary',
      text: this.plugin.t('btn_new_file'),
    });
    if (this.plugin.batchActive) newButton.disabled = true;
    newButton.addEventListener('click', () => {
      if (!this.plugin.isUnlocked()) return;
      new FileFormModal(this.plugin.app, this.plugin, { mode: 'create' }).open();
    });

    if (this.plugin.fileLoading) {
      panel.createDiv({ cls: 'xsv-hint xsv-file-loading', text: this.plugin.t('files_loading') });
    }

    const files = this.plugin.vaultFiles || [];
    if (!files.length) {
      panel.createDiv({ cls: 'xsv-hint', text: this.plugin.t('files_empty') });
      return;
    }
    const current = this.plugin.normalizeVaultPath(this.plugin.getVaultPath());
    const collapsed = new Set(normalizeCollapsedGroups(this.plugin.settings.collapsedGroups));
    const groups = new Map();
    for (const file of files) {
      const key = file.group || GROUP_UNGROUPED;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(file);
    }
    const list = panel.createDiv({ cls: 'xsv-file-list' });
    for (const [group, items] of groups) {
      const isCollapsed = !!group && collapsed.has(group);
      const header = list.createEl('button', {
        cls: 'xsv-group-header' + (isCollapsed ? ' xsv-group-collapsed' : ''),
        text:
          (isCollapsed ? '▸ ' : '▾ ') +
          (group || this.plugin.t('group_ungrouped')) +
          ' · ' +
          this.plugin.t('group_file_count', { count: items.length }),
      });
      header.addEventListener('click', () => {
        if (!group) return;
        void this.plugin.toggleGroupCollapsed(group);
      });
      if (isCollapsed) continue;
      const groupBody = list.createDiv({ cls: 'xsv-group-body' });
      for (const file of items) {
        const active = file.path === current;
        const row = groupBody.createDiv({
          cls: 'xsv-file-item' + (active ? ' xsv-file-item-active' : ''),
        });
        const main = row.createDiv({ cls: 'xsv-file-item-main' });
        main.createDiv({ cls: 'xsv-file-name', text: file.name });
        const metaParts = [];
        if (file.legacy) metaParts.push('xu-secrets.enc');
        if (file.mtime) metaParts.push(this.plugin.t('file_mtime', { time: fileMtimeText(file.mtime) }));
        if (metaParts.length) main.createDiv({ cls: 'xsv-file-meta', text: metaParts.join(' · ') });
        row.addEventListener('click', () => {
          if (row.classList && row.classList.contains('xsv-file-item-active')) return;
          void this.plugin.switchVaultFile(file.path);
        });
        const actions = row.createDiv({ cls: 'xsv-file-actions' });
        const renameButton = actions.createEl('button', {
          cls: 'xsv-icon-btn',
          text: '✎',
          attr: { 'aria-label': this.plugin.t('btn_rename_file'), title: this.plugin.t('btn_rename_file') },
        });
        renameButton.addEventListener('click', (event) => {
          if (event && event.stopPropagation) event.stopPropagation();
          if (!this.plugin.isUnlocked()) return;
          new FileFormModal(this.plugin.app, this.plugin, { mode: 'rename', file }).open();
        });
        const deleteButton = actions.createEl('button', {
          cls: 'xsv-icon-btn',
          text: '×',
          attr: { 'aria-label': this.plugin.t('btn_delete_file'), title: this.plugin.t('btn_delete_file') },
        });
        deleteButton.addEventListener('click', (event) => {
          if (event && event.stopPropagation) event.stopPropagation();
          if (!this.plugin.isUnlocked()) return;
          new ConfirmModal(
            this.plugin.app,
            this.plugin.t('confirm_delete_file', { name: file.name }),
            this.plugin.t('confirm_delete_file', { name: file.name }),
            this.plugin.t('btn_delete_file'),
            this.plugin.t('btn_cancel'),
            () => {
              void this.plugin.deleteVaultFile(file.path);
            }
          ).open();
        });
      }
    }
  }

  renderCopyReadonlyBanner(root) {
    const banner = root.createDiv({ cls: 'xsv-conflict-banner' });
    banner.createDiv({ cls: 'xsv-desc', text: this.plugin.t('err_conflict_copy_readonly') });
    banner.createDiv({
      cls: 'xsv-hint',
      text: this.plugin.t('readonly_copy_path', { path: this.plugin.getVaultPath() }),
    });
  }

  renderConflictBanner(root) {
    const banner = root.createDiv({ cls: 'xsv-conflict-banner' });
    banner.createDiv({
      cls: 'xsv-desc',
      text: this.plugin.t('conflict_banner', { path: this.plugin.conflictPath || '' }),
    });
    const actions = banner.createDiv({ cls: 'xsv-actions xsv-actions-start' });
    const reloadButton = actions.createEl('button', { cls: 'xsv-btn xsv-btn-primary', text: this.plugin.t('btn_reload') });
    reloadButton.addEventListener('click', () => {
      void (async () => {
        const ok = await this.plugin.reloadFromConflict();
        new Notice(this.plugin.t(ok ? 'notice_reloaded' : 'notice_unlock_first'), 4000);
      })();
    });
  }

  /* ---------------- 笔记模式 ---------------- */

  renderNotes(root, readOnly) {
    const notes = this.plugin.notes || [];
    if (!notes.length) {
      root.createDiv({ cls: 'xsv-empty', text: this.plugin.t('note_empty') });
      return;
    }
    let selected = notes.filter((note) => note.id === this.noteId)[0];
    if (!selected) {
      selected = notes[0];
      this.noteId = selected.id;
    }
    // 只读副本/冲突态下不允许继续编辑，立即丢弃草稿
    if (readOnly && this.noteEditing) {
      this.noteEditing = false;
      this.noteDraft = null;
    }

    const wrap = root.createDiv({ cls: 'xsv-notes' });
    const list = wrap.createDiv({ cls: 'xsv-note-list' });
    for (const note of notes) {
      const button = list.createEl('button', {
        cls: 'xsv-note-tab' + (note.id === selected.id ? ' xsv-note-tab-active' : ''),
        text: note.title,
      });
      button.addEventListener('click', () => {
        if (this.noteId === note.id && !this.noteEditing) return;
        this.noteId = note.id;
        this.noteEditing = false;
        this.noteDraft = null;
        this.revealedCells.clear();
        this.render();
      });
    }

    // 标题只由正文 Markdown 渲染一次；这里不再重复渲染页面头部标题
    const header = wrap.createDiv({ cls: 'xsv-note-header' });
    if (!readOnly && !this.noteEditing) {
      const editButton = header.createEl('button', {
        cls: 'xsv-btn xsv-btn-small',
        text: this.plugin.t('btn_note_edit'),
      });
      editButton.addEventListener('click', () => {
        this.noteEditing = true;
        this.noteDraft = selected.body;
        this.render();
      });
    }

    const body = wrap.createDiv({ cls: 'xsv-note-body' });
    if (this.noteEditing) {
      this.renderNoteEditor(body, selected);
      return;
    }
    if (!String(selected.body || '').trim()) {
      const guide = body.createDiv({ cls: 'xsv-note-guide' });
      guide.createDiv({ cls: 'xsv-note-guide-title', text: this.plugin.t('note_guide_title') });
      guide.createDiv({ cls: 'xsv-hint', text: this.plugin.t('note_guide_desc') });
      if (!readOnly) {
        const sampleButton = guide.createEl('button', {
          cls: 'xsv-btn xsv-btn-primary',
          text: this.plugin.t('btn_note_sample'),
        });
        sampleButton.addEventListener('click', () => {
          this.noteEditing = true;
          this.noteDraft = this.buildSampleNote();
          this.render();
        });
      }
      return;
    }
    this.renderMarkdown(body, selected.body);
  }

  // 示例表：一眼看到默认全明文、可点链接与转义后的特殊符号
  // 密码列含 |、*、_；竖线在源码中写成 \|，渲染与复制都还原为 |
  // 默认不做按列名遮挡；表下写明只有手动设为「密文」才会遮挡
  buildSampleNote() {
    return [
      '# 我的密钥',
      '',
      '## 常用账号',
      '',
      '| 名称 | 账号 | 密码 | 网址 |',
      '| :--- | :--- | :--- | :--- |',
      '| GitHub | your-github-name | p@ss\\|w0rd*_2026 | [github.com](https://github.com) |',
      '| 阿里云 | your-aliyun-id | P@ss-W0rd_*2026 | [aliyun.com](https://console.aliyun.com) |',
      '',
      '表格默认全部按原文显示。只有把列名加进「设置 → 列显示规则」并选「密文」，该列才会遮挡。',
    ].join('\n');
  }

  renderNoteEditor(body, note) {
    body.createDiv({ cls: 'xsv-hint', text: this.plugin.t('note_editor_hint') });
    const editor = body.createEl('textarea', { cls: 'xsv-note-editor' });
    editor.value = this.noteDraft != null ? this.noteDraft : note.body;

    editor.addEventListener('input', () => {
      this.noteDraft = editor.value;
    });
    const errorEl = body.createDiv({ cls: 'xsv-error' });
    errorEl.setText('');

    // 已有内容时不静默插入：先让用户选择追加还是替换
    const sampleChoice = body.createDiv({ cls: 'xsv-sample-choice' });
    if (sampleChoice.style) sampleChoice.style.display = 'none';
    sampleChoice.createDiv({ cls: 'xsv-hint', text: this.plugin.t('note_sample_choice') });
    const sampleActions = sampleChoice.createDiv({ cls: 'xsv-actions xsv-actions-start' });
    const applySample = (mode) => {
      const sample = this.buildSampleNote();
      const current = String(editor.value).replace(/\s+$/, '');
      // 示例只插入一次：重复点击「追加」不再叠加第二份表格与说明行
      if (mode === 'append' && current.indexOf(sample.trim()) >= 0) {
        new Notice(this.plugin.t('notice_sample_exists'), 4000);
        if (sampleChoice.style) sampleChoice.style.display = 'none';
        return;
      }
      editor.value = mode === 'replace' ? sample : current + '\n\n' + sample;
      this.noteDraft = editor.value;
      if (sampleChoice.style) sampleChoice.style.display = 'none';
    };
    const appendButton = sampleActions.createEl('button', {
      cls: 'xsv-btn xsv-btn-small',
      text: this.plugin.t('btn_sample_append'),
    });
    appendButton.addEventListener('click', () => applySample('append'));
    const replaceButton = sampleActions.createEl('button', {
      cls: 'xsv-btn xsv-btn-small',
      text: this.plugin.t('btn_sample_replace'),
    });
    replaceButton.addEventListener('click', () => applySample('replace'));
    const sampleCancelButton = sampleActions.createEl('button', {
      cls: 'xsv-btn xsv-btn-small',
      text: this.plugin.t('btn_cancel'),
    });
    sampleCancelButton.addEventListener('click', () => {
      if (sampleChoice.style) sampleChoice.style.display = 'none';
    });

    const actions = body.createDiv({ cls: 'xsv-actions xsv-actions-start' });
    const sampleButton = actions.createEl('button', { cls: 'xsv-btn', text: this.plugin.t('btn_note_sample') });
    sampleButton.addEventListener('click', () => {
      const sample = this.buildSampleNote();
      if (!String(editor.value).trim()) {
        editor.value = sample;
        this.noteDraft = sample;
        return;
      }
      if (sampleChoice.style) sampleChoice.style.display = '';
    });
    const cancelButton = actions.createEl('button', { cls: 'xsv-btn', text: this.plugin.t('btn_note_cancel') });
    cancelButton.addEventListener('click', () => {
      this.noteEditing = false;
      this.noteDraft = null;
      this.render();
    });
    const saveButton = actions.createEl('button', {
      cls: 'xsv-btn xsv-btn-primary',
      text: this.plugin.t('btn_note_save'),
    });
    saveButton.addEventListener('click', () => {
      void (async () => {
        errorEl.setText('');
        saveButton.disabled = true;
        try {
          const result = await this.plugin.saveNote(note.id, editor.value);
          this.noteEditing = false;
          this.noteDraft = null;
          if (result && result.conflict) {
            new Notice(this.plugin.t('notice_conflict_saved', { path: result.conflictPath || '' }), 12000);
          } else if (result && result.discarded) {
            new Notice(this.plugin.t('err_suspended'), 5000);
          }
          this.render();
        } catch (error) {
          saveButton.disabled = false;
          errorEl.setText(errorMessage(error));
        }
      })();
    });
  }

  // 简易 Markdown 渲染：全部用 DOM API 构建，从不拼接 HTML 字符串
  renderMarkdown(container, source) {
    const lines = String(source || '').replace(/\r\n?/g, '\n').split('\n');
    let index = 0;
    const paragraph = [];
    const flushParagraph = () => {
      if (!paragraph.length) return;
      const p = container.createEl('p');
      this.renderInline(p, paragraph.join(' '));
      paragraph.length = 0;
    };

    while (index < lines.length) {
      const line = lines[index];
      if (!line.trim()) {
        flushParagraph();
        index += 1;
        continue;
      }
      const heading = /^(#{1,6})\s+(.*)$/.exec(line);
      if (heading) {
        flushParagraph();
        const level = heading[1].length;
        const headingEl = container.createEl('h' + level);
        this.renderInline(headingEl, heading[2].trim());
        index += 1;
        continue;
      }
      if (/^\s*[-*]\s+/.test(line)) {
        flushParagraph();
        const ul = container.createEl('ul');
        while (index < lines.length) {
          const item = /^\s*[-*]\s+(.*)$/.exec(lines[index]);
          if (!item) break;
          const li = ul.createEl('li');
          this.renderInline(li, item[1]);
          index += 1;
        }
        continue;
      }
      if (/^\s*\d+\.\s+/.test(line)) {
        flushParagraph();
        const ol = container.createEl('ol');
        while (index < lines.length) {
          const item = /^\s*\d+\.\s+(.*)$/.exec(lines[index]);
          if (!item) break;
          const li = ol.createEl('li');
          this.renderInline(li, item[1]);
          index += 1;
        }
        continue;
      }
      if (this.isPipeTableStart(lines, index)) {
        flushParagraph();
        index = this.renderPipeTable(container, lines, index);
        continue;
      }
      paragraph.push(line.trim());
      index += 1;
    }
    flushParagraph();
  }

  // 按未转义的 | 切分单元格；\| 与 \\ 保留源码写法，交给 unescapeCellText 统一还原
  splitPipeRow(row) {
    let text = String(row).trim();
    if (text.startsWith('|') && !text.startsWith('\\|')) text = text.slice(1);
    if (text.endsWith('|')) {
      let backslashes = 0;
      let cursor = text.length - 2;
      while (cursor >= 0 && text[cursor] === '\\') {
        backslashes += 1;
        cursor -= 1;
      }
      if (backslashes % 2 === 0) text = text.slice(0, -1);
    }
    const cells = [];
    let current = '';
    let index = 0;
    while (index < text.length) {
      const char = text[index];
      if (char === '\\' && index + 1 < text.length) {
        const next = text[index + 1];
        if (next === '|' || next === '\\') {
          current += char + next;
          index += 2;
          continue;
        }
      }
      if (char === '|') {
        cells.push(current.trim());
        current = '';
        index += 1;
        continue;
      }
      current += char;
      index += 1;
    }
    cells.push(current.trim());
    return cells;
  }

  cellText(rawCell) {
    return unescapeCellText(String(rawCell == null ? '' : rawCell).trim());
  }

  // 单元格唯一例外：整格是 Markdown 链接或裸 http/https URL 时渲染为可点链接
  cellLink(value) {
    const mdLink = /^\[([^\]\n]+)\]\((https?:\/\/[^)\s]+)\)$/i.exec(value);
    if (mdLink) return { label: mdLink[1], url: mdLink[2] };
    if (/^https?:\/\/[^\s]+$/i.test(value)) return { label: value, url: value };
    return null;
  }

  isSensitiveHeader(text) {
    return this.plugin.getColumnMode(text) === 'secret';
  }

  renderCellLink(td, link) {
    const anchor = td.createEl('a', { text: link.label });
    anchor.setAttribute('href', link.url);
    anchor.setAttribute('target', '_blank');
    anchor.setAttribute('rel', 'noopener noreferrer');
    anchor.addEventListener('click', (event) => {
      if (event && typeof event.preventDefault === 'function') event.preventDefault();
      if (typeof window !== 'undefined' && typeof window.open === 'function') {
        window.open(link.url, '_blank', 'noopener,noreferrer');
      }
    });
  }

  attachCellCopy(td, value) {
    td.addClass('xsv-cell-copy');
    td.addEventListener('click', (event) => {
      const target = event && event.target;
      if (target && typeof target.closest === 'function' && (target.closest('a') || target.closest('button'))) {
        return;
      }
      const link = this.cellLink(value);
      if (link) {
        window.open(link.url, '_blank', 'noopener,noreferrer');
        return;
      }
      void this.plugin.copySecret(value).then((copied) => {
        if (copied) new Notice(this.plugin.t('notice_cell_copied'), 2000);
      });
    });
  }

  // 密文列：默认掩码，眼睛按钮临时显示；点击单元格本体仍复制真实值
  renderSensitiveCell(td, value, cellKey) {
    td.addClass('xsv-cell-secret');
    const textEl = td.createSpan({ cls: 'xsv-secret-text' });
    const revealed = this.revealedCells.has(cellKey);
    textEl.setText(revealed && value ? value : MASK_PLACEHOLDER);
    if (!value) return;
    this.attachCellCopy(td, value);
    const eye = td.createEl('button', {
      cls: 'xsv-eye-btn' + (revealed ? ' xsv-eye-btn-active' : ''),
      text: '👁',
    });
    eye.setAttribute('title', this.plugin.t(revealed ? 'btn_eye_hide' : 'btn_eye_show'));
    eye.addEventListener('click', (event) => {
      if (event && typeof event.stopPropagation === 'function') event.stopPropagation();
      const key = cellKey;
      if (this.revealedCells.has(key)) {
        this.revealedCells.delete(key);
        textEl.setText(MASK_PLACEHOLDER);
        eye.setAttribute('title', this.plugin.t('btn_eye_show'));
        eye.removeClass('xsv-eye-btn-active');
        return;
      }
      this.revealedCells.add(key);
      textEl.setText(value);
      eye.setAttribute('title', this.plugin.t('btn_eye_hide'));
      eye.addClass('xsv-eye-btn-active');
    });
  }

  isPipeTableStart(lines, index) {
    if (index + 1 >= lines.length) return false;
    const header = lines[index];
    if (header.indexOf('|') < 0) return false;
    const separator = this.splitPipeRow(lines[index + 1]);
    if (!separator.length) return false;
    return separator.every((cell) => /^:?-{3,}:?$/.test(cell));
  }

  renderPipeTable(container, lines, start) {
    const headerCells = this.splitPipeRow(lines[start]);
    const headerTexts = headerCells.map((cell) => this.cellText(cell));
    const sensitiveColumns = headerTexts.map((text) => this.isSensitiveHeader(text));
    const separatorCells = this.splitPipeRow(lines[start + 1]);
    const alignments = separatorCells.map((cell) => {
      const left = cell.startsWith(':');
      const right = cell.endsWith(':');
      if (left && right) return 'center';
      if (right) return 'right';
      return 'left';
    });
    const tableWrap = container.createDiv({ cls: 'xsv-table-wrap' });
    const table = tableWrap.createEl('table', { cls: 'xsv-md-table' });
    const thead = table.createEl('thead');
    const headRow = thead.createEl('tr');
    for (let col = 0; col < headerCells.length; col += 1) {
      const th = headRow.createEl('th');
      if (alignments[col] && th.style) th.style.textAlign = alignments[col];
      // 表头同样按纯文本显示，不做行内 Markdown 或引用解析
      this.appendInlineText(th, headerTexts[col]);
    }
    const tbody = table.createEl('tbody');
    let index = start + 2;
    let rowIndex = 0;
    while (index < lines.length && lines[index].trim() && lines[index].indexOf('|') >= 0) {
      const cells = this.splitPipeRow(lines[index]);
      const tr = tbody.createEl('tr');
      for (let col = 0; col < headerCells.length; col += 1) {
        const td = tr.createEl('td');
        if (alignments[col] && td.style) td.style.textAlign = alignments[col];
        const value = this.cellText(cells[col] || '');
        const cellKey = [this.noteId, rowIndex, col].join(':');
        if (sensitiveColumns[col]) {
          this.renderSensitiveCell(td, value, cellKey);
          continue;
        }
        if (value) {
          const link = this.cellLink(value);
          if (link) this.renderCellLink(td, link);
          else this.appendInlineText(td, value);
          // 单元格即复制单元：表头不参与，链接格点击开浏览器，空单元格不注册点击
          this.attachCellCopy(td, value);
        }
      }
      index += 1;
      rowIndex += 1;
    }
    const sensitiveCount = sensitiveColumns.filter(Boolean).length;
    if (sensitiveCount > 0) {
      tableWrap.createDiv({
        cls: 'xsv-sensitive-note',
        text: this.plugin.t('notice_sensitive_columns', { count: sensitiveCount }),
      });
    }
    return index;
  }

  appendInlineText(parent, text) {
    if (!text) return;
    if (typeof parent.appendText === 'function') parent.appendText(String(text));
    else parent.createSpan({ text: String(text) });
  }

  renderInline(parent, text) {
    let rest = String(text == null ? '' : text);
    // 0.3.1 起不再解析 {{条目.字段}}，花括号按字面文本显示
    const tokenRe = /(\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\([^)\s]+\))/;
    while (rest) {
      const match = tokenRe.exec(rest);
      if (!match) {
        this.appendInlineText(parent, rest);
        break;
      }
      if (match.index > 0) this.appendInlineText(parent, rest.slice(0, match.index));
      const token = match[0];
      rest = rest.slice(match.index + token.length);
      this.renderInlineToken(parent, token);
    }
  }

  renderInlineToken(parent, token) {
    if (token.startsWith('**') && token.endsWith('**')) {
      const strong = parent.createEl('strong');
      this.appendInlineText(strong, token.slice(2, -2));
      return;
    }
    if (token.startsWith('`') && token.endsWith('`')) {
      parent.createEl('code', { text: token.slice(1, -1) });
      return;
    }
    const link = /^\[([^\]]+)\]\(([^)\s]+)\)$/.exec(token);
    if (link) {
      const url = link[2];
      if (!/^https?:\/\//i.test(url)) {
        // 非 http/https 一律按纯文本显示，不生成可点击元素
        this.appendInlineText(parent, token);
        return;
      }
      const anchor = parent.createEl('a', { text: link[1] });
      anchor.setAttribute('href', url);
      anchor.setAttribute('target', '_blank');
      anchor.setAttribute('rel', 'noopener noreferrer');
      anchor.addEventListener('click', (event) => {
        if (event && typeof event.preventDefault === 'function') event.preventDefault();
        if (typeof window !== 'undefined' && typeof window.open === 'function') {
          window.open(url, '_blank', 'noopener,noreferrer');
        }
      });
      return;
    }
    // 其它 token（含 {{...}}，因为不在 tokenRe 中）按字面文本输出
    this.appendInlineText(parent, token);
  }


}

/* ------------------------------------------------------------------ */
/* 简单确认弹窗（清空全部列规则等二次确认）                             */
/* ------------------------------------------------------------------ */
class ConfirmModal extends Modal {
  constructor(app, title, message, confirmLabel, cancelLabel, onConfirm) {
    super(app);
    this.confirmTitle = title;
    this.confirmMessage = message;
    this.confirmLabel = confirmLabel;
    this.cancelLabel = cancelLabel;
    this.onConfirm = onConfirm;
  }

  onOpen() {
    this.titleEl.setText(this.confirmTitle);
    this.contentEl.createEl('p', { text: this.confirmMessage });
    const actions = this.contentEl.createDiv({ cls: 'xsv-modal-actions' });
    const cancel = actions.createEl('button', { cls: 'xsv-btn', text: this.cancelLabel });
    cancel.addEventListener('click', () => this.close());
    const confirm = actions.createEl('button', { cls: 'xsv-btn xsv-btn-danger', text: this.confirmLabel });
    confirm.addEventListener('click', () => {
      this.close();
      if (typeof this.onConfirm === 'function') this.onConfirm();
    });
  }

  onClose() {
    this.contentEl.empty();
  }
}

function buildQuestionControls(container, plugin, questions, answers) {
  const controls = [];
  const list = container.createDiv({ cls: 'xsv-question-list' });
  for (let index = 0; index < RECOVERY_QUESTIONS_COUNT; index += 1) {
    const row = list.createDiv({ cls: 'xsv-question-row' });
    row.createDiv({ cls: 'xsv-label', text: plugin.t('recovery_question_label', { index: index + 1 }) });
    const select = row.createEl('select', { cls: 'xsv-input' });
    select.createEl('option', { value: '', text: plugin.t('btn_choose_placeholder') });
    for (let preset = 1; preset <= 3; preset += 1) {
      select.createEl('option', {
        value: plugin.t('question_preset_' + preset),
        text: plugin.t('question_preset_' + preset),
      });
    }
    select.createEl('option', { value: '__custom__', text: plugin.t('question_custom') });
    const customInput = row.createEl('input', { cls: 'xsv-input xsv-question-custom', type: 'text' });
    customInput.placeholder = plugin.t('question_custom');
    customInput.classList.add('xsv-hidden');
    const answerInput = row.createEl('input', {
      cls: 'xsv-input',
      type: 'text',
      placeholder: plugin.t('recovery_answer_label', { index: index + 1 }),
    });
    const existingQuestion = (questions || [])[index] || '';
    if (existingQuestion) {
      const presetMatch = [1, 2, 3].find((preset) => plugin.t('question_preset_' + preset) === existingQuestion);
      if (presetMatch) select.value = existingQuestion;
      else {
        select.value = '__custom__';
        customInput.classList.remove('xsv-hidden');
        customInput.value = existingQuestion;
      }
    }
    answerInput.value = (answers || [])[index] || '';
    select.addEventListener('change', () => {
      customInput.classList.toggle('xsv-hidden', select.value !== '__custom__');
    });
    controls.push({ select, customInput, answerInput });
  }
  const collect = () => {
    const outQuestions = [];
    const outAnswers = [];
    let filled = 0;
    for (const control of controls) {
      let question = '';
      if (control.select.value && control.select.value !== '__custom__') question = control.select.value;
      else if (control.select.value === '__custom__') question = control.customInput.value;
      if (question) filled += 1;
      outQuestions.push(question);
      outAnswers.push(control.answerInput.value);
    }
    return { questions: outQuestions, answers: outAnswers, filled };
  };
  return { controls, collect };
}

/* 修改主密码：快速改密 / 彻底轮换两档，批量覆盖全部文件 */
class ChangePasswordModal extends Modal {
  constructor(app, plugin) {
    super(app);
    this.plugin = plugin;
  }

  onOpen() {
    const t = (key, params) => this.plugin.t(key, params);
    this.titleEl.setText(t('change_pw_title'));
    const current = this.contentEl.createEl('input', { cls: 'xsv-input', type: 'password' });
    current.placeholder = t('change_pw_current');
    current.autocomplete = 'current-password';
    const next = this.contentEl.createEl('input', { cls: 'xsv-input', type: 'password' });
    next.placeholder = t('change_pw_new');
    next.autocomplete = 'new-password';
    attachStrengthMeter(this.contentEl, this.plugin, next);
    const confirm = this.contentEl.createEl('input', { cls: 'xsv-input', type: 'password' });
    confirm.placeholder = t('change_pw_confirm');
    confirm.autocomplete = 'new-password';
    const modeRow = this.contentEl.createDiv({ cls: 'xsv-mode-row' });
    modeRow.createDiv({ cls: 'xsv-label', text: t('change_pw_mode') });
    const mode = modeRow.createEl('select', { cls: 'xsv-input' });
    mode.createEl('option', { value: 'quick', text: t('change_pw_mode_quick') });
    mode.createEl('option', { value: 'full', text: t('change_pw_mode_full') });
    const modeNote = this.contentEl.createDiv({ cls: 'xsv-hint', text: t('change_pw_quick_note') });
    mode.addEventListener('change', () => {
      modeNote.setText(mode.value === 'full' ? t('change_pw_full_note') : t('change_pw_quick_note'));
    });
    const error = this.contentEl.createDiv({ cls: 'xsv-error' });
    const progress = this.contentEl.createDiv({ cls: 'xsv-hint xsv-batch-progress' });
    const actions = this.contentEl.createDiv({ cls: 'xsv-modal-actions' });
    const cancel = actions.createEl('button', { cls: 'xsv-btn', text: t('btn_cancel') });
    cancel.addEventListener('click', () => this.close());
    const submit = actions.createEl('button', { cls: 'xsv-btn xsv-btn-primary', text: t('btn_change_password') });

    const run = async () => {
      error.setText('');
      submit.disabled = true;
      try {
        await this.plugin.changeMasterPassword(current.value, next.value, {
          mode: mode.value === 'full' ? 'full' : 'quick',
          onProgress: (batch) => {
            progress.setText(
              t('change_pw_progress', { current: batch.current, total: batch.total })
            );
          },
        });
        new Notice(t('notice_password_changed'), 5000);
        this.close();
      } catch (changeError) {
        progress.setText('');
        error.setText(errorMessage(changeError));
      } finally {
        submit.disabled = false;
      }
    };

    submit.addEventListener('click', () => {
      if (!current.value) {
        error.setText(t('err_old_password_wrong'));
        return;
      }
      if (String(next.value || '').length < MIN_MASTER_PASSWORD_LENGTH) {
        error.setText(t('err_new_password_short'));
        return;
      }
      if (next.value !== confirm.value) {
        error.setText(t('err_password_mismatch'));
        return;
      }
      const estimate = this.plugin.evaluatePasswordStrength(next.value);
      if (estimate.tier === 'danger') {
        new ConfirmModal(
          this.app,
          t('strength_confirm_title'),
          t('strength_confirm_desc', { single: estimate.singleText, cluster: estimate.clusterText }),
          t('btn_continue'),
          t('btn_cancel'),
          () => void run()
        ).open();
        return;
      }
      void run();
    });
  }

  onClose() {
    this.contentEl.empty();
  }
}

/* 设置/修改三个密保问题：要求当前主密码 */
class RecoveryQuestionsModal extends Modal {
  constructor(app, plugin) {
    super(app);
    this.plugin = plugin;
  }

  onOpen() {
    const t = (key, params) => this.plugin.t(key, params);
    this.titleEl.setText(t('recovery_title'));
    this.contentEl.createEl('p', { cls: 'xsv-desc', text: t('recovery_desc') });
    const current = this.contentEl.createEl('input', { cls: 'xsv-input', type: 'password' });
    current.placeholder = t('change_pw_current');
    const existing = this.plugin.sessionRecovery;
    const builder = buildQuestionControls(
      this.contentEl,
      this.plugin,
      existing ? existing.questions : [],
      []
    );
    this.contentEl.createDiv({ cls: 'xsv-hint', text: t('recovery_answer_hint') });
    const error = this.contentEl.createDiv({ cls: 'xsv-error' });
    const actions = this.contentEl.createDiv({ cls: 'xsv-modal-actions' });
    const cancel = actions.createEl('button', { cls: 'xsv-btn', text: t('btn_cancel') });
    cancel.addEventListener('click', () => this.close());
    const save = actions.createEl('button', { cls: 'xsv-btn xsv-btn-primary', text: t('btn_save_recovery') });
    save.addEventListener('click', async () => {
      if (!current.value) {
        error.setText(t('err_current_password_wrong'));
        return;
      }
      const collected = builder.collect();
      if (collected.filled !== RECOVERY_QUESTIONS_COUNT) {
        error.setText(t('err_recovery_questions_count'));
        return;
      }
      if (collected.answers.some((answer) => normalizeSecurityAnswer(answer).length < SECURITY_ANSWER_MIN)) {
        error.setText(t('err_recovery_answer_short'));
        return;
      }
      save.disabled = true;
      try {
        await this.plugin.setRecoveryQuestions(current.value, collected.questions, collected.answers);
        new Notice(t('notice_recovery_saved'), 5000);
        this.close();
      } catch (saveError) {
        error.setText(errorMessage(saveError));
      } finally {
        save.disabled = false;
      }
    });
  }

  onClose() {
    this.contentEl.empty();
  }
}

/* 忘记主密码：恢复码 / 三道密保问题 → 强制设置新主密码 */
class ForgotPasswordModal extends Modal {
  constructor(app, plugin, onDone) {
    super(app);
    this.plugin = plugin;
    this.onDone = onDone;
    this.step = 'risk';
    this.questions = [];
    this.completed = false;
  }

  onOpen() {
    this.render();
  }

  render() {
    const t = (key, params) => this.plugin.t(key, params);
    this.titleEl.setText(t('forgot_title'));
    this.contentEl.empty();
    const error = this.contentEl.createDiv({ cls: 'xsv-error' });
    if (this.step === 'risk') {
      this.contentEl.createEl('p', { cls: 'xsv-desc', text: t('forgot_risk') });
      this.contentEl.createDiv({ cls: 'xsv-hint', text: t('err_recovery_unavailable_hint') });
      const actions = this.contentEl.createDiv({ cls: 'xsv-modal-actions' });
      const cancel = actions.createEl('button', { cls: 'xsv-btn', text: t('btn_cancel') });
      cancel.addEventListener('click', () => this.close());
      const code = actions.createEl('button', { cls: 'xsv-btn xsv-btn-primary', text: t('forgot_choose_code') });
      code.addEventListener('click', () => {
        this.step = 'code';
        this.render();
      });
      const questions = actions.createEl('button', { cls: 'xsv-btn', text: t('forgot_choose_questions') });
      questions.addEventListener('click', async () => {
        const source = await this.plugin.findRecoverySource('questions');
        if (!source) {
          error.setText(t('err_recovery_unavailable'));
          this.contentEl.createDiv({ cls: 'xsv-hint', text: t('err_recovery_unavailable_hint') });
          return;
        }
        this.questions = source.envelope.recovery.questions.slice();
        this.step = 'questions';
        this.render();
      });
      return;
    }
    if (this.step === 'code') {
      const input = this.contentEl.createEl('input', { cls: 'xsv-input', type: 'text' });
      input.placeholder = t('forgot_code_label');
      this.contentEl.createDiv({ cls: 'xsv-hint', text: t('forgot_code_hint') });
      const actions = this.contentEl.createDiv({ cls: 'xsv-modal-actions' });
      const back = actions.createEl('button', { cls: 'xsv-btn', text: t('setup_back') });
      back.addEventListener('click', () => {
        this.step = 'risk';
        this.render();
      });
      const submit = actions.createEl('button', { cls: 'xsv-btn xsv-btn-primary', text: t('btn_recover_now') });
      submit.addEventListener('click', async () => {
        submit.disabled = true;
        const result = await this.plugin.recoverWithCode(input.value);
        submit.disabled = false;
        if (!result.ok) {
          error.setText(result.code === 'unavailable' ? t('err_recovery_unavailable') : t('err_recovery_failed'));
          return;
        }
        this.step = 'password';
        this.render();
      });
      return;
    }
    if (this.step === 'questions') {
      const inputs = [];
      for (let index = 0; index < RECOVERY_QUESTIONS_COUNT; index += 1) {
        this.contentEl.createDiv({ cls: 'xsv-label', text: this.questions[index] || '' });
        const input = this.contentEl.createEl('input', { cls: 'xsv-input', type: 'text' });
        input.placeholder = t('forgot_answer_label', { index: index + 1 });
        inputs.push(input);
      }
      const actions = this.contentEl.createDiv({ cls: 'xsv-modal-actions' });
      const back = actions.createEl('button', { cls: 'xsv-btn', text: t('setup_back') });
      back.addEventListener('click', () => {
        this.step = 'risk';
        this.render();
      });
      const submit = actions.createEl('button', { cls: 'xsv-btn xsv-btn-primary', text: t('btn_recover_now') });
      submit.addEventListener('click', async () => {
        submit.disabled = true;
        const result = await this.plugin.recoverWithQuestions(inputs.map((input) => input.value));
        submit.disabled = false;
        if (!result.ok) {
          // 不区分第几题错，一律同一句文案
          error.setText(result.code === 'unavailable' ? t('err_recovery_unavailable') : t('err_recovery_failed'));
          return;
        }
        this.step = 'password';
        this.render();
      });
      return;
    }
    // 设置新主密码
    this.contentEl.createEl('p', { cls: 'xsv-desc', text: t('forgot_new_password_desc') });
    const password = this.contentEl.createEl('input', { cls: 'xsv-input', type: 'password' });
    password.placeholder = t('change_pw_new');
    password.autocomplete = 'new-password';
    attachStrengthMeter(this.contentEl, this.plugin, password);
    const confirm = this.contentEl.createEl('input', { cls: 'xsv-input', type: 'password' });
    confirm.placeholder = t('change_pw_confirm');
    confirm.autocomplete = 'new-password';
    const actions = this.contentEl.createDiv({ cls: 'xsv-modal-actions' });
    const submit = actions.createEl('button', { cls: 'xsv-btn xsv-btn-primary', text: t('btn_reset_password') });
    const run = async () => {
      submit.disabled = true;
      try {
        await this.plugin.completeRecoveryPassword(password.value);
        this.completed = true;
        new Notice(t('notice_recovery_reset'), 12000);
        this.close();
        if (typeof this.onDone === 'function') this.onDone();
      } catch (resetError) {
        error.setText(errorMessage(resetError));
      } finally {
        submit.disabled = false;
      }
    };
    submit.addEventListener('click', () => {
      if (password.value.length < MIN_MASTER_PASSWORD_LENGTH) {
        error.setText(t('err_new_password_short'));
        return;
      }
      if (password.value !== confirm.value) {
        error.setText(t('err_password_mismatch'));
        return;
      }
      const estimate = this.plugin.evaluatePasswordStrength(password.value);
      if (estimate.tier === 'danger') {
        new ConfirmModal(
          this.app,
          t('strength_confirm_title'),
          t('strength_confirm_desc', { single: estimate.singleText, cluster: estimate.clusterText }),
          t('btn_continue'),
          t('btn_cancel'),
          () => void run()
        ).open();
        return;
      }
      void run();
    });
  }

  onClose() {
    if (!this.completed) this.plugin.pendingRecovery = null;
    this.contentEl.empty();
  }
}

/* 新建 / 重命名保险库文件：名称 + 已有分组下拉，或直接输入新分组 */
class FileFormModal extends Modal {
  constructor(app, plugin, options) {
    super(app);
    this.plugin = plugin;
    this.options = options || {};
  }

  onOpen() {
    const t = (key, params) => this.plugin.t(key, params);
    const renaming = this.options.mode === 'rename';
    const file = this.options.file || null;
    this.titleEl.setText(t(renaming ? 'rename_file_title' : 'new_file_title'));
    const body = this.contentEl.createDiv({ cls: 'xsv-file-form' });
    body.createDiv({ cls: 'xsv-label', text: t('new_file_name') });
    const nameInput = body.createEl('input', { cls: 'xsv-input', type: 'text' });
    nameInput.value = file ? file.name : '';
    body.createDiv({ cls: 'xsv-hint', text: t('new_file_name_hint') });
    body.createDiv({ cls: 'xsv-label', text: t('new_file_group') });
    const groupSelect = body.createEl('select', { cls: 'xsv-input' });
    groupSelect.createEl('option', { value: '', text: t('group_ungrouped') });
    const groups = this.plugin.getGroupOptions();
    if (file && file.group && groups.indexOf(file.group) < 0) groups.push(file.group);
    for (const group of groups) groupSelect.createEl('option', { value: group, text: group });
    groupSelect.createEl('option', { value: '__new__', text: t('new_file_group_new') });
    if (file && file.group) groupSelect.value = file.group;

    const newGroupWrap = body.createDiv({ cls: 'xsv-file-new-group' });
    newGroupWrap.style.display = 'none';
    newGroupWrap.createDiv({ cls: 'xsv-label', text: t('new_file_group_name') });
    const newGroupInput = newGroupWrap.createEl('input', { cls: 'xsv-input', type: 'text' });
    groupSelect.addEventListener('change', () => {
      newGroupWrap.style.display = groupSelect.value === '__new__' ? '' : 'none';
    });

    body.createDiv({ cls: 'xsv-hint xsv-file-plaintext-warn', text: t('new_file_plaintext_warn') });
    const errorBox = body.createDiv({ cls: 'xsv-error' });
    errorBox.style.display = 'none';
    const actions = body.createDiv({ cls: 'xsv-modal-actions' });
    const cancel = actions.createEl('button', { cls: 'xsv-btn', text: t('btn_cancel') });
    cancel.addEventListener('click', () => this.close());
    const submit = actions.createEl('button', {
      cls: 'xsv-btn xsv-btn-primary',
      text: t(renaming ? 'btn_save' : 'btn_new_file'),
    });
    submit.addEventListener('click', () => {
      void (async () => {
        const groupValue = groupSelect.value === '__new__' ? newGroupInput.value : groupSelect.value;
        const result = renaming
          ? await this.plugin.renameVaultFile(file.path, nameInput.value, groupValue)
          : await this.plugin.createVaultFile(nameInput.value, groupValue);
        if (result && result.ok) {
          this.close();
          return;
        }
        const reason = result && result.reason;
        errorBox.style.display = '';
        errorBox.setText(
          reason === 'exists'
            ? t('err_file_name_exists')
            : reason === 'invalid'
              ? t('err_file_name_invalid')
              : t('err_file_name_invalid')
        );
      })();
    });
  }

  onClose() {
    this.contentEl.empty();
  }
}

/* ------------------------------------------------------------------ */
/* 主插件类                                                            */
/* ------------------------------------------------------------------ */
class XUSecretVault extends Plugin {
  settings = {};
  cryptoApi = null;
  sessionKey = null;
  sessionSalt = null;
  sessionIterations = KDF_ITERATIONS;
  // v3：sessionKey = DEK（内容密钥）；sessionKek = 主密码包裹密钥
  sessionKek = null;
  rawDek = null;
  rawMasterKey = null;
  sessionFileId = null;
  sessionFileIdBase64 = '';
  sessionFormatVersion = FORMAT_VERSION;
  sessionRecovery = null;
  sessionRecoveryCode = null;
  sessionLegacyKey = null;
  batch = null;
  batchActive = false;
  batchAbortRequested = false;
  lastBatchResult = null;
  pendingRecovery = null;
  entries = [];
  notes = [];
  contentVersion = 0;
  vaultState = 'unknown';
  idleDeadline = 0;
  clipboardTimer = 0;
  clipboardText = null;

  writeChain = Promise.resolve();
  sessionGeneration = 0;
  knownBlobHash = null;
  reverifyChallenge = null;
  lastReverifyError = '';
  failureCount = 0;
  blockedUntil = 0;
  hiddenAt = 0;
  hiddenAtWall = 0;
  idleDeadlineWall = 0;
  countdownDeadline = 0;
  countdownDeadlineWall = 0;
  countdownSeconds = 0;
  countdownTimer = 0;
  suspendReason = '';
  suspended = false;
  conflictPending = false;
  conflictPath = '';
  lastUnlockError = '';
  openViews = new Set();
  vaultSources = [];
  selectedVaultPath = '';
  v1UpgradeWarned = false;

  // 多文件：列表、当前文件、每文件独立密钥/哈希/冲突状态
  vaultFiles = [];
  selectedFilePath = '';
  fileSessions = new Map();
  sessionPassword = '';
  fileLoading = '';

  // 统一单调时钟：退避、空闲与后台计时都不受系统时间跳变影响
  nowMs() {
    return monotonicNow();
  }

  // 供测试遍历：两语言并集的全部 i18n 词条键
  listI18nKeys() {
    return Array.from(new Set([...Object.keys(I18N.zh), ...Object.keys(I18N.en)]));
  }

  t(key, vars) {
    const lang = this.settings && this.settings.language === 'en' ? 'en' : 'zh';
    const dict = I18N[lang] || I18N.zh;
    let value = dict[key];
    if (value === undefined) value = I18N.zh[key];
    if (value === undefined) value = key;
    if (vars && typeof value === 'string') {
      for (const name of Object.keys(vars)) {
        value = value.split('{' + name + '}').join(String(vars[name]));
      }
    }
    return value;
  }

  async onload() {
    await this.loadSettings();
    this.cryptoApi = getWebCrypto();

    this.registerView(VIEW_TYPE, (leaf) => new SecretVaultView(leaf, this));
    this.settingTab = new SecretVaultSettingTab(this.app, this);
    this.addSettingTab(this.settingTab);

    this.addRibbonIcon('lock', this.t('cmd_open'), () => {
      void this.openVaultView();
    });

    this.addCommand({
      id: 'open-vault',
      name: this.t('cmd_open'),
      callback: () => {
        void this.openVaultView();
      },
    });
    this.addCommand({
      id: 'lock-vault',
      name: this.t('cmd_lock'),
      callback: () => {
        if (this.isUnlocked()) {
          this.lock();
          new Notice(this.t('notice_locked_done'), 3000);
        } else {
          new Notice(this.t('notice_locked'), 3000);
        }
      },
    });
    this.registerInterval(globalThis.setInterval(() => this.checkAutoLock(), 15000));

    // 启动清理：删除上次异常退出可能留下的本插件临时密文（*.tmp*）
    void this.cleanupStaleTempFiles();

    // 切后台 / 失焦：立即遮罩并清屏；按设置倒计时锁定，hidden 超过 60 秒仍强制锁定
    if (typeof document !== 'undefined' && document && typeof document.addEventListener === 'function') {
      this.registerDomEvent(document, 'visibilitychange', () => this.handleVisibilityChange());
    }
    if (typeof window !== 'undefined' && window && typeof window.addEventListener === 'function') {
      this.registerDomEvent(window, 'blur', () => this.handleWindowBlur());
      this.registerDomEvent(window, 'focus', () => this.handleWindowFocus());
    }

    this.app.workspace.onLayoutReady(() => {
      if (!this.cryptoApi) new Notice(this.t('err_crypto_unavailable'), 10000);
      // 旧版侧栏视图类型已不再注册：清掉工作区里残留的旧 leaf，
      // 避免它作为未知视图残留在侧栏，与新整页入口形成两个入口
      const cleanupLegacy = () => {
        const targets = new Set();
        try {
          for (const leaf of this.app.workspace.getLeavesOfType(LEGACY_VIEW_TYPE) || []) targets.add(leaf);
        } catch (error) {
          /* ignore */
        }
        // 兼容恢复成占位视图（getLeavesOfType 匹配不到）的情况
        try {
          this.app.workspace.iterateAllLeaves((leaf) => {
            let type = '';
            try {
              type = leaf.view && typeof leaf.view.getViewType === 'function' ? leaf.view.getViewType() : '';
            } catch (error) {
              type = '';
            }
            if (type === LEGACY_VIEW_TYPE) targets.add(leaf);
          });
        } catch (error) {
          /* ignore */
        }
        for (const leaf of targets) {
          try {
            leaf.detach();
          } catch (error) {
            /* ignore */
          }
        }
      };
      cleanupLegacy();
      globalThis.setTimeout(cleanupLegacy, 500);
    });

    console.debug('[' + PLUGIN_ID + '] loaded v' + this.manifest.version);
  }

  onunload() {
    this.lock();
    this.clearClipboardTimer();
  }

  /* ---------------- 设置与路径 ---------------- */

  async loadSettings() {
    this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
    if (this.settings.language !== 'en') this.settings.language = 'zh';
    this.settings.backgroundLockSeconds = normalizeBackgroundSeconds(this.settings.backgroundLockSeconds);
    // 目录与界面偏好：只保留字符串/数组，不含任何笔记内容或密码
    this.settings.vaultDir = normalizeVaultDir(this.settings.vaultDir);
    this.settings.selectedFile = normalizeRelativePath(this.settings.selectedFile);
    this.settings.collapsedGroups = normalizeCollapsedGroups(this.settings.collapsedGroups);
    // 只保留 { name, mode }；旧格式/脏数据自动归一化，绝不携带任何密码或笔记内容
    this.settings.columnRules = normalizeColumnRules(this.settings.columnRules);
    // 0.3.1 默认的 12 条预置规则不算用户自定义：升级到 0.3.2 时静默清空，回到全明文
    if (isLegacyDefaultColumnRules(this.settings.columnRules)) this.settings.columnRules = [];
  }

  getBackgroundLockSeconds() {
    return normalizeBackgroundSeconds(this.settings.backgroundLockSeconds);
  }

  async saveSettings() {
    await this.saveData(this.settings);
  }

  /* ---------------- 列显示规则 ---------------- */

  getColumnRules() {
    return normalizeColumnRules(this.settings.columnRules);
  }

  // 精确匹配 > 包含匹配（取最长的规则名）> 未命中按明文
  getColumnMode(header) {
    const text = String(header == null ? '' : header).trim().toLowerCase();
    if (!text) return 'plain';
    const rules = this.getColumnRules();
    const exact = rules.filter((rule) => rule.name.toLowerCase() === text)[0];
    if (exact) return exact.mode;
    let best = null;
    for (const rule of rules) {
      const name = rule.name.toLowerCase();
      if (text.indexOf(name) >= 0 && (!best || name.length > best.name.length)) {
        best = { name, mode: rule.mode };
      }
    }
    return best ? best.mode : 'plain';
  }

  async saveColumnRules(rules) {
    this.settings.columnRules = normalizeColumnRules(rules);
    await this.saveSettings();
    // 立即重渲染当前笔记表格，不要求重启或重新解锁
    this.refreshViews();
    return this.settings.columnRules;
  }

  async addColumnRule(name, mode) {
    const cleanName = normalizeRuleName(name);
    if (!cleanName) {
      new Notice(this.t('notice_rule_name_empty'), 3000);
      return { ok: false, reason: 'empty' };
    }
    const normalizedMode = COLUMN_RULE_MODES.indexOf(mode) >= 0 ? mode : 'plain';
    const rules = this.getColumnRules();
    const existing = rules.filter((rule) => rule.name.toLowerCase() === cleanName.toLowerCase())[0];
    if (existing) {
      existing.mode = normalizedMode;
      await this.saveColumnRules(rules);
      return { ok: true, merged: true, rules: this.settings.columnRules };
    }
    if (rules.length >= COLUMN_RULE_LIMIT) {
      new Notice(this.t('notice_rule_limit', { limit: COLUMN_RULE_LIMIT }), 4000);
      return { ok: false, reason: 'limit' };
    }
    rules.push({ name: cleanName, mode: normalizedMode });
    await this.saveColumnRules(rules);
    return { ok: true, rules: this.settings.columnRules };
  }

  async updateColumnRule(index, patch) {
    const rules = this.getColumnRules();
    if (index < 0 || index >= rules.length) return { ok: false, reason: 'missing' };
    const target = rules[index];
    if (patch && patch.name !== undefined) {
      const cleanName = normalizeRuleName(patch.name);
      if (!cleanName) {
        new Notice(this.t('notice_rule_name_empty'), 3000);
        return { ok: false, reason: 'empty' };
      }
      target.name = cleanName;
    }
    if (patch && patch.mode !== undefined) {
      target.mode = COLUMN_RULE_MODES.indexOf(patch.mode) >= 0 ? patch.mode : 'plain';
    }
    await this.saveColumnRules(rules);
    return { ok: true, rules: this.settings.columnRules };
  }

  async deleteColumnRule(index) {
    const rules = this.getColumnRules();
    if (index < 0 || index >= rules.length) return { ok: false, reason: 'missing' };
    rules.splice(index, 1);
    await this.saveColumnRules(rules);
    return { ok: true, rules: this.settings.columnRules };
  }

  // 默认规则是空表：此操作清空全部自定义规则，回到「全明文」
  async applyDefaultColumnRules() {
    this.settings.columnRules = cloneDefaultColumnRules();
    await this.saveSettings();
    this.refreshViews();
    new Notice(this.t('notice_rules_restored'), 3000);
    return this.settings.columnRules;
  }

  // 清空规则必须二次确认，避免误清自定义规则
  requestRestoreDefaultColumnRules(onDone) {
    this.confirmModal = new ConfirmModal(
      this.app,
      this.t('btn_restore_default_rules'),
      this.t('confirm_restore_rules'),
      this.t('btn_restore_default_rules'),
      this.t('btn_cancel'),
      () => {
        void this.applyDefaultColumnRules().then(() => {
          if (typeof onDone === 'function') onDone();
        });
      }
    );
    this.confirmModal.open();
    return this.confirmModal;
  }

  normalizeVaultPath(raw) {
    let path = String(raw == null ? '' : raw).trim().replace(/\\/g, '/');
    const parts = path.split('/').filter((part) => part && part !== '.' && part !== '..');
    path = parts.join('/');
    if (!path) path = DEFAULT_VAULT_PATH;
    if (!/\.enc$/i.test(path)) path += '.enc';
    return path;
  }

  getVaultDir() {
    return normalizeVaultDir(this.settings.vaultDir);
  }

  defaultVaultFilePath() {
    return this.normalizeVaultPath(this.getVaultDir() + '/' + DEFAULT_FILE_NAME + '.enc');
  }

  // 当前路径优先级：已解锁的当前文件 > 解锁前显式选的冲突副本 > 上次选中的文件 > 旧版默认路径
  getVaultPath() {
    if (this.selectedFilePath) return this.normalizeVaultPath(this.selectedFilePath);
    const selected = String(this.selectedVaultPath || '').trim();
    if (selected) return this.normalizeVaultPath(selected);
    if (this.settings.selectedFile) return this.normalizeVaultPath(this.settings.selectedFile);
    return this.normalizeVaultPath(this.settings.vaultPath);
  }

  // 冲突副本一律只读；正式文件（含旧版 xu-secrets.enc）可写
  isReadOnlyCopy() {
    return CONFLICT_COPY_RE.test(this.getVaultPath());
  }

  // 把当前内存态（密钥、哈希、冲突标记）存回该文件的独立记录
  rememberCurrentFileSession() {
    if (!this.selectedFilePath || !this.sessionKey || !this.sessionSalt) return;
    const saltBase64 = bytesToBase64(this.sessionSalt);
    this.fileSessions.set(this.normalizeVaultPath(this.selectedFilePath), {
      key: this.sessionKey,
      kek: this.sessionKek,
      rawDek: this.rawDek,
      rawMasterKey: this.rawMasterKey,
      fileId: this.sessionFileId,
      fileIdBase64: this.sessionFileIdBase64,
      formatVersion: this.sessionFormatVersion,
      legacyKey: this.sessionLegacyKey,
      recovery: this.sessionRecovery,
      recoveryCode: this.sessionRecoveryCode,
      salt: this.sessionSalt,
      saltBase64,
      iterations: this.sessionIterations,
      hash: this.knownBlobHash,
      conflictPending: this.conflictPending,
      conflictPath: this.conflictPath,
    });
  }

  // 当前会话的 v3 写入上下文
  currentV3Context() {
    if (!this.rawDek || !this.sessionKek || !this.sessionSalt || !this.sessionFileId) {
      throw new Error(this.t('err_session_expired'));
    }
    return {
      rawDek: this.rawDek,
      kek: this.sessionKek,
      salt: this.sessionSalt,
      iterations: this.sessionIterations,
      fileId: this.sessionFileId,
      rawMasterKey: this.rawMasterKey,
      recovery: this.sessionRecovery,
      recoveryCode: this.sessionRecoveryCode,
    };
  }

  // 把一个已解密/已构造的 v3 会话装进当前插件状态
  async applyV3Session(session) {
    const cryptoObj = this.requireCrypto();
    this.sessionFormatVersion = FORMAT_VERSION;
    this.sessionLegacyKey = null;
    this.rawDek = session.rawDek;
    this.rawMasterKey = session.rawMasterKey;
    this.sessionKek = session.kek;
    this.sessionSalt = session.salt;
    this.sessionIterations = session.iterations;
    this.sessionFileId = session.fileId;
    this.sessionFileIdBase64 = session.fileIdBase64;
    this.sessionRecovery = session.recovery || null;
    this.sessionRecoveryCode = session.recoveryCode || null;
    this.sessionKey = await importAesGcmKey(cryptoObj, session.rawDek);
    this.entries = session.data.entries || [];
    this.notes = session.data.notes || [];
    this.contentVersion = Number(session.data.contentVersion || 0);
    this.knownBlobHash = session.hash != null ? session.hash : null;
    this.sessionPassword = session.password;
  }

  // legacy 会话（迁移失败时仍可继续读写旧格式）
  applyLegacySession(session) {
    this.sessionFormatVersion = Number(session.formatVersion);
    this.sessionLegacyKey = session.key;
    this.sessionKey = session.key;
    this.rawDek = null;
    this.rawMasterKey = null;
    this.sessionKek = null;
    this.sessionSalt = session.salt;
    this.sessionIterations = session.iterations;
    this.sessionFileId = null;
    this.sessionFileIdBase64 = '';
    this.sessionRecovery = session.recovery || null;
    this.sessionRecoveryCode = session.recoveryCode || null;
    this.entries = session.data.entries || [];
    this.notes = session.data.notes || [];
    this.contentVersion = Number(session.data.contentVersion || 0);
    this.knownBlobHash = session.hash != null ? session.hash : null;
    this.sessionPassword = session.password;
  }

  // 递归扫描保险库目录下所有 .enc（含子目录），外加旧版 <vault>/xu-secrets.enc
  async scanVaultFiles() {
    const adapter = this.app.vault.adapter;
    const dir = this.getVaultDir();
    const files = [];
    const seen = new Set();
    const walk = async (relativeDir) => {
      let listed = null;
      try {
        listed = await adapter.list(relativeDir);
      } catch (error) {
        return;
      }
      if (!listed) return;
      const filePaths = Array.isArray(listed.files) ? listed.files : [];
      for (const filePath of filePaths) {
        const full = normalizeRelativePath(filePath);
        if (!full || seen.has(full)) continue;
        const base = full.slice(full.lastIndexOf('/') + 1);
        if (!/\.enc$/i.test(base) || CONFLICT_COPY_RE.test(base) || /\.bak$/i.test(base)) continue;
        if (/\.tmp-[0-9]{8}-[0-9]{6}-[A-Za-z0-9]{1,8}$/.test(base)) continue;
        let mtime = 0;
        try {
          const stat = typeof adapter.stat === 'function' ? await adapter.stat(full) : null;
          mtime = stat && typeof stat.mtime === 'number' ? stat.mtime : stat && stat.mtime ? new Date(stat.mtime).getTime() : 0;
        } catch (error) {
          mtime = 0;
        }
        const parent = full.slice(0, Math.max(0, full.lastIndexOf('/')));
        let group = '';
        if (parent === dir) group = '';
        else if (parent.indexOf(dir + '/') === 0) group = parent.slice(dir.length + 1);
        else group = parent;
        seen.add(full);
        files.push({
          path: full,
          name: base.replace(/\.enc$/i, ''),
          group,
          mtime,
          legacy: full === this.normalizeVaultPath(this.settings.vaultPath) && parent !== dir,
        });
      }
      const folders = Array.isArray(listed.folders) ? listed.folders : [];
      for (const folder of folders) {
        await walk(normalizeRelativePath(folder));
      }
    };
    await walk(dir);
    // 旧版默认文件：在保险库目录之外，单独补进来，不迁移、不删除
    const legacyPath = this.normalizeVaultPath(this.settings.vaultPath);
    if (legacyPath && !seen.has(legacyPath)) {
      let exists = false;
      try {
        exists = await adapter.exists(legacyPath);
      } catch (error) {
        exists = false;
      }
      if (exists) {
        const base = legacyPath.slice(legacyPath.lastIndexOf('/') + 1).replace(/\.enc$/i, '');
        let mtime = 0;
        try {
          const stat = typeof adapter.stat === 'function' ? await adapter.stat(legacyPath) : null;
          mtime = stat && typeof stat.mtime === 'number' ? stat.mtime : 0;
        } catch (error) {
          mtime = 0;
        }
        seen.add(legacyPath);
        files.push({ path: legacyPath, name: base, group: '', mtime, legacy: true });
      }
    }
    // 分组在前（按名称），「未分组」放最后；组内按文件名排序
    files.sort((left, right) => {
      if (left.group !== right.group) {
        if (!left.group) return 1;
        if (!right.group) return -1;
        return left.group.localeCompare(right.group, 'zh');
      }
      return left.name.localeCompare(right.name, 'zh');
    });
    this.vaultFiles = files;
    // 默认文件：当前选中 > 上次选中 > 旧版文件 > 列表第一个
    const existing = new Set(files.map((item) => item.path));
    let chosen = '';
    if (this.selectedFilePath && existing.has(this.normalizeVaultPath(this.selectedFilePath))) {
      chosen = this.normalizeVaultPath(this.selectedFilePath);
    } else if (this.settings.selectedFile && existing.has(this.normalizeVaultPath(this.settings.selectedFile))) {
      chosen = this.normalizeVaultPath(this.settings.selectedFile);
    } else if (existing.has(legacyPath)) {
      chosen = legacyPath;
    } else if (files.length) {
      chosen = files[0].path;
    }
    this.settings.selectedFile = chosen || this.settings.selectedFile || '';
    return files;
  }

  getGroupOptions() {
    const groups = new Set();
    for (const file of this.vaultFiles) {
      if (file.group) groups.add(file.group);
    }
    return Array.from(groups).sort((left, right) => left.localeCompare(right, 'zh'));
  }

  // 解锁前枚举候选库文件：当前文件 + 同 stem 的 conflict 副本，交给用户显式选择
  async scanVaultSources() {
    const adapter = this.app.vault.adapter;
    const canonical = this.getVaultPath();
    let canonicalExists = false;
    try {
      canonicalExists = await adapter.exists(canonical);
    } catch (error) {
      /* ignore */
    }
    const extras = [];
    if (typeof adapter.list === 'function') {
      const slash = canonical.lastIndexOf('/');
      const dir = slash < 0 ? '' : canonical.slice(0, slash);
      const base = slash < 0 ? canonical : canonical.slice(slash + 1);
      const stem = escapeRegExp(base.replace(/\.enc$/i, ''));
      // 允许一个或多个 .conflict-YYYYMMDD-HHMMSS[-n] 段，覆盖嵌套冲突副本
      const sourceRe = new RegExp(
        '^' + stem + '((?:\\.conflict-[0-9]{8}-[0-9]{6}(?:-[0-9]+)?)+)\\.enc$'
      );
      let listed = null;
      try {
        listed = await adapter.list(dir);
      } catch (error) {
        listed = null;
      }
      if (listed && Array.isArray(listed.files)) {
        for (const file of listed.files) {
          const name = String(file).slice(String(file).lastIndexOf('/') + 1);
          const match = sourceRe.exec(name);
          if (!match) continue;
          const stamps = match[1].match(/[0-9]{8}-[0-9]{6}/g) || [];
          extras.push({
            full: dir ? dir + '/' + name : name,
            stamp: stamps.length ? stamps[stamps.length - 1] : '',
          });
        }
      }
    }
    // 正式库固定第一；其余按最后一次冲突时间倒序（同一时间再按文件名稳定排序）
    extras.sort((left, right) => right.stamp.localeCompare(left.stamp) || left.full.localeCompare(right.full));
    const sources = (canonicalExists ? [canonical] : []).concat(extras.map((item) => item.full));
    this.vaultSources = sources;
    this.refreshViews();
    return sources;
  }

  requireCrypto() {
    if (!this.cryptoApi) this.cryptoApi = getWebCrypto();
    if (!this.cryptoApi) throw new Error(this.t('err_crypto_unavailable'));
    return this.cryptoApi;
  }

  isUnlocked() {
    return !!this.sessionKey;
  }

  async detectVaultExists() {
    try {
      const files = await this.scanVaultFiles();
      this.vaultState = files.length ? 'present' : 'absent';
    } catch (error) {
      console.error('[' + PLUGIN_ID + '] detect vault failed:', error);
      // 读取异常不能当成"文件不存在"，否则会引导用户创建并覆盖同名旧库
      this.vaultState = 'error';
    }
    this.refreshViews();
    void this.scanVaultSources();
    return this.vaultState;
  }

  /* ---------------- 加密原语 ---------------- */

  async deriveKeyFromText(text, salt, iterations) {
    const cryptoObj = this.requireCrypto();
    const material = await cryptoObj.subtle.importKey(
      'raw',
      utf8Encode(text),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );
    return cryptoObj.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: KDF_HASH },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async deriveKey(password, salt, iterations) {
    return this.deriveKeyFromText(normalizePassword(password), salt, iterations);
  }

  async hashText(text) {
    const cryptoObj = this.requireCrypto();
    const digest = await cryptoObj.subtle.digest('SHA-256', utf8Encode(text));
    return bytesToBase64(digest);
  }

  // v2 旧信封：仅用于迁移失败后继续以旧格式工作的后备路径
  async encryptLegacyToEnvelope(entries, key, salt, iterations, notes) {
    const cryptoObj = this.requireCrypto();
    const iv = randomBytes(cryptoObj, IV_BYTES);
    const saltBase64 = bytesToBase64(salt);
    // updatedAt 与笔记体都放进加密载荷，不在信封头上明文暴露
    const plaintext = JSON.stringify({
      version: V2_FORMAT_VERSION,
      contentVersion: CONTENT_VERSION,
      updatedAt: new Date().toISOString(),
      entries,
      notes: notes || [],
    });
    const ciphertext = await cryptoObj.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: buildAad(
          AAD_PREFIX,
          V2_FORMAT_VERSION,
          KDF_ALGO,
          iterations,
          saltBase64,
          CIPHER_ALGO
        ),
        tagLength: TAG_LENGTH,
      },
      key,
      utf8Encode(plaintext)
    );
    return {
      formatVersion: V2_FORMAT_VERSION,
      kdf: { algo: KDF_ALGO, iterations, salt: saltBase64 },
      cipher: { algo: CIPHER_ALGO, iv: bytesToBase64(iv) },
      payload: bytesToBase64(ciphertext),
    };
  }

  async questionTextHash(questions) {
    const cryptoObj = this.requireCrypto();
    const digest = await cryptoObj.subtle.digest(
      'SHA-256',
      utf8Encode((questions || []).map(normalizeQuestionText).join('\n'))
    );
    return bytesToBase64(digest);
  }

  async buildRecoveryBlock(rawMasterKey, questions, answers) {
    const cryptoObj = this.requireCrypto();
    const salt = randomBytes(cryptoObj, SALT_BYTES);
    const iterations = RECOVERY_KDF_ITERATIONS;
    const saltBase64 = bytesToBase64(salt);
    const normalizedQuestions = (questions || []).map(normalizeQuestionText);
    const answerKey = await this.deriveKeyFromText(
      joinSecurityAnswers(answers),
      salt,
      iterations
    );
    const qHash = await this.questionTextHash(normalizedQuestions);
    const wrappedDek = await wrapRawKey(
      cryptoObj,
      answerKey,
      rawMasterKey,
      buildWrapAadV3('recovery', FORMAT_VERSION, KDF_ALGO, iterations, saltBase64, CIPHER_ALGO, qHash)
    );
    return {
      kdf: { algo: KDF_ALGO, iterations, salt: saltBase64 },
      questions: normalizedQuestions,
      wrappedDek,
    };
  }

  async buildRecoveryCodeBlock(rawMasterKey, code) {
    const cryptoObj = this.requireCrypto();
    const salt = randomBytes(cryptoObj, SALT_BYTES);
    const iterations = RECOVERY_CODE_KDF_ITERATIONS;
    const saltBase64 = bytesToBase64(salt);
    const codeKey = await this.deriveKeyFromText(
      normalizeRecoveryCode(code),
      salt,
      iterations
    );
    const wrappedDek = await wrapRawKey(
      cryptoObj,
      codeKey,
      rawMasterKey,
      buildWrapAadV3('recovery-code', FORMAT_VERSION, KDF_ALGO, iterations, saltBase64, CIPHER_ALGO)
    );
    return {
      kdf: { algo: KDF_ALGO, iterations, salt: saltBase64 },
      wrappedDek,
    };
  }

  // v3 信封：payload 用 DEK；DEK 同时被主密码 KEK 与主密钥包裹；
  // 主密钥再被密保答案 / 恢复码包裹，因此恢复一次即可覆盖全部文件。
  async buildV3Envelope(entries, notes, ctx) {
    const cryptoObj = this.requireCrypto();
    const saltBase64 = bytesToBase64(ctx.salt);
    const fileIdBase64 =
      typeof ctx.fileId === 'string' ? ctx.fileId : bytesToBase64(ctx.fileId);
    const iterations = Number(ctx.iterations);
    const dekKey = await importAesGcmKey(cryptoObj, ctx.rawDek);
    const masterKey = await importAesGcmKey(cryptoObj, ctx.rawMasterKey);
    let ivBase64;
    let payloadBase64;
    if (ctx.payloadReuse && typeof ctx.payloadReuse.payload === 'string') {
      // 快速改密：DEK 不变、内容不重加密，仅换 salt/KEK 重包包裹层
      ivBase64 = String(ctx.payloadReuse.iv);
      payloadBase64 = String(ctx.payloadReuse.payload);
    } else {
      const iv = randomBytes(cryptoObj, IV_BYTES);
      const plaintext = JSON.stringify({
        contentVersion: CONTENT_VERSION,
        updatedAt: new Date().toISOString(),
        entries,
        notes: notes || [],
      });
      const ciphertext = await cryptoObj.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv,
          additionalData: buildPayloadAadV3(FORMAT_VERSION, fileIdBase64, CIPHER_ALGO),
          tagLength: TAG_LENGTH,
        },
        dekKey,
        utf8Encode(plaintext)
      );
      ivBase64 = bytesToBase64(iv);
      payloadBase64 = bytesToBase64(ciphertext);
    }
    const wrappedDek = await wrapRawKey(
      cryptoObj,
      ctx.kek,
      ctx.rawDek,
      buildWrapAadV3('password', FORMAT_VERSION, KDF_ALGO, iterations, saltBase64, CIPHER_ALGO)
    );
    const wrappedMasterKey = await wrapRawKey(
      cryptoObj,
      ctx.kek,
      ctx.rawMasterKey,
      buildWrapAadV3('master', FORMAT_VERSION, KDF_ALGO, iterations, saltBase64, CIPHER_ALGO)
    );
    const wrappedDekByMaster = await wrapRawKey(
      cryptoObj,
      masterKey,
      ctx.rawDek,
      buildMasterDekAad(fileIdBase64, CIPHER_ALGO)
    );
    const envelope = {
      formatVersion: FORMAT_VERSION,
      fileId: fileIdBase64,
      kdf: { algo: KDF_ALGO, iterations, salt: saltBase64 },
      cipher: { algo: CIPHER_ALGO, iv: ivBase64 },
      wrappedDek,
      wrappedMasterKey,
      wrappedDekByMaster,
      payload: payloadBase64,
    };
    if (ctx.recovery) envelope.recovery = ctx.recovery;
    if (ctx.recoveryCode) envelope.recoveryCode = ctx.recoveryCode;
    return envelope;
  }

  validateEnvelope(envelope) {
    if (!envelope || typeof envelope !== 'object') throw new Error('invalid envelope');
    const formatVersion = Number(envelope.formatVersion);
    // 已知版本之外一律报「版本不支持」，不要混成密码错误
    if (
      formatVersion !== FORMAT_VERSION &&
      formatVersion !== V2_FORMAT_VERSION &&
      formatVersion !== LEGACY_FORMAT_VERSION
    ) {
      const error = new Error('unsupported formatVersion');
      error.code = 'xsv-version-unsupported';
      throw error;
    }
    if (!envelope.kdf || typeof envelope.kdf !== 'object') throw new Error('invalid kdf');
    if (envelope.kdf.algo !== KDF_ALGO) throw new Error('invalid kdf algo');
    if (formatVersion <= V2_FORMAT_VERSION && Number(envelope.kdf.iterations) !== KDF_ITERATIONS) {
      throw new Error('invalid kdf iterations');
    }
    if (formatVersion === FORMAT_VERSION && Number(envelope.kdf.iterations) < 100000) {
      throw new Error('invalid kdf iterations');
    }
    if (typeof envelope.kdf.salt !== 'string') throw new Error('invalid salt');
    if (base64ToBytes(envelope.kdf.salt).length !== SALT_BYTES) throw new Error('invalid salt length');
    if (!envelope.cipher || typeof envelope.cipher !== 'object') throw new Error('invalid cipher');
    // cipher.algo 参与 AAD，这里也断言只能是 AES-256-GCM
    if (envelope.cipher.algo !== CIPHER_ALGO) throw new Error('invalid cipher algo');
    if (typeof envelope.cipher.iv !== 'string') throw new Error('invalid iv');
    if (base64ToBytes(envelope.cipher.iv).length !== IV_BYTES) throw new Error('invalid iv length');
    if (typeof envelope.payload !== 'string' || !envelope.payload) throw new Error('invalid payload');
    if (formatVersion === FORMAT_VERSION) {
      if (typeof envelope.fileId !== 'string') throw new Error('invalid fileId');
      if (base64ToBytes(envelope.fileId).length !== FILE_ID_BYTES) throw new Error('invalid fileId length');
      for (const field of ['wrappedDek', 'wrappedMasterKey', 'wrappedDekByMaster']) {
        const blob = envelope[field];
        if (!blob || typeof blob !== 'object') throw new Error('invalid ' + field);
        if (typeof blob.iv !== 'string' || base64ToBytes(blob.iv).length !== IV_BYTES) {
          throw new Error('invalid ' + field + ' iv');
        }
        if (typeof blob.ciphertext !== 'string' || !blob.ciphertext) {
          throw new Error('invalid ' + field + ' ciphertext');
        }
      }
      if (envelope.recovery != null) {
        const recovery = envelope.recovery;
        if (!recovery.kdf || typeof recovery.kdf !== 'object') throw new Error('invalid recovery kdf');
        if (recovery.kdf.algo !== KDF_ALGO) throw new Error('invalid recovery kdf algo');
        if (Number(recovery.kdf.iterations) < 100000) throw new Error('invalid recovery iterations');
        if (typeof recovery.kdf.salt !== 'string') throw new Error('invalid recovery salt');
        if (!Array.isArray(recovery.questions) || recovery.questions.length !== RECOVERY_QUESTIONS_COUNT) {
          throw new Error('invalid recovery questions');
        }
        if (!recovery.wrappedDek || typeof recovery.wrappedDek.ciphertext !== 'string') {
          throw new Error('invalid recovery wrappedDek');
        }
      }
      if (envelope.recoveryCode != null) {
        const code = envelope.recoveryCode;
        if (!code.kdf || typeof code.kdf !== 'object') throw new Error('invalid recoveryCode kdf');
        if (Number(code.kdf.iterations) < 10000) throw new Error('invalid recoveryCode iterations');
        if (!code.wrappedDek || typeof code.wrappedDek.ciphertext !== 'string') {
          throw new Error('invalid recoveryCode wrappedDek');
        }
      }
    }
    return envelope;
  }

  parseEnvelope(text) {
    return this.validateEnvelope(JSON.parse(text));
  }

  // v1 兼容的两种 AAD：0.1.1 用 v2 前缀并含 cipher.algo；0.1.0 用 v1 前缀且不含 cipher.algo
  legacyAadCandidates(envelope) {
    const iterations = Number(envelope.kdf.iterations);
    const saltBase64 = String(envelope.kdf.salt);
    return [
      buildAad(
        AAD_PREFIX,
        envelope.formatVersion,
        envelope.kdf.algo,
        iterations,
        saltBase64,
        envelope.cipher.algo
      ),
      utf8Encode(
        [AAD_PREFIX_V1, envelope.formatVersion, envelope.kdf.algo, String(iterations), saltBase64].join('|')
      ),
    ];
  }

  async decryptEnvelope(envelope, key) {
    const cryptoObj = this.requireCrypto();
    const formatVersion = Number(envelope.formatVersion);
    const iv = base64ToBytes(envelope.cipher.iv);
    const payload = base64ToBytes(envelope.payload);
    let decryptKey = key;
    if (formatVersion === FORMAT_VERSION) {
      if (decryptKey instanceof Uint8Array) decryptKey = await importAesGcmKey(cryptoObj, decryptKey);
      const plaintext = await cryptoObj.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv,
          additionalData: buildPayloadAadV3(
            FORMAT_VERSION,
            String(envelope.fileId),
            envelope.cipher.algo
          ),
          tagLength: TAG_LENGTH,
        },
        decryptKey,
        payload
      );
      return JSON.parse(utf8Decode(plaintext));
    }
    const iterations = Number(envelope.kdf.iterations);
    const saltBase64 = String(envelope.kdf.salt);
    const additionalDataList =
      formatVersion === LEGACY_FORMAT_VERSION
        ? this.legacyAadCandidates(envelope)
        : [
            buildAad(
              AAD_PREFIX,
              envelope.formatVersion,
              envelope.kdf.algo,
              iterations,
              saltBase64,
              envelope.cipher.algo
            ),
          ];
    let lastError = null;
    for (const additionalData of additionalDataList) {
      try {
        const plaintext = await cryptoObj.subtle.decrypt(
          { name: 'AES-GCM', iv, additionalData, tagLength: TAG_LENGTH },
          decryptKey,
          payload
        );
        return JSON.parse(utf8Decode(plaintext));
      } catch (error) {
        lastError = error;
      }
    }
    throw lastError || new Error('decrypt failed');
  }

  async readVaultText(path) {
    const adapter = this.app.vault.adapter;
    let size = null;
    if (typeof adapter.stat === 'function') {
      try {
        const stat = await adapter.stat(path);
        if (stat && typeof stat.size === 'number') size = stat.size;
      } catch (error) {
        size = null;
      }
    }
    // 8 MB 上限：避免超大文件把解密/整体加密拖死
    if (size !== null && size > MAX_VAULT_BYTES) throw new Error(this.t('err_vault_too_large'));
    const text = await adapter.read(path);
    if (utf8Encode(text).length > MAX_VAULT_BYTES) throw new Error(this.t('err_vault_too_large'));
    return text;
  }

  async ensureParentDir(path) {
    const adapter = this.app.vault.adapter;
    const slash = path.lastIndexOf('/');
    if (slash < 0) return;
    const segments = path.slice(0, slash).split('/').filter(Boolean);
    let current = '';
    for (const segment of segments) {
      current = current ? current + '/' + segment : segment;
      const exists = await adapter.exists(current);
      if (!exists) await adapter.mkdir(current);
    }
  }

  // 解密刚生成的密文并与预期条目/笔记逐字段比对（D-01：不能只比对字符串）
  async verifyEnvelopeText(text, key, expectedEntries, expectedNotes) {
    const envelope = this.parseEnvelope(text);
    const data = await this.decryptEnvelope(envelope, key);
    const payload = decodePayload(data);
    if (!payload) throw new Error(this.t('err_write_verify'));
    if (!sameJson(payload.entries, expectedEntries)) throw new Error(this.t('err_write_verify'));
    if (expectedNotes != null && !sameJson(payload.notes, expectedNotes)) throw new Error(this.t('err_write_verify'));
  }

  // 唯一临时文件名：避免多次写入或崩溃残留互相踩踏
  uniqueTempPath(path) {
    const cryptoObj = this.requireCrypto();
    const stamp = fileStamp(new Date());
    const tail = bytesToBase64(randomBytes(cryptoObj, 6)).replace(/[^a-zA-Z0-9]/g, '').slice(0, 8);
    return path + '.tmp-' + stamp + '-' + tail;
  }

  // 启动清理：只删本插件生成的临时文件，且只删创建超过 1 小时的残留
  // 命名严格限定为 <vault>.tmp-YYYYMMDD-HHMMSS-<1~8位字母数字>，避免误删用户文件或另一实例正在写的 tmp
  async cleanupStaleTempFiles() {
    const adapter = this.app.vault.adapter;
    if (typeof adapter.list !== 'function' || typeof adapter.remove !== 'function') return;
    const dirs = new Set();
    for (const file of this.vaultFiles) {
      const slash = file.path.lastIndexOf('/');
      dirs.add(slash < 0 ? '' : file.path.slice(0, slash));
    }
    const current = this.getVaultPath();
    const slash = current.lastIndexOf('/');
    dirs.add(slash < 0 ? '' : current.slice(0, slash));
    const now = Date.now();
    for (const dir of dirs) {
      let listed = null;
      try {
        listed = await adapter.list(dir);
      } catch (error) {
        continue;
      }
      if (!listed || !Array.isArray(listed.files)) continue;
      for (const file of listed.files) {
        const name = String(file).slice(String(file).lastIndexOf('/') + 1);
        const match = /^(.*)\.tmp-([0-9]{8})-([0-9]{6})-([A-Za-z0-9]{1,8})$/.exec(name);
        if (!match) continue;
        const createdAt = parseFileStamp(match[2], match[3]);
        // 时间戳解析失败或不足 1 小时：可能是另一实例正在写，保留
        if (!createdAt || now - createdAt < 3600000) continue;
        try {
          await adapter.remove(file);
        } catch (error) {
          /* ignore */
        }
      }
    }
  }

  conflictError() {
    const error = new Error('xsv-conflict');
    error.code = 'xsv-conflict';
    return error;
  }

  discardError() {
    const error = new Error(this.t('err_save_discarded'));
    error.discarded = true;
    return error;
  }

  // 原子写：唯一 .tmp（密文）→ 读回解密校验 → 旧库改名到 .bak → tmp 落位 → 终检 → 删 .bak
  // Obsidian 的 DataAdapter.rename 在目标已存在时会抛 "Destination file already exists!"，
  // 因此不能直接 rename(tmp, path)：必须先把旧文件改名让位，再让 tmp 顶上去。
  // options: { generation, guardExternal, mustNotExist, notes }
  async writeEnvelope(entries, key, salt, iterations, targetPath, trackHash, options) {
    const opts = options || {};
    const path = targetPath || this.getVaultPath();
    if (opts.generation != null && opts.generation !== this.sessionGeneration) throw this.discardError();
    const notes = opts.notes != null ? opts.notes : this.notes || [];

    const useV3 = opts.v3Ctx || (this.sessionFormatVersion === FORMAT_VERSION && !opts.legacy);
    let envelope;
    let verifyKey;
    if (useV3) {
      const ctx = opts.v3Ctx || this.currentV3Context();
      envelope = await this.buildV3Envelope(entries, notes, ctx);
      verifyKey = ctx.rawDek;
    } else {
      envelope = await this.encryptLegacyToEnvelope(entries, key, salt, iterations, notes);
      verifyKey = key;
    }
    const text = JSON.stringify(envelope, null, 2);
    if (utf8Encode(text).length > MAX_VAULT_BYTES) throw new Error(this.t('err_vault_too_large'));
    await this.verifyEnvelopeText(text, verifyKey, entries, notes);
    await this.ensureParentDir(path);

    const adapter = this.app.vault.adapter;
    const tmpPath = this.uniqueTempPath(path);
    const bakPath = path + '.bak';
    let backupText = null;
    let backupWritten = false;
    let movedOld = false;
    let renamed = false;
    let rollbackFailed = false;

    try {
      await adapter.write(tmpPath, text);
      const readBack = await adapter.read(tmpPath);
      if (readBack !== text) throw new Error(this.t('err_write_verify'));
      await this.verifyEnvelopeText(readBack, verifyKey, entries, notes);

      // rename 前再判一次 generation / suspended：锁定后的在途任务绝不再落盘
      if (opts.generation != null && (opts.generation !== this.sessionGeneration || this.suspended)) {
        throw this.discardError();
      }

      // rename 前最后一次重取哈希（TOCTOU 复核），并顺带拿到可用于回滚的旧密文
      let currentExists = false;
      let currentText = null;
      try {
        currentExists = await adapter.exists(path);
        if (currentExists) currentText = await adapter.read(path);
      } catch (error) {
        throw this.conflictError();
      }
      if (opts.mustNotExist && currentExists) throw new Error(this.t('err_vault_exists'));
      if (opts.guardExternal) {
        if (!currentExists || !this.knownBlobHash) throw this.conflictError();
        if ((await this.hashText(currentText)) !== this.knownBlobHash) throw this.conflictError();
      }

      if (currentExists) {
        backupText = currentText;
        // 清掉上次失败遗留的 .bak（当前密文已在内存，不会丢数据）
        if (await adapter.exists(bakPath)) await adapter.remove(bakPath);
        // 旧库改名到 .bak：既避开 rename 目标已存在，又保证旧数据始终有落点
        await adapter.rename(path, bakPath);
        backupWritten = true;
        movedOld = true;
      }

      await adapter.rename(tmpPath, path);
      renamed = true;

      const finalText = await adapter.read(path);
      if (finalText !== text) throw new Error(this.t('err_write_verify'));
      await this.verifyEnvelopeText(finalText, verifyKey, entries, notes);
      if (trackHash !== false) this.knownBlobHash = await this.hashText(finalText);
    } catch (error) {
      try {
        if (typeof adapter.remove === 'function') await adapter.remove(tmpPath);
      } catch (cleanupError) {
        /* 文件不存在时无需处理 */
      }
      try {
        if (movedOld) {
          // 旧库在 .bak：清掉可能残留的新文件后，把旧库改名回原位
          if (await adapter.exists(path)) await adapter.remove(path);
          await adapter.rename(bakPath, path);
          movedOld = false;
          backupWritten = false;
          if (trackHash !== false && backupText !== null) this.knownBlobHash = await this.hashText(backupText);
        } else if (renamed) {
          // 原文件本不存在：删掉写进去的新文件，恢复“不存在”状态
          await adapter.remove(path);
          if (trackHash !== false) this.knownBlobHash = null;
        }
      } catch (rollbackError) {
        rollbackFailed = true;
        console.error('[' + PLUGIN_ID + '] rollback failed:', rollbackError);
        // 回滚失败时保留 .bak，并在报错里给出恢复路径；原文件本不存在时没有 .bak，不得指向不存在的文件
        if (backupWritten && error && typeof error === 'object' && typeof error.message === 'string') {
          error.message = error.message + ' ' + this.t('err_rollback_kept', { path: bakPath });
        }
      }
      // 回滚成功或从未移动旧库时清理 .bak；回滚失败则保留供手动恢复
      if (backupWritten && !rollbackFailed) {
        try {
          await adapter.remove(bakPath);
        } catch (cleanupError) {
          /* ignore */
        }
      }
      throw this.normalizeWriteError(error, opts);
    }
    if (backupWritten && !opts.keepBackup) {
      try {
        await adapter.remove(bakPath);
      } catch (cleanupError) {
        /* ignore */
      }
    }
    return text;
  }

  // 把适配器/系统抛出的英文错误收成可读中文；本插件自己生成的提示原样保留
  normalizeWriteError(error, opts) {
    if (!error || typeof error !== 'object') return new Error(this.t('err_save_failed'));
    if (error.code === 'xsv-conflict' || error.discarded) return error;
    const message = errorMessage(error);
    const rollbackPrefix = this.t('err_rollback_prefix');
    const rollbackIndex = message.indexOf(rollbackPrefix);
    const rollbackNote = rollbackIndex >= 0 ? ' ' + message.slice(rollbackIndex) : '';
    if (opts && opts.mustNotExist && /Destination file already exists/i.test(message)) {
      return new Error(this.t('err_vault_exists'));
    }
    const localized = [
      this.t('err_write_verify'),
      this.t('err_vault_too_large'),
      this.t('err_vault_exists'),
      this.t('err_suspended'),
      this.t('err_conflict_editing_blocked'),
      this.t('err_conflict_copy_readonly'),
      this.t('err_save_discarded'),
    ];
    if (localized.indexOf(message) >= 0) return error;
    return new Error(this.t('err_save_failed') + rollbackNote);
  }

  // 写前哈希比对：文件被外部改过（或凭空出现/消失）就拒绝覆盖
  async detectExternalChange(path) {
    let exists = false;
    try {
      exists = await this.app.vault.adapter.exists(path);
    } catch (error) {
      return true;
    }
    if (!exists) return this.knownBlobHash !== null;
    if (!this.knownBlobHash) return true;
    try {
      const text = await this.readVaultText(path);
      return (await this.hashText(text)) !== this.knownBlobHash;
    } catch (error) {
      return true;
    }
  }

  async buildConflictPath(path) {
    const base = path.replace(/\.enc$/i, '');
    const stamp = fileStamp(new Date());
    let candidate = base + '.conflict-' + stamp + '.enc';
    let counter = 2;
    // 极端情况下同一秒多次冲突：追加序号避免覆盖
    while (await this.app.vault.adapter.exists(candidate)) {
      candidate = base + '.conflict-' + stamp + '-' + counter + '.enc';
      counter += 1;
    }
    return candidate;
  }

  // 串行化：读现有 → 合并 → 加密 → 写盘全部在 writeChain 内执行，入队前不计算 next
  async commitEntries(mutator) {
    return this.commitMutation(mutator, 'entries');
  }

  // 笔记保存与条目保存共用同一条串行化 + 冲突 + 原子写链路
  async saveNote(id, body) {
    return this.commitMutation((entries, notes) => {
      const index = notes.findIndex((item) => item.id === id);
      if (index < 0) throw new Error(this.t('err_note_missing'));
      const nextNotes = notes.map((item, itemIndex) =>
        itemIndex === index ? { ...item, body: String(body), updatedAt: new Date().toISOString() } : item
      );
      return { notes: nextNotes };
    }, 'notes');
  }

  async commitMutation(mutator, kind) {
    if (!this.isUnlocked()) throw new Error(this.t('notice_unlock_first'));
    if (this.batchActive) throw new Error(this.t('err_batch_busy', {
        current: this.batch ? this.batch.current : 0,
        total: this.batch ? this.batch.total : 0,
      }));
    if (this.suspended) throw new Error(this.t('err_suspended'));
    if (this.conflictPending) throw new Error(this.t('err_conflict_editing_blocked'));
    if (this.isReadOnlyCopy()) throw new Error(this.t('err_conflict_copy_readonly'));
    const generation = this.sessionGeneration;
    const key = this.sessionKey;
    const salt = this.sessionSalt;
    const iterations = this.sessionIterations;
    const path = this.getVaultPath();
    const job = () => this.runWriteJob(mutator, kind, generation, key, salt, iterations, path);
    const task = this.writeChain.then(job, job);
    this.writeChain = task.then(
      () => undefined,
      () => undefined
    );
    const result = await task;
    if (result && result.written) this.refreshViews();
    return result;
  }

  async runWriteJob(mutator, kind, generation, key, salt, iterations, path) {
    // 锁定/挂起后的待写任务直接丢弃，绝不把明文重新落盘
    const active = () => generation === this.sessionGeneration && this.sessionKey !== null && !this.suspended;
    if (!active()) return { written: false, discarded: true, unchanged: false, conflict: false };
    const outcome = mutator(this.entries, this.notes) || {};
    let nextEntries = this.entries;
    let nextNotes = this.notes;
    if (kind === 'notes') {
      if (!outcome.notes) return { written: false, discarded: false, unchanged: true, conflict: false };
      nextNotes = outcome.notes;
    } else {
      if (!outcome.entries) return { written: false, discarded: false, unchanged: true, conflict: false };
      nextEntries = outcome.entries;
    }
    if (await this.detectExternalChange(path)) {
      return this.handleConflict(nextEntries, nextNotes, key, salt, iterations, path, generation);
    }
    try {
      await this.writeEnvelope(nextEntries, key, salt, iterations, path, true, {
        generation,
        guardExternal: true,
        notes: nextNotes,
      });
    } catch (error) {
      // 加密期间同步端写入：改为另存 conflict 副本，绝不覆盖
      if (error && error.code === 'xsv-conflict') {
        return this.handleConflict(nextEntries, nextNotes, key, salt, iterations, path, generation);
      }
      throw error;
    }
    if (!active()) return { written: false, discarded: true, unchanged: false, conflict: false };
    this.entries = nextEntries;
    if (kind === 'notes') this.notes = nextNotes;
    this.rememberCurrentFileSession();
    return { written: true, discarded: false, unchanged: false, conflict: false };
  }

  // 冲突：原文件不动，本次改动另存副本；内存快照标记为过期，重载前禁止继续编辑
  async handleConflict(next, nextNotes, key, salt, iterations, path, generation) {
    if (generation !== this.sessionGeneration || this.sessionKey === null) {
      return { written: false, discarded: true, unchanged: false, conflict: false };
    }
    const conflictPath = await this.buildConflictPath(path);
    try {
      await this.writeEnvelope(next, key, salt, iterations, conflictPath, false, {
        generation,
        notes: nextNotes,
      });
    } catch (error) {
      if (error && error.discarded) {
        return { written: false, discarded: true, unchanged: false, conflict: false };
      }
      throw error;
    }
    this.conflictPending = true;
    this.conflictPath = conflictPath;
    this.rememberCurrentFileSession();
    // 明确告知：已另存副本、原文件未被覆盖；不更新 this.entries，避免继续基于旧快照编辑
    new Notice(this.t('notice_conflict_saved', { path: conflictPath }), 12000);
    this.refreshViews();
    void this.scanVaultSources();
    return { written: false, discarded: false, unchanged: false, conflict: true, conflictPath };
  }

  // 冲突后重载：用当前会话密钥重新读取磁盘；无法解密则直接锁定，要求重新输入主密码
  async reloadFromConflict() {
    if (!this.isUnlocked()) return false;
    try {
      const path = this.getVaultPath();
      const text = await this.readVaultText(path);
      const envelope = this.parseEnvelope(text);
      if (
        envelope.kdf.salt !== bytesToBase64(this.sessionSalt) ||
        Number(envelope.kdf.iterations) !== this.sessionIterations
      ) {
        this.lock();
        return false;
      }
      const data = await this.decryptEnvelope(envelope, this.sessionKey);
      const payload = decodePayload(data);
      if (!payload) throw new Error('invalid payload');
      this.entries = payload.entries.map((item, index) => normalizeStoredEntry(item, 'restored-' + index));
      let notes = payload.notes.map((item, index) => normalizeStoredNote(item, 'note-' + index));
      if (!notes.length) notes = [createDefaultNote()];
      this.notes = notes;
      this.contentVersion = payload.contentVersion;
      this.knownBlobHash = await this.hashText(text);
      this.conflictPending = false;
      this.conflictPath = '';
      this.resetIdleTimer();
      this.refreshViews();
      return true;
    } catch (error) {
      console.error('[' + PLUGIN_ID + '] reload after conflict failed:', error);
      this.lock();
      return false;
    }
  }

  /* ---------------- 批量改密 / 恢复码 / 密保问题 ---------------- */

  // 批量操作覆盖目录内全部正式 .enc（含子目录/分组），不含冲突副本
  batchTargetFiles() {
    const paths = new Set();
    for (const file of this.vaultFiles || []) paths.add(this.normalizeVaultPath(file.path));
    if (this.selectedFilePath) paths.add(this.normalizeVaultPath(this.selectedFilePath));
    return Array.from(paths).filter(
      (path) => path.endsWith('.enc') && !CONFLICT_COPY_RE.test(path) && path !== this.conflictPath
    );
  }

  // 整批回滚：直接恢复操作前读到的原始密文字节，不做 KDF、不依赖会话密钥
  async atomicRestoreText(path, text) {
    const adapter = this.app.vault.adapter;
    await this.ensureParentDir(path);
    const tmpPath = path + '.rollback-' + Date.now() + '-' + Math.random().toString(16).slice(2) + '.tmp';
    const bakPath = path + '.rollback-bak';
    let moved = false;
    try {
      await adapter.write(tmpPath, text);
      const readBack = await adapter.read(tmpPath);
      if (readBack !== text) throw new Error(this.t('err_write_verify'));
      if (await adapter.exists(bakPath)) await adapter.remove(bakPath).catch(() => undefined);
      if (await adapter.exists(path)) {
        await adapter.rename(path, bakPath);
        moved = true;
      }
      await adapter.rename(tmpPath, path);
      const finalText = await adapter.read(path);
      if (finalText !== text) throw new Error(this.t('err_write_verify'));
      if (moved) await adapter.remove(bakPath).catch(() => undefined);
    } catch (error) {
      try {
        if (moved && (await adapter.exists(bakPath))) {
          if (await adapter.exists(path)) await adapter.remove(path);
          await adapter.rename(bakPath, path);
        }
      } catch (restoreError) {
        console.error('[' + PLUGIN_ID + '] rollback restore failed:', restoreError);
      }
      throw error;
    } finally {
      if (await adapter.exists(tmpPath)) await adapter.remove(tmpPath).catch(() => undefined);
    }
  }

  // 通用批量任务：进度 N/M、锁定/挂起中断、任一失败整批回滚
  async runBatchFileJob(kind, job, options) {
    const opts = options || {};
    if (!opts.allowLocked && !this.isUnlocked()) throw new Error(this.t('notice_unlock_first'));
    if (this.batchActive) throw new Error(this.t('err_batch_busy', {
        current: this.batch ? this.batch.current : 0,
        total: this.batch ? this.batch.total : 0,
      }));
    let paths = this.batchTargetFiles();
    if (!paths.length && opts.allowLocked) {
      // 锁定时列表已清空：临时扫描一次，仅用于本次批量任务，结束后立即清空
      try {
        await this.scanVaultFiles();
      } catch (error) {
        paths = [];
      }
      paths = this.batchTargetFiles();
    }
    if (!paths.length) throw new Error(this.t('err_batch_empty'));
    this.batchActive = true;
    this.batchAbortRequested = false;
    this.batch = { kind, total: paths.length, current: 0, path: '', completed: [] };
    this.refreshViews();
    if (opts.onProgress) {
      try {
        opts.onProgress(this.batch);
      } catch (error) {
        /* ignore progress callback errors */
      }
    }
    const generation = this.sessionGeneration;
    try {
      const result = await this.enqueueWrite(async () => {
        const snapshots = new Map();
        const completed = [];
        try {
          for (const path of paths) {
            if (
              this.batchAbortRequested ||
              generation !== this.sessionGeneration ||
              this.suspended
            ) {
              const error = new Error(this.t('err_batch_interrupted'));
              error.code = 'xsv-batch-interrupted';
              throw error;
            }
            const original = await this.app.vault.adapter.read(path);
            snapshots.set(path, original);
            // 防止批处理期间其它进程改动该文件
            const latest = await this.app.vault.adapter.read(path);
            if (latest !== original) {
              const error = new Error(this.t('err_external_change'));
              error.code = 'xsv-conflict';
              throw error;
            }
            const outcome = await job(path, original);
            if (!outcome) {
              this.batch.current += 1;
              this.batch.path = path;
              continue;
            }
            await this.writeEnvelope(outcome.entries, null, outcome.salt, outcome.iterations, path, false, {
              generation,
              v3Ctx: outcome.ctx,
              notes: outcome.notes,
            });
            completed.push(path);
            this.batch.completed = completed.slice();
            this.batch.current += 1;
            this.batch.path = path;
            this.refreshViews();
            if (opts.onProgress) {
              try {
                opts.onProgress(this.batch);
              } catch (progressError) {
                /* ignore progress callback errors */
              }
            }
          }
          this.lastBatchResult = { kind, ok: true, completed: completed.slice(), rolledBack: [], rollbackErrors: [] };
          return { ok: true, completed, snapshots };
        } catch (error) {
          const rollbackPaths = completed.slice().reverse();
          const rollbackErrors = [];
          for (const path of rollbackPaths) {
            try {
              await this.atomicRestoreText(path, snapshots.get(path));
            } catch (rollbackError) {
              rollbackErrors.push(path);
              console.error('[' + PLUGIN_ID + '] batch rollback failed:', path, rollbackError);
            }
          }
          this.lastBatchResult = {
            kind,
            ok: false,
            completed: completed.slice(),
            rolledBack: rollbackPaths,
            rollbackErrors,
            reason: error && error.code ? error.code : 'error',
            message: error && error.message ? error.message : '',
          };
          throw error;
        }
      });
      return result;
    } finally {
      this.batchActive = false;
      this.batchAbortRequested = false;
      this.batch = null;
      if (!this.isUnlocked()) {
        // 锁定态恢复/批量结束后不保留文件名与路径
        this.vaultFiles = [];
        this.selectedFilePath = '';
      }
      this.refreshViews();
    }
  }

  // 校验密码能解开当前第一个文件（只验证，不产生写操作）
  async verifyVaultPassword(password) {
    const paths = this.batchTargetFiles();
    if (!paths.length) return false;
    try {
      const text = await this.app.vault.adapter.read(paths[0]);
      const envelope = this.parseEnvelope(text);
      if (Number(envelope.formatVersion) === FORMAT_VERSION) {
        const saltBase64 = String(envelope.kdf.salt);
        const iterations = Number(envelope.kdf.iterations);
        const kek = await this.deriveKey(password, base64ToBytes(saltBase64), iterations);
        await unwrapRawKey(
          this.requireCrypto(),
          kek,
          envelope.wrappedDek,
          buildWrapAadV3('password', FORMAT_VERSION, KDF_ALGO, iterations, saltBase64, CIPHER_ALGO)
        );
      } else {
        const key = await this.deriveKey(
          password,
          base64ToBytes(envelope.kdf.salt),
          Number(envelope.kdf.iterations)
        );
        await this.decryptEnvelope(envelope, key);
      }
      return true;
    } catch (error) {
      return false;
    }
  }

  // 修改主密码：默认快速改密（换 salt/KEK 重包同一 DEK）；彻底轮换还会生成新 DEK 重加密内容
  async changeMasterPassword(oldPassword, newPassword, options) {
    const opts = options || {};
    const mode = opts.mode === 'full' ? 'full' : 'quick';
    const oldNormalized = normalizePassword(oldPassword);
    const newNormalized = normalizePassword(newPassword);
    if (!oldNormalized) throw new Error(this.t('err_old_password_wrong'));
    if (newNormalized.length < MIN_MASTER_PASSWORD_LENGTH) {
      throw new Error(this.t('err_new_password_short'));
    }
    const paths = this.batchTargetFiles();
    if (!paths.length) throw new Error(this.t('err_batch_empty'));
    if (!(await this.verifyVaultPassword(oldNormalized))) {
      throw new Error(this.t('err_old_password_wrong'));
    }
    const sessions = new Map();
    const result = await this.runBatchFileJob('change-password', async (path, text) => {
      const cryptoObj = this.requireCrypto();
      const envelope = this.parseEnvelope(text);
      const formatVersion = Number(envelope.formatVersion);
      let rawDek;
      let rawMasterKey;
      let fileId;
      let recovery = null;
      let recoveryCode = null;
      let data;
      if (formatVersion === FORMAT_VERSION) {
        const saltBase64 = String(envelope.kdf.salt);
        const iterations = Number(envelope.kdf.iterations);
        const oldKek = await this.deriveKey(oldNormalized, base64ToBytes(saltBase64), iterations);
        try {
          rawDek = await unwrapRawKey(
            cryptoObj,
            oldKek,
            envelope.wrappedDek,
            buildWrapAadV3('password', FORMAT_VERSION, KDF_ALGO, iterations, saltBase64, CIPHER_ALGO)
          );
          rawMasterKey = await unwrapRawKey(
            cryptoObj,
            oldKek,
            envelope.wrappedMasterKey,
            buildWrapAadV3('master', FORMAT_VERSION, KDF_ALGO, iterations, saltBase64, CIPHER_ALGO)
          );
        } catch (error) {
          throw new Error(this.t('err_old_password_wrong'));
        }
        data = await this.decryptEnvelope(envelope, rawDek);
        fileId = base64ToBytes(envelope.fileId);
        recovery = envelope.recovery || null;
        recoveryCode = envelope.recoveryCode || null;
      } else {
        const oldKey = await this.deriveKey(
          oldNormalized,
          base64ToBytes(envelope.kdf.salt),
          Number(envelope.kdf.iterations)
        );
        data = await this.decryptEnvelope(envelope, oldKey);
        rawDek = randomBytes(cryptoObj, DEK_BYTES);
        rawMasterKey = this.rawMasterKey || randomBytes(cryptoObj, MASTER_KEY_BYTES);
        fileId = randomBytes(cryptoObj, FILE_ID_BYTES);
        recovery = this.sessionRecovery;
        recoveryCode = this.sessionRecoveryCode;
      }
      const payload = decodePayload(data);
      if (!payload) throw new Error(this.t('err_vault_corrupt'));
      const newSalt = randomBytes(cryptoObj, SALT_BYTES);
      const newKek = await this.deriveKey(newNormalized, newSalt, KDF_ITERATIONS);
      const nextDek = mode === 'full' ? randomBytes(cryptoObj, DEK_BYTES) : rawDek;
      const ctx = {
        rawDek: nextDek,
        kek: newKek,
        salt: newSalt,
        iterations: KDF_ITERATIONS,
        fileId,
        rawMasterKey,
        recovery,
        recoveryCode,
      };
      if (formatVersion === FORMAT_VERSION && mode !== 'full') {
        // 快速档：payload 与 fileId 均不变，只重包包裹层（不重加密内容）
        ctx.payloadReuse = { iv: String(envelope.cipher.iv), payload: String(envelope.payload) };
      }
      sessions.set(path, {
        data: payload,
        rawDek: nextDek,
        kek: newKek,
        rawMasterKey,
        salt: newSalt,
        saltBase64: bytesToBase64(newSalt),
        iterations: KDF_ITERATIONS,
        fileId,
        fileIdBase64: bytesToBase64(fileId),
        recovery,
        recoveryCode,
      });
      return {
        entries: payload.entries,
        notes: payload.notes,
        salt: newSalt,
        iterations: KDF_ITERATIONS,
        ctx,
      };
    }, { onProgress: opts.onProgress });

    this.sessionPassword = newNormalized;
    const currentPath = this.selectedFilePath ? this.normalizeVaultPath(this.selectedFilePath) : '';
    const current = sessions.get(currentPath);
    if (current) {
      await this.applyV3Session(
        Object.assign({}, current, {
          password: newNormalized,
          hash: await this.hashText(await this.readVaultText(currentPath)),
        })
      );
      this.reverifyChallenge = await this.buildReverifyChallenge(
        this.sessionKek,
        this.sessionSalt,
        this.sessionIterations
      );
      this.fileSessions.set(currentPath, {
        key: this.sessionKey,
        kek: this.sessionKek,
        rawDek: this.rawDek,
        rawMasterKey: this.rawMasterKey,
        fileId: this.sessionFileId,
        fileIdBase64: this.sessionFileIdBase64,
        formatVersion: FORMAT_VERSION,
        legacyKey: null,
        recovery: this.sessionRecovery,
        recoveryCode: this.sessionRecoveryCode,
        salt: this.sessionSalt,
        saltBase64: bytesToBase64(this.sessionSalt),
        iterations: this.sessionIterations,
        hash: this.knownBlobHash,
        conflictPending: false,
        conflictPath: '',
      });
    }
    for (const [path, session] of sessions.entries()) {
      if (path === currentPath) continue;
      const cached = this.fileSessions.get(path);
      if (!cached) continue;
      const dekKey = await importAesGcmKey(this.requireCrypto(), session.rawDek);
      this.fileSessions.set(path, Object.assign({}, cached, {
        key: dekKey,
        kek: session.kek,
        rawDek: session.rawDek,
        rawMasterKey: session.rawMasterKey,
        fileId: session.fileId,
        fileIdBase64: session.fileIdBase64,
        formatVersion: FORMAT_VERSION,
        legacyKey: null,
        recovery: session.recovery,
        recoveryCode: session.recoveryCode,
        salt: session.salt,
        saltBase64: session.saltBase64,
        iterations: session.iterations,
      }));
    }
    return { ok: true, mode, total: result.completed.length };
  }

  // 设置/修改密保问题：要求当前主密码；重包每个文件的主密钥并整批原子化
  async setRecoveryQuestions(currentPassword, questions, answers) {
    const password = normalizePassword(currentPassword);
    if (!password) throw new Error(this.t('err_current_password_wrong'));
    if (!(await this.verifyVaultPassword(password))) {
      throw new Error(this.t('err_current_password_wrong'));
    }
    if (!Array.isArray(questions) || questions.length !== RECOVERY_QUESTIONS_COUNT) {
      throw new Error(this.t('err_recovery_questions_count'));
    }
    const normalizedQuestions = questions.map(normalizeQuestionText);
    if (normalizedQuestions.some((question) => !question)) {
      throw new Error(this.t('err_recovery_questions_empty'));
    }
    if (!Array.isArray(answers) || answers.length !== RECOVERY_QUESTIONS_COUNT) {
      throw new Error(this.t('err_recovery_answers_required'));
    }
    if (answers.some((answer) => normalizeSecurityAnswer(answer).length < SECURITY_ANSWER_MIN)) {
      throw new Error(this.t('err_recovery_answer_short'));
    }
    let newRecovery = null;
    await this.runBatchFileJob('recovery-questions', async (path, text) => {
      const cryptoObj = this.requireCrypto();
      const envelope = this.parseEnvelope(text);
      if (Number(envelope.formatVersion) !== FORMAT_VERSION) {
        throw new Error(this.t('err_legacy_needs_upgrade'));
      }
      const saltBase64 = String(envelope.kdf.salt);
      const iterations = Number(envelope.kdf.iterations);
      const kek = await this.deriveKey(password, base64ToBytes(saltBase64), iterations);
      const rawMasterKey = await unwrapRawKey(
        cryptoObj,
        kek,
        envelope.wrappedMasterKey,
        buildWrapAadV3('master', FORMAT_VERSION, KDF_ALGO, iterations, saltBase64, CIPHER_ALGO)
      );
      const rawDek = await unwrapRawKey(
        cryptoObj,
        kek,
        envelope.wrappedDek,
        buildWrapAadV3('password', FORMAT_VERSION, KDF_ALGO, iterations, saltBase64, CIPHER_ALGO)
      );
      const payload = decodePayload(await this.decryptEnvelope(envelope, rawDek));
      if (!payload) throw new Error(this.t('err_vault_corrupt'));
      const recovery = await this.buildRecoveryBlock(rawMasterKey, normalizedQuestions, answers);
      newRecovery = recovery;
      const ctx = {
        rawDek,
        kek,
        salt: base64ToBytes(saltBase64),
        iterations,
        fileId: base64ToBytes(envelope.fileId),
        rawMasterKey,
        recovery,
        recoveryCode: envelope.recoveryCode || null,
      };
      return {
        entries: payload.entries,
        notes: payload.notes,
        salt: ctx.salt,
        iterations,
        ctx,
      };
    });
    if (newRecovery) {
      this.sessionRecovery = newRecovery;
      const currentPath = this.selectedFilePath ? this.normalizeVaultPath(this.selectedFilePath) : '';
      const cached = this.fileSessions.get(currentPath);
      if (cached) this.fileSessions.set(currentPath, Object.assign({}, cached, { recovery: newRecovery }));
    }
    return { ok: true };
  }

  async findRecoverySource(kind) {
    const preferred = this.selectedFilePath ? [this.normalizeVaultPath(this.selectedFilePath)] : [];
    let paths = Array.from(new Set(preferred.concat(this.batchTargetFiles())));
    if (!paths.length) {
      // 锁定时列表已清空：临时扫描目录找恢复源，但不把文件名留在内存
      const previousFiles = this.vaultFiles;
      const previousSelected = this.settings.selectedFile;
      try {
        const scanned = await this.scanVaultFiles();
        paths = scanned.map((file) => file.path);
      } catch (error) {
        paths = [];
      } finally {
        if (!this.isUnlocked()) {
          this.vaultFiles = previousFiles;
          this.settings.selectedFile = previousSelected;
        }
      }
    }
    for (const path of paths) {
      if (!(await this.app.vault.adapter.exists(path))) continue;
      try {
        const text = await this.app.vault.adapter.read(path);
        const envelope = this.parseEnvelope(text);
        if (Number(envelope.formatVersion) !== FORMAT_VERSION) continue;
        if (kind === 'questions' && envelope.recovery) {
          return { path, text, envelope };
        }
        if (kind === 'code' && envelope.recoveryCode) {
          return { path, text, envelope };
        }
      } catch (error) {
        /* 跳过损坏/不匹配的文件，继续找可用恢复源 */
      }
    }
    return null;
  }

  async verifyRecoveredMasterKey(source, rawMasterKey) {
    const cryptoObj = this.requireCrypto();
    const rawDek = await unwrapRawKey(
      cryptoObj,
      await importAesGcmKey(cryptoObj, rawMasterKey),
      source.envelope.wrappedDekByMaster,
      buildMasterDekAad(String(source.envelope.fileId), CIPHER_ALGO)
    );
    await this.decryptEnvelope(source.envelope, rawDek);
    return rawDek;
  }

  // 三道密保问题恢复：答案归一化 → PBKDF2-SHA512 1,000,000 + 独立 salt → 解出主密钥
  async recoverWithQuestions(answers) {
    const source = await this.findRecoverySource('questions');
    if (!source) return { ok: false, code: 'unavailable' };
    try {
      if (!Array.isArray(answers) || answers.length !== RECOVERY_QUESTIONS_COUNT) throw new Error('answers');
      const cryptoObj = this.requireCrypto();
      const recovery = source.envelope.recovery;
      const saltBase64 = String(recovery.kdf.salt);
      const iterations = Number(recovery.kdf.iterations);
      const key = await this.deriveKeyFromText(
        joinSecurityAnswers(answers),
        base64ToBytes(saltBase64),
        iterations
      );
      const qHash = await this.questionTextHash(recovery.questions);
      const rawMasterKey = await unwrapRawKey(
        cryptoObj,
        key,
        recovery.wrappedDek,
        buildWrapAadV3('recovery', FORMAT_VERSION, KDF_ALGO, iterations, saltBase64, CIPHER_ALGO, qHash)
      );
      await this.verifyRecoveredMasterKey(source, rawMasterKey);
      this.pendingRecovery = { rawMasterKey, sourcePath: source.path, kind: 'questions' };
      return { ok: true, questions: recovery.questions.slice(), sourcePath: source.path };
    } catch (error) {
      this.registerUnlockFailure();
      return { ok: false, code: 'failed' };
    }
  }

  // 恢复码恢复：高熵随机码 → 独立 salt → 解出主密钥
  async recoverWithCode(code) {
    const source = await this.findRecoverySource('code');
    if (!source) return { ok: false, code: 'unavailable' };
    try {
      const normalized = normalizeRecoveryCode(code);
      if (!normalized) throw new Error('code');
      const cryptoObj = this.requireCrypto();
      const block = source.envelope.recoveryCode;
      const saltBase64 = String(block.kdf.salt);
      const iterations = Number(block.kdf.iterations);
      const key = await this.deriveKeyFromText(normalized, base64ToBytes(saltBase64), iterations);
      const rawMasterKey = await unwrapRawKey(
        cryptoObj,
        key,
        block.wrappedDek,
        buildWrapAadV3('recovery-code', FORMAT_VERSION, KDF_ALGO, iterations, saltBase64, CIPHER_ALGO)
      );
      await this.verifyRecoveredMasterKey(source, rawMasterKey);
      this.pendingRecovery = { rawMasterKey, sourcePath: source.path, kind: 'code' };
      return { ok: true, sourcePath: source.path };
    } catch (error) {
      this.registerUnlockFailure();
      return { ok: false, code: 'failed' };
    }
  }

  // 恢复成功后强制设置新主密码，并把全部文件重包；失败整批回滚
  async completeRecoveryPassword(newPassword) {
    const pending = this.pendingRecovery;
    if (!pending || !pending.rawMasterKey) throw new Error(this.t('err_recovery_unavailable'));
    const newNormalized = normalizePassword(newPassword);
    if (newNormalized.length < MIN_MASTER_PASSWORD_LENGTH) {
      throw new Error(this.t('err_new_password_short'));
    }
    const sessions = new Map();
    const result = await this.runBatchFileJob(
      'recovery-complete',
      async (path, text) => {
        const cryptoObj = this.requireCrypto();
        const envelope = this.parseEnvelope(text);
        if (Number(envelope.formatVersion) !== FORMAT_VERSION || !envelope.wrappedDekByMaster) {
          throw new Error(this.t('err_legacy_needs_upgrade'));
        }
        const masterKey = await importAesGcmKey(cryptoObj, pending.rawMasterKey);
        const rawDek = await unwrapRawKey(
          cryptoObj,
          masterKey,
          envelope.wrappedDekByMaster,
          buildMasterDekAad(String(envelope.fileId), CIPHER_ALGO)
        );
        const payload = decodePayload(await this.decryptEnvelope(envelope, rawDek));
        if (!payload) throw new Error(this.t('err_vault_corrupt'));
        const newSalt = randomBytes(cryptoObj, SALT_BYTES);
        const newKek = await this.deriveKey(newNormalized, newSalt, KDF_ITERATIONS);
        const ctx = {
          rawDek,
          kek: newKek,
          salt: newSalt,
          iterations: KDF_ITERATIONS,
          fileId: base64ToBytes(envelope.fileId),
          rawMasterKey: pending.rawMasterKey,
          recovery: envelope.recovery || null,
          recoveryCode: envelope.recoveryCode || null,
        };
        sessions.set(path, {
          data: payload,
          rawDek,
          kek: newKek,
          rawMasterKey: pending.rawMasterKey,
          salt: newSalt,
          saltBase64: bytesToBase64(newSalt),
          iterations: KDF_ITERATIONS,
          fileId: base64ToBytes(envelope.fileId),
          fileIdBase64: String(envelope.fileId),
          recovery: envelope.recovery || null,
          recoveryCode: envelope.recoveryCode || null,
        });
        return {
          entries: payload.entries,
          notes: payload.notes,
          salt: newSalt,
          iterations: KDF_ITERATIONS,
          ctx,
        };
      },
      { allowLocked: true }
    );
    const source = sessions.get(pending.sourcePath) || sessions.values().next().value;
    if (!source) throw new Error(this.t('err_recovery_unavailable'));
    await this.applyV3Session(
      Object.assign({}, source, {
        password: newNormalized,
        hash: await this.hashText(await this.readVaultText(pending.sourcePath)),
      })
    );
    this.selectedFilePath = pending.sourcePath;
    this.selectedVaultPath = '';
    this.sessionGeneration += 1;
    this.reverifyChallenge = await this.buildReverifyChallenge(
      this.sessionKek,
      this.sessionSalt,
      this.sessionIterations
    );
    this.fileSessions.clear();
    this.rememberCurrentFileSession();
    this.pendingRecovery = null;
    this.failureCount = 0;
    this.blockedUntil = 0;
    this.suspended = false;
    this.suspendReason = '';
    this.stopCountdown();
    this.vaultState = 'present';
    this.conflictPending = false;
    this.conflictPath = '';
    this.settings.initializedPath = this.normalizeVaultPath(pending.sourcePath);
    this.settings.selectedFile = this.normalizeVaultPath(pending.sourcePath);
    this.resetIdleTimer();
    await this.scanVaultFiles();
    this.refreshViews();
    try {
      await this.saveSettings();
    } catch (error) {
      console.error('[' + PLUGIN_ID + '] save settings failed:', error);
    }
    new Notice(this.t('notice_recovery_reset'), 12000);
    return { ok: true, total: result.completed.length };
  }

  // 供 UI/测试调用的纯本地强度估算
  evaluatePasswordStrength(password) {
    const estimate = estimatePasswordStrength(password);
    return Object.assign({}, estimate, {
      tierLabel: this.t(
        estimate.tier === 'danger'
          ? 'strength_danger'
          : estimate.tier === 'general'
            ? 'strength_general'
            : 'strength_safe'
      ),
      singleText: formatDuration(estimate.secondsSingle, this.language),
      clusterText: formatDuration(estimate.secondsCluster, this.language),
    });
  }

  /* ---------------- 多文件与分组 ---------------- */

  // 所有切换 / 新建 / 删除 / 重命名都进同一条串行链，避免与保存并发
  enqueueWrite(job) {
    const task = this.writeChain.then(job, job);
    this.writeChain = task.then(
      () => undefined,
      () => undefined
    );
    return task;
  }

  resetViewNotes() {
    try {
      const leaves = this.app.workspace.getLeavesOfType(VIEW_TYPE) || [];
      for (const leaf of leaves) {
        const view = leaf && leaf.view;
        if (!view) continue;
        view.noteId = '';
        view.noteEditing = false;
        view.noteDraft = null;
        view.revealedCells.clear();
      }
    } catch (error) {
      /* ignore */
    }
  }

  // 读取并切到指定文件；密钥按文件缓存，首次打开才付一次 KDF
  async loadFileSession(path, generation) {
    const target = this.normalizeVaultPath(path);
    const text = await this.readVaultText(target);
    const envelope = this.parseEnvelope(text);
    const formatVersion = Number(envelope.formatVersion);
    const iterations = Number(envelope.kdf.iterations);
    const saltBase64 = String(envelope.kdf.salt);
    const salt = base64ToBytes(saltBase64);
    const cached = this.fileSessions.get(target);
    if (!this.sessionPassword) {
      const error = new Error(this.t('err_session_password_lost'));
      error.code = 'xsv-need-password';
      throw error;
    }
    // 解锁期间可能已经锁定：锁定后绝不把旧会话读出的内容写进内存
    if (generation !== undefined && generation !== this.sessionGeneration) {
      const discarded = new Error('discarded');
      discarded.code = 'xsv-discarded';
      throw discarded;
    }
    let session = null;
    let legacy = null;
    if (formatVersion === FORMAT_VERSION) {
      try {
        if (
          cached &&
          cached.formatVersion === FORMAT_VERSION &&
          cached.saltBase64 === saltBase64 &&
          cached.iterations === iterations &&
          cached.rawDek
        ) {
          const dekKey = await importAesGcmKey(this.requireCrypto(), cached.rawDek);
          const data = await this.decryptEnvelope(envelope, dekKey);
          const payload = decodePayload(data);
          if (!payload) throw new Error(this.t('err_vault_corrupt'));
          session = {
            data: payload,
            rawDek: cached.rawDek,
            kek: cached.kek,
            rawMasterKey: cached.rawMasterKey,
            salt,
            saltBase64,
            iterations,
            fileId: base64ToBytes(envelope.fileId),
            fileIdBase64: String(envelope.fileId),
            recovery: envelope.recovery || null,
            recoveryCode: envelope.recoveryCode || null,
            hash: await this.hashText(text),
          };
        } else {
          session = await this.openV3SessionFromEnvelope(envelope, this.sessionPassword, {
            hash: await this.hashText(text),
          });
        }
      } catch (error) {
        // 缓存可能因外部改密码失效：重派生一次，仍失败则拒绝打开该文件
        try {
          if (cached) this.fileSessions.delete(target);
          session = await this.openV3SessionFromEnvelope(envelope, this.sessionPassword, {
            hash: await this.hashText(text),
          });
        } catch (retryError) {
          const wrong = new Error(this.t('err_file_wrong_password'));
          wrong.code = 'xsv-wrong-file-password';
          throw wrong;
        }
      }
    } else {
      let key;
      let data;
      try {
        key = await this.deriveKey(this.sessionPassword, salt, iterations);
        data = await this.decryptEnvelope(envelope, key);
      } catch (error) {
        const wrong = new Error(this.t('err_file_wrong_password'));
        wrong.code = 'xsv-wrong-file-password';
        throw wrong;
      }
      legacy = {
        data: decodePayload(data),
        key,
        salt,
        saltBase64,
        iterations,
        formatVersion,
        hash: await this.hashText(text),
      };
      if (!legacy.data) throw new Error(this.t('err_vault_corrupt'));
      try {
        session = await this.migrateLegacyEnvelopeToV3(
          target,
          envelope,
          legacy.data,
          this.sessionPassword,
          generation
        );
        session.hash = await this.hashText(await this.readVaultText(target));
      } catch (error) {
        if (error && error.discarded) throw error;
        console.error('[' + PLUGIN_ID + '] switch-file upgrade failed:', error);
      }
    }
    if (generation !== undefined && generation !== this.sessionGeneration) {
      const discarded = new Error('discarded');
      discarded.code = 'xsv-discarded';
      throw discarded;
    }
    this.rememberCurrentFileSession();
    if (session) {
      await this.applyV3Session(
        Object.assign({}, session, { password: this.sessionPassword })
      );
      this.reverifyChallenge = await this.buildReverifyChallenge(
        this.sessionKek,
        this.sessionSalt,
        this.sessionIterations
      );
      this.fileSessions.set(target, {
        key: this.sessionKey,
        kek: this.sessionKek,
        rawDek: this.rawDek,
        rawMasterKey: this.rawMasterKey,
        fileId: this.sessionFileId,
        fileIdBase64: this.sessionFileIdBase64,
        formatVersion: FORMAT_VERSION,
        legacyKey: null,
        recovery: this.sessionRecovery,
        recoveryCode: this.sessionRecoveryCode,
        salt: this.sessionSalt,
        saltBase64: bytesToBase64(this.sessionSalt),
        iterations: this.sessionIterations,
        hash: this.knownBlobHash,
        conflictPending: !!(cached && cached.conflictPending),
        conflictPath: cached && cached.conflictPath ? cached.conflictPath : '',
      });
    } else {
      this.applyLegacySession(Object.assign({}, legacy, { password: this.sessionPassword }));
      this.reverifyChallenge = await this.buildReverifyChallenge(
        legacy.key,
        legacy.salt,
        legacy.iterations,
        buildAad(AAD_PREFIX, legacy.formatVersion, KDF_ALGO, legacy.iterations, legacy.saltBase64, CIPHER_ALGO)
      );
      this.fileSessions.set(target, {
        key: legacy.key,
        kek: null,
        rawDek: null,
        rawMasterKey: null,
        fileId: null,
        fileIdBase64: '',
        formatVersion: legacy.formatVersion,
        legacyKey: legacy.key,
        recovery: null,
        recoveryCode: null,
        salt: legacy.salt,
        saltBase64: legacy.saltBase64,
        iterations: legacy.iterations,
        hash: legacy.hash,
        conflictPending: !!(cached && cached.conflictPending),
        conflictPath: cached && cached.conflictPath ? cached.conflictPath : '',
      });
    }
    let notes = this.notes.map((item, index) => normalizeStoredNote(item, 'note-' + index));
    if (!notes.length) notes = [createDefaultNote()];
    this.notes = notes;
    this.entries = this.entries.map((item, index) => normalizeStoredEntry(item, 'restored-' + index));
    this.selectedFilePath = target;
    this.selectedVaultPath = '';
    this.knownBlobHash = session ? this.knownBlobHash : legacy.hash;
    this.conflictPending = !!(cached && cached.conflictPending);
    this.conflictPath = cached && cached.conflictPath ? cached.conflictPath : '';
    this.settings.selectedFile = target;
    this.vaultState = 'present';
    this.resetViewNotes();
    this.resetIdleTimer();
    return true;
  }

  async switchVaultFile(path) {
    if (!this.isUnlocked()) return false;
    if (this.batchActive) {
      new Notice(this.t('err_batch_busy', {
        current: this.batch ? this.batch.current : 0,
        total: this.batch ? this.batch.total : 0,
      }), 4000);
      return false;
    }
    const target = this.normalizeVaultPath(path);
    if (this.selectedFilePath && target === this.normalizeVaultPath(this.selectedFilePath)) return true;
    this.fileLoading = target;
    this.refreshViews();
    const generation = this.sessionGeneration;
    try {
      const result = await this.enqueueWrite(async () => {
        if (!this.isUnlocked() || this.suspended) return false;
        try {
          return await this.loadFileSession(target, generation);
        } catch (error) {
          if (error && error.code === 'xsv-discarded') return false;
          console.error('[' + PLUGIN_ID + '] switch file failed:', error);
          new Notice(this.t('err_file_wrong_password'), 6000);
          return false;
        }
      });
      return !!result;
    } finally {
      this.fileLoading = '';
      await this.scanVaultFiles();
      this.refreshViews();
      try {
        await this.saveSettings();
      } catch (error) {
        /* 偏好保存失败不影响使用 */
      }
    }
  }

  // 新建文件：名称可含 组/名字；用当前会话主密码派生该文件自己的密钥
  async createVaultFile(rawName, rawGroup) {
    if (!this.isUnlocked()) {
      new Notice(this.t('notice_unlock_first'), 3000);
      return { ok: false, reason: 'locked' };
    }
    if (this.batchActive) {
      new Notice(this.t('err_batch_busy', {
        current: this.batch ? this.batch.current : 0,
        total: this.batch ? this.batch.total : 0,
      }), 4000);
      return { ok: false, reason: 'busy' };
    }
    const parsed = parseVaultFileInput(rawName, rawGroup);
    if (!parsed) {
      new Notice(this.t('err_file_name_invalid'), 4000);
      return { ok: false, reason: 'invalid' };
    }
    const dir = this.getVaultDir();
    const target = this.normalizeVaultPath(
      [dir, parsed.group, parsed.name + '.enc'].filter(Boolean).join('/')
    );
    if (await this.app.vault.adapter.exists(target)) {
      new Notice(this.t('err_file_name_exists'), 4000);
      return { ok: false, reason: 'exists' };
    }
    const generation = this.sessionGeneration;
    const password = this.sessionPassword;
    if (!password) {
      new Notice(this.t('err_session_password_lost'), 4000);
      return { ok: false, reason: 'no-password' };
    }
    const result = await this.enqueueWrite(async () => {
      if (generation !== this.sessionGeneration || !this.sessionKey || this.suspended) {
        return { ok: false, reason: 'discarded' };
      }
      if (await this.app.vault.adapter.exists(target)) return { ok: false, reason: 'exists' };
      const cryptoObj = this.requireCrypto();
      const salt = randomBytes(cryptoObj, SALT_BYTES);
      const kek = await this.deriveKey(password, salt, KDF_ITERATIONS);
      const rawDek = randomBytes(cryptoObj, DEK_BYTES);
      const rawMasterKey = this.rawMasterKey || randomBytes(cryptoObj, MASTER_KEY_BYTES);
      const fileId = randomBytes(cryptoObj, FILE_ID_BYTES);
      if (generation !== this.sessionGeneration || !this.sessionKey || this.suspended) {
        return { ok: false, reason: 'discarded' };
      }
      const notes = [createDefaultNote()];
      const ctx = {
        rawDek,
        kek,
        salt,
        iterations: KDF_ITERATIONS,
        fileId,
        rawMasterKey,
        recovery: this.sessionRecovery,
        recoveryCode: this.sessionRecoveryCode,
      };
      await this.writeEnvelope([], null, salt, KDF_ITERATIONS, target, true, {
        generation,
        mustNotExist: true,
        notes,
        v3Ctx: ctx,
      });
      const writtenText = await this.readVaultText(target);
      // 新文件成为当前文件：旧文件状态先存回其独立记录
      this.rememberCurrentFileSession();
      await this.applyV3Session({
        data: { entries: [], notes, contentVersion: CONTENT_VERSION },
        rawDek,
        kek,
        rawMasterKey,
        salt,
        saltBase64: bytesToBase64(salt),
        iterations: KDF_ITERATIONS,
        fileId,
        fileIdBase64: bytesToBase64(fileId),
        recovery: this.sessionRecovery,
        recoveryCode: this.sessionRecoveryCode,
        hash: await this.hashText(writtenText),
        password,
      });
      this.selectedFilePath = target;
      this.selectedVaultPath = '';
      this.reverifyChallenge = await this.buildReverifyChallenge(kek, salt, KDF_ITERATIONS);
      this.conflictPending = false;
      this.conflictPath = '';
      this.fileSessions.set(target, {
        key: this.sessionKey,
        kek,
        rawDek,
        rawMasterKey,
        fileId,
        fileIdBase64: bytesToBase64(fileId),
        formatVersion: FORMAT_VERSION,
        legacyKey: null,
        recovery: this.sessionRecovery,
        recoveryCode: this.sessionRecoveryCode,
        salt,
        saltBase64: bytesToBase64(salt),
        iterations: KDF_ITERATIONS,
        hash: this.knownBlobHash,
        conflictPending: false,
        conflictPath: '',
      });
      this.settings.selectedFile = target;
      this.resetViewNotes();
      this.resetIdleTimer();
      return { ok: true, path: target, name: parsed.name, group: parsed.group };
    });
    await this.scanVaultFiles();
    this.refreshViews();
    if (result && result.ok) {
      new Notice(this.t('notice_file_created', { name: parsed.name }), 3000);
      try {
        await this.saveSettings();
      } catch (error) {
        /* ignore */
      }
    } else if (result && result.reason === 'exists') {
      new Notice(this.t('err_file_name_exists'), 4000);
    }
    return result || { ok: false, reason: 'failed' };
  }

  // 重命名 / 移动：同目录内改名或换分组，同名目标一律拒绝
  async renameVaultFile(path, rawName, rawGroup) {
    if (!this.isUnlocked()) return { ok: false, reason: 'locked' };
    if (this.batchActive) {
      new Notice(this.t('err_batch_busy', {
        current: this.batch ? this.batch.current : 0,
        total: this.batch ? this.batch.total : 0,
      }), 4000);
      return { ok: false, reason: 'busy' };
    }
    const parsed = parseVaultFileInput(rawName, rawGroup);
    if (!parsed) {
      new Notice(this.t('err_file_name_invalid'), 4000);
      return { ok: false, reason: 'invalid' };
    }
    const from = this.normalizeVaultPath(path);
    const dir = this.getVaultDir();
    const to = this.normalizeVaultPath([dir, parsed.group, parsed.name + '.enc'].filter(Boolean).join('/'));
    if (to === from) return { ok: true, path: from };
    const adapter = this.app.vault.adapter;
    const generation = this.sessionGeneration;
    const result = await this.enqueueWrite(async () => {
      if (generation !== this.sessionGeneration || !this.sessionKey) return { ok: false, reason: 'discarded' };
      if (await adapter.exists(to)) return { ok: false, reason: 'exists' };
      await this.ensureParentDir(to);
      await adapter.rename(from, to);
      const record = this.fileSessions.get(from);
      if (record) {
        this.fileSessions.delete(from);
        this.fileSessions.set(to, record);
      }
      if (this.selectedFilePath && this.normalizeVaultPath(this.selectedFilePath) === from) {
        this.selectedFilePath = to;
        this.settings.selectedFile = to;
      }
      return { ok: true, path: to };
    });
    await this.scanVaultFiles();
    this.refreshViews();
    if (result && result.ok) {
      new Notice(this.t('notice_file_renamed', { name: parsed.name }), 3000);
      try {
        await this.saveSettings();
      } catch (error) {
        /* ignore */
      }
    } else if (result && result.reason === 'exists') {
      new Notice(this.t('err_file_name_exists'), 4000);
    }
    return result || { ok: false, reason: 'failed' };
  }

  async deleteVaultFile(path) {
    if (!this.isUnlocked()) return { ok: false, reason: 'locked' };
    if (this.batchActive) {
      new Notice(this.t('err_batch_busy', {
        current: this.batch ? this.batch.current : 0,
        total: this.batch ? this.batch.total : 0,
      }), 4000);
      return { ok: false, reason: 'busy' };
    }
    const target = this.normalizeVaultPath(path);
    const generation = this.sessionGeneration;
    const isCurrent = this.selectedFilePath && this.normalizeVaultPath(this.selectedFilePath) === target;
    const nextPath = isCurrent
      ? (this.vaultFiles.filter((file) => file.path !== target)[0] || {}).path || ''
      : '';
    const result = await this.enqueueWrite(async () => {
      if (generation !== this.sessionGeneration || !this.sessionKey) return { ok: false, reason: 'discarded' };
      try {
        await this.app.vault.adapter.remove(target);
      } catch (error) {
        return { ok: false, reason: 'failed' };
      }
      this.fileSessions.delete(target);
      if (isCurrent) {
        this.selectedFilePath = '';
        this.settings.selectedFile = '';
        this.sessionKey = null;
        this.sessionSalt = null;
        this.entries = [];
        this.notes = [];
        this.knownBlobHash = null;
        this.conflictPending = false;
        this.conflictPath = '';
        if (nextPath && (await this.app.vault.adapter.exists(nextPath))) {
          try {
            await this.loadFileSession(nextPath);
          } catch (error) {
            this.sessionKey = null;
          }
        }
      }
      return { ok: true };
    });
    await this.scanVaultFiles();
    this.vaultState = this.vaultFiles.length ? 'present' : 'absent';
    if (result && result.ok) {
      new Notice(this.t('notice_file_deleted'), 3000);
      if (!this.isUnlocked()) {
        this.lock();
        return result;
      }
      this.refreshViews();
      try {
        await this.saveSettings();
      } catch (error) {
        /* ignore */
      }
    }
    return result || { ok: false, reason: 'failed' };
  }

  async setVaultDir(rawDir) {
    this.settings.vaultDir = normalizeVaultDir(rawDir);
    await this.scanVaultFiles();
    this.vaultState = this.vaultFiles.length ? 'present' : 'absent';
    this.refreshViews();
    await this.saveSettings();
  }

  async toggleGroupCollapsed(group) {
    const key = normalizeRelativePath(group);
    if (!key) return;
    const collapsed = normalizeCollapsedGroups(this.settings.collapsedGroups);
    const index = collapsed.indexOf(key);
    if (index >= 0) collapsed.splice(index, 1);
    else collapsed.push(key);
    this.settings.collapsedGroups = collapsed;
    await this.saveSettings();
    this.refreshViews();
  }

  /* ---------------- 保险库生命周期 ---------------- */

  async createVault(password, options) {
    const opts = options || {};
    const cryptoObj = this.requireCrypto();
    const normalized = normalizePassword(password);
    const questions = Array.isArray(opts.questions) ? opts.questions.map(normalizeQuestionText) : [];
    const answers = Array.isArray(opts.answers) ? opts.answers : [];
    if (questions.length) {
      if (questions.length !== RECOVERY_QUESTIONS_COUNT) throw new Error(this.t('err_recovery_questions_count'));
      if (questions.some((question) => !question)) throw new Error(this.t('err_recovery_questions_empty'));
      if (answers.length !== RECOVERY_QUESTIONS_COUNT || answers.some((answer) => normalizeSecurityAnswer(answer).length < SECURITY_ANSWER_MIN)) {
        throw new Error(this.t('err_recovery_answer_short'));
      }
    }
    const salt = randomBytes(cryptoObj, SALT_BYTES);
    const kek = await this.deriveKey(normalized, salt, KDF_ITERATIONS);
    const rawDek = randomBytes(cryptoObj, DEK_BYTES);
    const rawMasterKey = randomBytes(cryptoObj, MASTER_KEY_BYTES);
    const fileId = randomBytes(cryptoObj, FILE_ID_BYTES);
    const recoveryCode = base32Encode(randomBytes(cryptoObj, 16));
    const recovery = questions.length
      ? await this.buildRecoveryBlock(rawMasterKey, questions, answers)
      : null;
    const recoveryCodeBlock = await this.buildRecoveryCodeBlock(rawMasterKey, recoveryCode);
    // 首次创建落在新目录下的默认文件；旧版 <vault>/xu-secrets.enc 已存在时不会走到这里
    const configured = this.normalizeVaultPath(this.settings.vaultPath);
    const path =
      configured && configured !== DEFAULT_VAULT_PATH
        ? configured
        : this.defaultVaultFilePath();
    this.selectedVaultPath = '';
    // 已存在同名文件时拒绝创建，避免覆盖旧库；writeEnvelope 在 rename 前还会再查一次，堵住 exists→rename 竞态
    if (await this.app.vault.adapter.exists(path)) throw new Error(this.t('err_vault_exists'));
    const initialNotes = [createDefaultNote()];
    const ctx = {
      rawDek,
      kek,
      salt,
      iterations: KDF_ITERATIONS,
      fileId,
      rawMasterKey,
      recovery,
      recoveryCode: recoveryCodeBlock,
    };
    await this.writeEnvelope([], null, salt, KDF_ITERATIONS, path, true, {
      generation: this.sessionGeneration,
      mustNotExist: true,
      notes: initialNotes,
      v3Ctx: ctx,
    });
    this.sessionGeneration += 1;
    await this.applyV3Session({
      data: { entries: [], notes: initialNotes, contentVersion: CONTENT_VERSION },
      rawDek,
      kek,
      rawMasterKey,
      salt,
      saltBase64: bytesToBase64(salt),
      iterations: KDF_ITERATIONS,
      fileId,
      fileIdBase64: bytesToBase64(fileId),
      recovery,
      recoveryCode: recoveryCodeBlock,
      hash: await this.hashText(await this.readVaultText(path)),
      password: normalized,
    });
    this.selectedFilePath = path;
    this.vaultState = 'present';
    this.conflictPending = false;
    this.conflictPath = '';
    this.fileSessions.set(path, {
      key: this.sessionKey,
      kek,
      rawDek,
      rawMasterKey,
      fileId,
      fileIdBase64: bytesToBase64(fileId),
      formatVersion: FORMAT_VERSION,
      legacyKey: null,
      recovery,
      recoveryCode: recoveryCodeBlock,
      salt,
      saltBase64: bytesToBase64(salt),
      iterations: KDF_ITERATIONS,
      hash: this.knownBlobHash,
      conflictPending: false,
      conflictPath: '',
    });
    this.reverifyChallenge = await this.buildReverifyChallenge(kek, salt, KDF_ITERATIONS);
    this.failureCount = 0;
    this.blockedUntil = 0;
    this.settings.initializedPath = path;
    this.settings.selectedFile = path;
    this.resetIdleTimer();
    await this.scanVaultFiles();
    this.refreshViews();
    try {
      await this.saveSettings();
    } catch (error) {
      console.error('[' + PLUGIN_ID + '] save settings failed:', error);
    }
    // 恢复码只在创建向导里显示一次；不落盘、不写日志
    return { ok: true, recoveryCode: formatRecoveryCode(recoveryCode), recoveryCodeRaw: recoveryCode };
  }

  // 重验挑战：会话内随机口令用 KEK 加密一次；重验必须付同样的 KDF 成本并解开它
  async buildReverifyChallenge(key, salt, iterations, aadOverride) {
    const cryptoObj = this.requireCrypto();
    const iv = randomBytes(cryptoObj, IV_BYTES);
    const marker = bytesToBase64(randomBytes(cryptoObj, 16));
    const aad =
      aadOverride ||
      buildWrapAadV3(
        'password',
        FORMAT_VERSION,
        KDF_ALGO,
        iterations,
        bytesToBase64(salt),
        CIPHER_ALGO
      );
    const ciphertext = await cryptoObj.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad, tagLength: TAG_LENGTH },
      key,
      utf8Encode(REVERIFY_MARKER + marker)
    );
    return { iv, ciphertext: new Uint8Array(ciphertext), marker, aad };
  }

  getUnlockWaitSeconds() {
    const left = this.blockedUntil - this.nowMs();
    return left > 0 ? Math.ceil(left / 1000) : 0;
  }

  registerUnlockFailure() {
    this.failureCount += 1;
    const backoff = Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * Math.pow(2, this.failureCount - 1));
    this.blockedUntil = this.nowMs() + backoff;
  }

  // 解开 v3 信封：密码 KEK 解包裹 DEK / 主密钥，再用 DEK 解内容
  async openV3SessionFromEnvelope(envelope, password, extra) {
    const cryptoObj = this.requireCrypto();
    const saltBase64 = String(envelope.kdf.salt);
    const salt = base64ToBytes(saltBase64);
    const iterations = Number(envelope.kdf.iterations);
    const kek = await this.deriveKey(password, salt, iterations);
    const passwordAad = buildWrapAadV3(
      'password',
      FORMAT_VERSION,
      KDF_ALGO,
      iterations,
      saltBase64,
      CIPHER_ALGO
    );
    const rawDek = await unwrapRawKey(cryptoObj, kek, envelope.wrappedDek, passwordAad);
    const rawMasterKey = await unwrapRawKey(
      cryptoObj,
      kek,
      envelope.wrappedMasterKey,
      buildWrapAadV3('master', FORMAT_VERSION, KDF_ALGO, iterations, saltBase64, CIPHER_ALGO)
    );
    const dekKey = await importAesGcmKey(cryptoObj, rawDek);
    const data = await this.decryptEnvelope(envelope, dekKey);
    const payload = decodePayload(data);
    if (!payload) throw new Error(this.t('err_vault_corrupt'));
    return Object.assign(
      {
        data: payload,
        rawDek,
        kek,
        rawMasterKey,
        salt,
        saltBase64,
        iterations,
        fileId: base64ToBytes(envelope.fileId),
        fileIdBase64: String(envelope.fileId),
        formatVersion: FORMAT_VERSION,
        recovery: envelope.recovery || null,
        recoveryCode: envelope.recoveryCode || null,
      },
      extra || {}
    );
  }

  // 把 v1/v2 文件迁移到 v3：成功时保留 .bak，失败时 writeEnvelope 会恢复原字节
  async migrateLegacyEnvelopeToV3(path, envelope, data, password, generation, options) {
    const opts = options || {};
    const cryptoObj = this.requireCrypto();
    const saltBase64 = String(envelope.kdf.salt);
    const salt = base64ToBytes(saltBase64);
    const iterations = Number(envelope.kdf.iterations);
    const kek = await this.deriveKey(password, salt, iterations);
    const rawDek = randomBytes(cryptoObj, DEK_BYTES);
    const rawMasterKey = this.rawMasterKey || randomBytes(cryptoObj, MASTER_KEY_BYTES);
    const fileId = randomBytes(cryptoObj, FILE_ID_BYTES);
    const ctx = {
      rawDek,
      kek,
      salt,
      iterations,
      fileId,
      rawMasterKey,
      recovery: this.sessionRecovery,
      recoveryCode: this.sessionRecoveryCode,
    };
    const notes = data.notes || [];
    await this.writeEnvelope(data.entries || [], null, salt, iterations, path, true, {
      generation,
      v3Ctx: ctx,
      notes,
      keepBackup: true,
    });
    const text = await this.readVaultText(path);
    return {
      data,
      rawDek,
      kek,
      rawMasterKey,
      salt,
      saltBase64,
      iterations,
      fileId,
      fileIdBase64: bytesToBase64(fileId),
      formatVersion: FORMAT_VERSION,
      recovery: ctx.recovery || null,
      recoveryCode: ctx.recoveryCode || null,
      hash: await this.hashText(text),
      migrated: true,
    };
  }

  // 统一失败口径：文件缺失/JSON 畸形/base64 损坏/密码错误都 return false，不抛原始异常
  // 唯一例外：未知版本明确提示「版本不支持」，避免被误读成密码错误
  async unlock(password) {
    this.lastUnlockError = '';
    const wait = this.getUnlockWaitSeconds();
    if (wait > 0) {
      this.lastUnlockError = this.t('err_unlock_backoff', { seconds: wait });
      return false;
    }
    try {
      const path = this.getVaultPath();
      const exists = await this.app.vault.adapter.exists(path);
      if (!exists) {
        this.vaultState = 'absent';
        this.lastUnlockError = this.t('err_vault_missing');
        this.refreshViews();
        return false;
      }
      const text = await this.readVaultText(path);
      const envelope = this.parseEnvelope(text);
      const formatVersion = Number(envelope.formatVersion);
      const previousMasterKey = this.rawMasterKey;
      const previousRecovery = this.sessionRecovery;
      const previousRecoveryCode = this.sessionRecoveryCode;
      this.sessionGeneration += 1;
      const generation = this.sessionGeneration;
      let session = null;
      let legacy = null;
      if (formatVersion === FORMAT_VERSION) {
        try {
          session = await this.openV3SessionFromEnvelope(envelope, password);
        } catch (error) {
          this.registerUnlockFailure();
          this.lastUnlockError = this.t('err_unlock_failed');
          return false;
        }
      } else {
        const saltBase64 = String(envelope.kdf.salt);
        const salt = base64ToBytes(saltBase64);
        const iterations = Number(envelope.kdf.iterations);
        let key;
        let data;
        try {
          key = await this.deriveKey(password, salt, iterations);
          data = await this.decryptEnvelope(envelope, key);
          if (!decodePayload(data)) throw new Error('invalid payload');
        } catch (error) {
          this.registerUnlockFailure();
          this.lastUnlockError = this.t('err_unlock_failed');
          return false;
        }
        legacy = {
          data: decodePayload(data),
          key,
          salt,
          saltBase64,
          iterations,
          formatVersion,
          hash: await this.hashText(text),
        };
        // 迁移期间让 writeEnvelope 能用本次 generation；失败则保持原字节并继续以旧格式工作
        this.rawMasterKey = previousMasterKey;
        this.sessionRecovery = previousRecovery;
        this.sessionRecoveryCode = previousRecoveryCode;
        try {
          session = await this.migrateLegacyEnvelopeToV3(
            path,
            envelope,
            legacy.data,
            password,
            generation
          );
          session.hash = await this.hashText(await this.readVaultText(path));
          new Notice(
            this.t(formatVersion === LEGACY_FORMAT_VERSION ? 'notice_upgraded_v1' : 'notice_upgraded_v2'),
            8000
          );
        } catch (error) {
          if (error && error.discarded) {
            // 锁定中断：本次解锁不再继续
            return false;
          }
          console.error('[' + PLUGIN_ID + '] legacy upgrade failed:', error);
          if (!this.v1UpgradeWarned) {
            this.v1UpgradeWarned = true;
            new Notice(this.t('notice_upgrade_failed'), 8000);
          }
        }
      }

      this.failureCount = 0;
      this.blockedUntil = 0;
      this.suspended = false;
      this.suspendReason = '';
      this.stopCountdown();
      this.hiddenAt = 0;
      this.hiddenAtWall = 0;
      let entries;
      let notes;
      if (session) {
        await this.applyV3Session(Object.assign({}, session, { password: normalizePassword(password), hash: session.hash != null ? session.hash : await this.hashText(text) }));
        entries = this.entries;
        notes = this.notes;
        this.sessionGeneration = generation;
        this.reverifyChallenge = await this.buildReverifyChallenge(
          this.sessionKek,
          this.sessionSalt,
          this.sessionIterations
        );
        this.fileSessions.set(path, {
          key: this.sessionKey,
          kek: this.sessionKek,
          rawDek: this.rawDek,
          rawMasterKey: this.rawMasterKey,
          fileId: this.sessionFileId,
          fileIdBase64: this.sessionFileIdBase64,
          formatVersion: FORMAT_VERSION,
          legacyKey: null,
          recovery: this.sessionRecovery,
          recoveryCode: this.sessionRecoveryCode,
          salt: this.sessionSalt,
          saltBase64: bytesToBase64(this.sessionSalt),
          iterations: this.sessionIterations,
          hash: this.knownBlobHash,
          conflictPending: false,
          conflictPath: '',
        });
      } else {
        this.applyLegacySession(Object.assign({}, legacy, { password: normalizePassword(password) }));
        entries = this.entries;
        notes = this.notes;
        this.reverifyChallenge = await this.buildReverifyChallenge(
          legacy.key,
          legacy.salt,
          legacy.iterations,
          buildAad(
            AAD_PREFIX,
            legacy.formatVersion,
            KDF_ALGO,
            legacy.iterations,
            legacy.saltBase64,
            CIPHER_ALGO
          )
        );
        this.fileSessions.set(path, {
          key: legacy.key,
          kek: null,
          rawDek: null,
          rawMasterKey: null,
          fileId: null,
          fileIdBase64: '',
          formatVersion: legacy.formatVersion,
          legacyKey: legacy.key,
          recovery: null,
          recoveryCode: null,
          salt: legacy.salt,
          saltBase64: legacy.saltBase64,
          iterations: legacy.iterations,
          hash: legacy.hash,
          conflictPending: false,
          conflictPath: '',
        });
      }
      if (!notes.length) {
        notes = [createDefaultNote()];
        this.notes = notes;
      }
      this.vaultState = 'present';
      this.conflictPending = false;
      this.conflictPath = '';
      this.selectedFilePath = path;
      this.selectedVaultPath = '';
      // 记录当前文件路径（不用冲突副本路径），用于"文件缺失"判断
      this.settings.initializedPath = this.normalizeVaultPath(path);
      this.settings.selectedFile = this.normalizeVaultPath(path);
      this.resetIdleTimer();
      await this.scanVaultFiles();
      // 若解锁的是冲突副本，列表会把"上次文件"修正回正式库；缺失态判断也用修正后的路径
      if (this.settings.selectedFile) this.settings.initializedPath = this.settings.selectedFile;
      this.refreshViews();
      try {
        await this.saveSettings();
      } catch (error) {
        console.error('[' + PLUGIN_ID + '] save settings failed:', error);
      }
      return true;
    } catch (error) {
      if (error && error.code === 'xsv-version-unsupported') {
        // 版本未知：不当作密码错误，也不计入爆破退避
        this.lastUnlockError = this.t('err_version_unsupported');
        return false;
      }
      // 文件本身超限属于状态错误，不是密码错误：不罚等待、不累计失败次数
      if (errorMessage(error) === this.t('err_vault_too_large')) {
        this.lastUnlockError = this.t('err_vault_too_large');
        return false;
      }
      console.error('[' + PLUGIN_ID + '] unlock failed:', error);
      this.registerUnlockFailure();
      this.lastUnlockError = this.t('err_unlock_failed');
      return false;
    }
  }

  // 回到前台后的重新验证：与解锁同量级成本（会话盐 KDF + 解挑战密文），并复用同一套失败退避
  async reverify(password) {
    this.lastReverifyError = '';
    if (!this.isUnlocked() || !this.reverifyChallenge) return false;
    const wait = this.getUnlockWaitSeconds();
    if (wait > 0) {
      this.lastReverifyError = this.t('err_unlock_backoff', { seconds: wait });
      return false;
    }
    // KDF 期间可能被锁定/切换会话，成功前必须复查 generation
    const generation = this.sessionGeneration;
    try {
      const cryptoObj = this.requireCrypto();
      const challenge = this.reverifyChallenge;
      const candidate = await this.deriveKey(password, this.sessionSalt, this.sessionIterations);
      if (generation !== this.sessionGeneration || !this.sessionKey) return false;
      const plaintext = await cryptoObj.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: challenge.iv,
          additionalData: challenge.aad,
          tagLength: TAG_LENGTH,
        },
        candidate,
        challenge.ciphertext
      );
      if (generation !== this.sessionGeneration || !this.sessionKey) return false;
      if (utf8Decode(plaintext) !== REVERIFY_MARKER + challenge.marker) throw new Error('mismatch');
      this.failureCount = 0;
      this.blockedUntil = 0;
      this.hiddenAt = 0;
      this.hiddenAtWall = 0;
      this.suspended = false;
      this.suspendReason = '';
      this.stopCountdown();
      this.unmaskAllViews();
      this.resetIdleTimer();
      this.refreshViews();
      return true;
    } catch (error) {
      // 已被锁定/会话已切换：不要在本会话里计失败，也不改挂起态
      if (generation !== this.sessionGeneration) return false;
      this.registerUnlockFailure();
      const seconds = this.getUnlockWaitSeconds();
      this.lastReverifyError =
        seconds > 0 ? this.t('err_unlock_backoff', { seconds }) : this.t('notice_reverify_failed');
      return false;
    }
  }

  lock() {
    const hadSession = this.isUnlocked();
    this.sessionGeneration += 1;
    if (this.batchActive) this.batchAbortRequested = true;
    this.sessionKey = null;
    this.sessionSalt = null;
    this.sessionIterations = KDF_ITERATIONS;
    this.sessionKek = null;
    this.rawDek = null;
    this.rawMasterKey = null;
    this.sessionFileId = null;
    this.sessionFileIdBase64 = '';
    this.sessionFormatVersion = FORMAT_VERSION;
    this.sessionRecovery = null;
    this.sessionRecoveryCode = null;
    this.sessionLegacyKey = null;
    this.pendingRecovery = null;
    this.entries = [];
    this.notes = [];
    this.contentVersion = 0;
    this.idleDeadline = 0;
    this.idleDeadlineWall = 0;
    this.knownBlobHash = null;
    this.reverifyChallenge = null;
    this.lastReverifyError = '';
    this.hiddenAt = 0;
    this.hiddenAtWall = 0;
    this.stopCountdown();
    this.suspended = false;
    this.suspendReason = '';
    this.conflictPending = false;
    this.conflictPath = '';
    this.selectedVaultPath = '';
    this.lastUnlockError = '';

    // 多文件：清空所有文件的派生密钥、主密码暂存与列表快照，DOM 中不保留任何文件名/内容预览
    this.fileSessions.clear();
    this.sessionPassword = '';
    this.selectedFilePath = '';
    this.vaultFiles = [];
    this.fileLoading = '';

    this.clearClipboardTimer();
    if (this.clipboardText) void this.clearClipboardIfOwned(false);
    this.clipboardText = null;

    this.clearViewScreens();
    this.refreshViews();
    void this.scanVaultSources();
    if (hadSession) console.debug('[' + PLUGIN_ID + '] locked');
  }

  clearViewScreens() {
    try {
      const leaves = this.app.workspace.getLeavesOfType(VIEW_TYPE);
      for (const leaf of leaves) {
        const view = leaf && leaf.view;
        if (view && typeof view.clearSensitive === 'function') view.clearSensitive();
      }
    } catch (error) {
      console.error('[' + PLUGIN_ID + '] clear view screens failed:', error);
    }
  }

  /* ---------------- 条目 CRUD ---------------- */

  assertUnlocked() {
    if (!this.isUnlocked()) throw new Error(this.t('notice_unlock_first'));
    // 遮罩/挂起期间必须重新验证后才能读写
    if (this.suspended) throw new Error(this.t('err_suspended'));
    if (this.conflictPending) throw new Error(this.t('err_conflict_editing_blocked'));
    // 冲突副本只读：写入副本会在锁定后静默丢弃，因此所有写操作都同一文案拒绝
    if (this.isReadOnlyCopy()) throw new Error(this.t('err_conflict_copy_readonly'));
    this.touchActivity();
  }

  async addEntry(input) {
    this.assertUnlocked();
    const base = normalizeEntryInput(input);
    const now = new Date().toISOString();
    const entry = Object.assign(
      {
        id: this.newEntryId(),
        createdAt: now,
        updatedAt: now,
      },
      base
    );
    const result = await this.commitEntries((current) => ({ entries: current.concat([entry]) }));
    if (!result.written) return false;
    return entry;
  }

  async updateEntry(id, input) {
    this.assertUnlocked();
    const base = normalizeEntryInput(input);
    // 查找与比对都放进串行队列，避免并发保存拿到过期快照后互相覆盖
    const result = await this.commitEntries((current) => {
      const index = current.findIndex((entry) => entry.id === id);
      if (index < 0) throw new Error(this.t('err_vault_corrupt'));
      const previous = current[index];
      const unchanged =
        previous.name === base.name &&
        previous.type === base.type &&
        previous.content === base.content &&
        previous.note === base.note &&
        JSON.stringify(previous.tags) === JSON.stringify(base.tags);
      if (unchanged) return { entries: null };
      const next = current.slice();
      next[index] = Object.assign({}, previous, base, { updatedAt: new Date().toISOString() });
      return { entries: next };
    });
    if (result.unchanged) return 'unchanged';
    if (!result.written) return false;
    return true;
  }

  async deleteEntry(id) {
    this.assertUnlocked();
    const result = await this.commitEntries((current) => {
      const next = current.filter((entry) => entry.id !== id);
      if (next.length === current.length) return { entries: null };
      return { entries: next };
    });
    if (result.unchanged || !result.written) return false;
    return true;
  }

  newEntryId() {
    const cryptoObj = this.requireCrypto();
    if (typeof cryptoObj.randomUUID === 'function') return cryptoObj.randomUUID();
    return Array.from(randomBytes(cryptoObj, 16), (byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  /* ---------------- 剪贴板与自动锁定 ---------------- */

  async copySecret(text) {
    if (!text) return false;
    this.touchActivity();
    if (!this.isUnlocked()) return false;
    if (this.suspended) {
      new Notice(this.t('err_suspended'), 5000);
      return false;
    }
    if (this.conflictPending) {
      new Notice(this.t('err_conflict_editing_blocked'), 6000);
      return false;
    }
    if (
      typeof navigator === 'undefined' ||
      !navigator.clipboard ||
      typeof navigator.clipboard.writeText !== 'function'
    ) {
      new Notice(this.t('err_clipboard_unavailable'), 6000);
      return false;
    }
    try {
      await navigator.clipboard.writeText(text);
    } catch (error) {
      console.error('[' + PLUGIN_ID + '] clipboard write failed:', error);
      new Notice(this.t('err_clipboard_unavailable'), 6000);
      return false;
    }
    // 写剪贴板期间若已锁定，立即清空，不再把明文写回内存或起定时器
    if (!this.isUnlocked()) {
      try {
        await navigator.clipboard.writeText('');
      } catch (error) {
        console.error('[' + PLUGIN_ID + '] clipboard cleanup failed:', error);
      }
      return false;
    }
    this.clipboardText = text;
    this.clearClipboardTimer();
    const seconds = Math.max(5, Number(this.settings.clipboardClearSeconds) || 30);
    new Notice(this.t('notice_copied', { seconds }), 4000);
    this.clipboardTimer = globalThis.setTimeout(() => {
      void this.clearClipboardIfOwned(true);
    }, seconds * 1000);
    return true;
  }

  async clearClipboardIfOwned(notify) {
    const owned = this.clipboardText;
    this.clipboardText = null;
    this.clearClipboardTimer();
    if (!owned) return;
    if (
      typeof navigator === 'undefined' ||
      !navigator.clipboard ||
      typeof navigator.clipboard.writeText !== 'function'
    ) {
      return;
    }
    let current = null;
    let readFailed = true;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        current = await navigator.clipboard.readText();
        readFailed = false;
        break;
      } catch (error) {
        readFailed = true;
        await delay(60);
      }
    }
    // 读不到剪贴板就不做任何写入：无法确认内容时只提示手动检查，避免误清用户内容
    if (readFailed) {
      if (notify) new Notice(this.t('notice_clipboard_unverified'), 6000);
      return;
    }
    if (current !== owned) return;
    // 清空前的最后一次确认，仅当内容确实仍是本插件写入的值时才清
    try {
      const confirmation = await navigator.clipboard.readText();
      if (confirmation !== owned) return;
    } catch (error) {
      if (notify) new Notice(this.t('notice_clipboard_unverified'), 6000);
      return;
    }
    try {
      await navigator.clipboard.writeText('');
      if (notify) new Notice(this.t('notice_clipboard_cleared'), 3000);
    } catch (error) {
      console.error('[' + PLUGIN_ID + '] clipboard clear failed:', error);
      new Notice(this.t('notice_clipboard_unverified'), 6000);
    }
  }

  clearClipboardTimer() {
    if (this.clipboardTimer) {
      globalThis.clearTimeout(this.clipboardTimer);
      this.clipboardTimer = 0;
    }
  }

  resetIdleTimer() {
    if (!this.isUnlocked()) {
      this.idleDeadline = 0;
      this.idleDeadlineWall = 0;
      return;
    }
    const minutes = Math.max(1, Number(this.settings.autoLockMinutes) || 15);
    const span = minutes * 60000;
    // 单调钟防系统时间回拨，墙钟防合盖休眠（performance.now 在休眠期间不前进）
    this.idleDeadline = this.nowMs() + span;
    this.idleDeadlineWall = Date.now() + span;
  }

  touchActivity() {
    if (this.isUnlocked()) this.resetIdleTimer();
  }

  // 后台超过阈值：直接锁定并清屏
  lockFromBackground() {
    if (!this.isUnlocked()) return;
    this.lock();
    new Notice(this.t('notice_background_locked'), 6000);
  }

  unmaskAllViews() {
    const leaves = this.app.workspace.getLeavesOfType(VIEW_TYPE) || [];
    for (const leaf of leaves) {
      const view = leaf && leaf.view;
      if (!view || typeof view !== 'object') continue;
      view.masked = false;
      if (view.revealedCells && typeof view.revealedCells.clear === 'function') view.revealedCells.clear();
    }
  }

  maskAllViews() {
    try {
      const leaves = this.app.workspace.getLeavesOfType(VIEW_TYPE);
      for (const leaf of leaves) {
        const view = leaf && leaf.view;
        if (view && typeof view.maskSensitive === 'function') view.maskSensitive();
      }
    } catch (error) {
      console.error('[' + PLUGIN_ID + '] mask views failed:', error);
    }
  }

  countdownActive() {
    return !!(this.countdownDeadline || this.countdownDeadlineWall);
  }

  // 双时钟取大：合盖休眠后墙钟已前进，单调钟可能停摆；两者任一超时即视为到点
  getCountdownRemaining() {
    if (!this.countdownActive()) return -1;
    const monoRemaining = this.countdownDeadline ? this.countdownDeadline - this.nowMs() : 0;
    const wallRemaining = this.countdownDeadlineWall ? this.countdownDeadlineWall - Date.now() : 0;
    return Math.max(monoRemaining, wallRemaining);
  }

  startCountdown(seconds) {
    this.stopCountdown();
    if (seconds <= 0) return;
    const span = seconds * 1000;
    this.countdownSeconds = seconds;
    this.countdownDeadline = this.nowMs() + span;
    this.countdownDeadlineWall = Date.now() + span;
    this.countdownTimer = globalThis.setInterval(() => this.tickCountdown(), 1000);
  }

  stopCountdown() {
    if (this.countdownTimer) {
      globalThis.clearInterval(this.countdownTimer);
      this.countdownTimer = 0;
    }
    this.countdownDeadline = 0;
    this.countdownDeadlineWall = 0;
    this.countdownSeconds = 0;
  }

  tickCountdown() {
    if (!this.isUnlocked() || !this.suspended) {
      this.stopCountdown();
      return;
    }
    const remaining = this.getCountdownRemaining();
    if (remaining <= 0) {
      this.finishCountdownLock();
      return;
    }
    this.updateCountdownViews(remaining);
  }

  updateCountdownViews(remainingMs) {
    const seconds = Math.max(0, Math.ceil(remainingMs / 1000));
    try {
      const leaves = this.app.workspace.getLeavesOfType(VIEW_TYPE);
      for (const leaf of leaves) {
        const view = leaf && leaf.view;
        if (view && view.masked && typeof view.updateMaskCountdown === 'function') {
          view.updateMaskCountdown(seconds);
        }
      }
    } catch (error) {
      /* ignore */
    }
  }

  finishCountdownLock() {
    this.stopCountdown();
    this.lock();
    new Notice(this.t('notice_countdown_locked'), 6000);
  }

  // reason='background'：倒计时内回来自动恢复；reason='panel'：多面板需重新验证
  suspendForBackground(reason) {
    if (!this.isUnlocked()) return;
    const nextReason = reason || 'background';
    // 多面板的重验尚未完成时，不被后续失焦倒计时绕过
    if (this.suspended && this.suspendReason === 'panel' && nextReason === 'background') return;
    this.suspended = true;
    this.suspendReason = nextReason;
    const seconds = nextReason === 'panel' ? 0 : this.getBackgroundLockSeconds();
    if (seconds <= 0) {
      // 立即 = 原来的严格行为：不保留会话，回来必须重输主密码
      if (nextReason !== 'panel') {
        this.lock();
        new Notice(this.t('notice_locked_done'), 3000);
        return;
      }
      this.stopCountdown();
    } else {
      this.startCountdown(seconds);
    }
    this.clearViewScreens();
    this.maskAllViews();
    this.refreshViews();
  }

  resumeFromBackground() {
    if (!this.isUnlocked() || !this.suspended) return;
    this.suspended = false;
    this.suspendReason = '';
    this.hiddenAt = 0;
    this.hiddenAtWall = 0;
    this.stopCountdown();
    this.unmaskAllViews();
    this.resetIdleTimer();
    this.refreshViews();
  }

  // 回到前台：倒计时内直接恢复；已到点则锁定；多面板挂起保持遮罩等待重验
  handleForeground() {
    if (!this.isUnlocked() || !this.suspended) return;
    // 多面板重验未完成：保持遮罩，必须验证主密码
    if (this.suspendReason === 'panel') return;
    const remaining = this.getCountdownRemaining();
    if (remaining < 0) return;
    if (remaining <= 0) {
      this.finishCountdownLock();
      return;
    }
    this.resumeFromBackground();
  }

  handleVisibilityChange() {
    const hidden = typeof document !== 'undefined' && document ? !!document.hidden : false;
    if (hidden) {
      this.hiddenAt = this.hiddenAt || this.nowMs();
      this.hiddenAtWall = this.hiddenAtWall || Date.now();
      this.suspendForBackground('background');
      return;
    }
    const elapsed = Math.max(
      this.hiddenAt ? this.nowMs() - this.hiddenAt : 0,
      this.hiddenAtWall ? Date.now() - this.hiddenAtWall : 0
    );
    this.hiddenAt = 0;
    this.hiddenAtWall = 0;
    if (this.isUnlocked() && elapsed >= HIDDEN_LOCK_MS) {
      this.lockFromBackground();
      return;
    }
    this.handleForeground();
  }

  handleWindowBlur() {
    if (typeof document !== 'undefined' && document && document.hidden) return;
    this.hiddenAt = this.hiddenAt || this.nowMs();
    this.hiddenAtWall = this.hiddenAtWall || Date.now();
    this.suspendForBackground('background');
  }

  handleWindowFocus() {
    if (typeof document !== 'undefined' && document && document.hidden) return;
    this.handleForeground();
  }

  checkAutoLock() {
    if (!this.isUnlocked()) return;
    // 三套机制取最早触发者：失焦倒计时、后台 60 秒、空闲自动锁
    if (this.suspended && this.countdownActive() && this.getCountdownRemaining() <= 0) {
      this.finishCountdownLock();
      return;
    }
    // 取墙钟与单调钟的较大者：休眠/回拨任一异常时另一种仍能兜底
    const hiddenElapsed = Math.max(
      this.hiddenAt ? this.nowMs() - this.hiddenAt : 0,
      this.hiddenAtWall ? Date.now() - this.hiddenAtWall : 0
    );
    if (hiddenElapsed >= HIDDEN_LOCK_MS) {
      this.lockFromBackground();
      return;
    }
    if (this.suspended && this.countdownActive()) {
      this.updateCountdownViews(this.getCountdownRemaining());
    }
    const idleExpired =
      (this.idleDeadline > 0 && this.nowMs() >= this.idleDeadline) ||
      (this.idleDeadlineWall > 0 && Date.now() >= this.idleDeadlineWall);
    if (idleExpired) {
      this.stopCountdown();
      this.lock();
      new Notice(this.t('notice_auto_locked'), 6000);
    }
  }

  /* ---------------- 视图与命令 ---------------- */

  refreshViews() {
    try {
      const leaves = this.app.workspace.getLeavesOfType(VIEW_TYPE);
      for (const leaf of leaves) {
        const view = leaf && leaf.view;
        if (
          view &&
          typeof view.getViewType === 'function' &&
          view.getViewType() === VIEW_TYPE &&
          typeof view.render === 'function'
        ) {
          try {
            view.render();
          } catch (error) {
            console.error('[' + PLUGIN_ID + '] render view failed:', error);
          }
        }
      }
    } catch (error) {
      console.error('[' + PLUGIN_ID + '] refresh views failed:', error);
    }
  }

  // 在主编辑区打开整页视图；已存在时只聚焦，不新建
  async openVaultView() {
    // 快照旧 leaf 集合：后续只对「本次新建」的 leaf 做兜底清理
    let leaves = this.app.workspace.getLeavesOfType(VIEW_TYPE).slice();
    if (!leaves.length) {
      await delay(60);
      leaves = this.app.workspace.getLeavesOfType(VIEW_TYPE).slice();
    }
    if (leaves.length) {
      await this.app.workspace.revealLeaf(leaves[0]);
      return leaves[0];
    }

    const workspace = this.app.workspace;
    let created = null;
    if (typeof workspace.getLeaf === 'function') {
      created = workspace.getLeaf(true);
    }
    if (!created) {
      new Notice(this.t('err_view_open_failed'), 5000);
      return null;
    }
    try {
      await created.setViewState({ type: VIEW_TYPE, active: true });
    } catch (error) {
      /* 下面统一做延时复查 */
    }

    // ghost / empty 占位复查：视图可能晚一拍才挂到 leaf 上
    let ready = false;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      leaves = this.app.workspace.getLeavesOfType(VIEW_TYPE).slice();
      if (leaves.length) {
        ready = true;
        break;
      }
      await delay(attempt === 0 ? 80 : 200);
    }
    if (ready) {
      // 单实例：若此时已有多张，只聚焦最早一张，不批量 detach
      await this.app.workspace.revealLeaf(leaves[0]);
      return leaves[0];
    }

    // 500ms 兜底：仍然只有空占位，撤掉本次自己新建的 leaf，不动旧 leaf
    await delay(220);
    leaves = this.app.workspace.getLeavesOfType(VIEW_TYPE).slice();
    if (leaves.length) {
      await this.app.workspace.revealLeaf(leaves[0]);
      return leaves[0];
    }
    try {
      created.detach();
    } catch (error) {
      /* ignore */
    }
    new Notice(this.t('err_view_open_failed'), 5000);
    return null;
  }
}

module.exports = XUSecretVault;
