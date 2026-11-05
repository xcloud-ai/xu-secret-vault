/* XU Secret Vault — 本地加密密钥保险库（明文不落盘） */
'use strict';

const { ItemView, Modal, Notice, Plugin, PluginSettingTab, Setting } = require('obsidian');

const PLUGIN_ID = 'xu-secret-vault';
const VIEW_TYPE = 'xu-secret-vault-view';
const REPO_URL = 'https://github.com/xcloud-ai/xu-secret-vault';
const DEFAULT_VAULT_PATH = 'xu-secrets.enc';
const FORMAT_VERSION = 1;
const KDF_ALGO = 'PBKDF2-SHA512';
const KDF_HASH = 'SHA-512';
const KDF_ITERATIONS = 600000;
const AAD_PREFIX = 'xsv-aad-v2';
const CIPHER_ALGO = 'AES-256-GCM';
const TAG_LENGTH = 128;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const MAX_VAULT_BYTES = 8 * 1024 * 1024;
const HIDDEN_LOCK_MS = 60000;
const BACKOFF_BASE_MS = 500;
const BACKOFF_MAX_MS = 30000;
const ENTRY_TYPES = ['password', 'api-key', 'private-key', 'note'];

const DEFAULT_SETTINGS = {
  language: 'zh',
  vaultPath: DEFAULT_VAULT_PATH,
  autoLockMinutes: 15,
  clipboardClearSeconds: 30,
  initializedPath: '',
};

const I18N = {
  zh: {
    cmd_open: '打开密钥保险库',
    cmd_lock: '锁定保险库',
    cmd_add: '新增条目',
    view_title: '密钥保险库',
    subtitle_locked: '保险库已锁定',
    subtitle_unlocked: '已解锁 · {count} 个条目',
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
    err_generic: '操作失败：{msg}',
    setting_title: 'XU Secret Vault（密钥保险库）',
    setting_header_desc: '在本地加密保存密码、API 密钥与私钥；明文不写入任何笔记或明文文件。',
    setting_group_vault: '保险库',
    setting_group_security: '安全',
    setting_group_about: '关于',
    setting_language: '界面语言',
    setting_language_desc: '切换中文 / English。',
    setting_vault_path: '保险库文件路径',
    setting_vault_path_desc: '相对 vault 根目录的路径，必须以 .enc 结尾（缺失时自动补全）。默认 xu-secrets.enc。',
    setting_auto_lock: '自动锁定（分钟）',
    setting_auto_lock_desc: '无操作超过该时长后自动锁定（默认 15 分钟）；切到后台超过 60 秒也会立即锁定，并清除内存中的密钥与已显形的明文。',
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
    notice_conflict: '检测到保险库文件被外部修改，已拒绝覆盖；本次改动另存为 {path}。',
    notice_clipboard_forced: '无法读取剪贴板，已无条件清空以防明文残留。',
    notice_background_locked: '插件在后台超过 60 秒，保险库已自动锁定。',
    notice_reverify_failed: '验证失败，请重新输入主密码。',
    mask_title: '内容已隐藏',
    mask_desc: '窗口失去焦点或切到后台，面板已加上遮罩并清除已显形的明文。请输入主密码继续查看。',
    btn_reverify: '验证并继续',
  },
  en: {
    cmd_open: 'Open secret vault',
    cmd_lock: 'Lock secret vault',
    cmd_add: 'Add entry',
    view_title: 'Secret Vault',
    subtitle_locked: 'Vault is locked',
    subtitle_unlocked: 'Unlocked · {count} entries',
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
    err_generic: 'Operation failed: {msg}',
    setting_title: 'XU Secret Vault',
    setting_header_desc: 'Encrypt passwords, API keys and private keys locally; plaintext is never written to notes or plaintext files.',
    setting_group_vault: 'Vault',
    setting_group_security: 'Security',
    setting_group_about: 'About',
    setting_language: 'Language',
    setting_language_desc: 'Switch between Chinese and English.',
    setting_vault_path: 'Vault file path',
    setting_vault_path_desc: 'Path relative to the vault root. It must end with .enc (added automatically if missing). Default: xu-secrets.enc.',
    setting_auto_lock: 'Auto-lock (minutes)',
    setting_auto_lock_desc: 'Lock automatically after this idle period (default 15 minutes). Moving to the background for more than 60 seconds also locks immediately and clears keys and revealed plaintext from memory.',
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
    notice_conflict: 'The vault file was modified externally, so overwriting was refused. This change was saved as {path}.',
    notice_clipboard_forced: 'The clipboard could not be read; it was cleared unconditionally to avoid leaking plaintext.',
    notice_background_locked: 'The plugin was in the background for over 60 seconds, so the vault was locked.',
    notice_reverify_failed: 'Verification failed. Enter the master password again.',
    mask_title: 'Content hidden',
    mask_desc: 'The window lost focus or moved to the background, so the panel is masked and revealed plaintext was cleared. Enter the master password to continue.',
    btn_reverify: 'Verify and continue',
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
function buildAad(formatVersion, kdfAlgo, iterations, saltBase64, cipherAlgo) {
  return utf8Encode(
    [AAD_PREFIX, formatVersion, kdfAlgo, String(iterations), saltBase64, cipherAlgo].join('|')
  );
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

function sameJson(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
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

/* ------------------------------------------------------------------ */
/* 设置页（1.13 声明式 Path A：仅 getSettingDefinitions，无 display）      */
/* ------------------------------------------------------------------ */
class SecretVaultSettingTab extends PluginSettingTab {
  getSettingDefinitions() {
    const plugin = this.plugin;
    const t = (key) => plugin.t(key);
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
            name: t('setting_clipboard_clear'),
            desc: t('setting_clipboard_clear_desc'),
            control: { type: 'slider', key: 'clipboardClearSeconds', min: 5, max: 120, step: 5 },
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
  }
}

/* ------------------------------------------------------------------ */
/* 侧边栏视图                                                          */
/* ------------------------------------------------------------------ */
class SecretVaultView extends ItemView {
  constructor(leaf, plugin) {
    super(leaf);
    this.plugin = plugin;
    this.query = '';
    this.revealed = new Set();
    this.uiError = '';
    this.detecting = false;
    this.masked = false;
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
    this.render();
    void this.ensureVaultState();
  }

  // 关闭面板即清屏并锁定，避免"关了但视图仍缓存明文"
  async onClose() {
    this.clearSensitive();
    this.masked = false;
    this.plugin.lock();
  }

  // 锁定时同步清屏：立即移除已显形的明文，而不是只丢缓存
  clearSensitive() {
    this.revealed.clear();
    this.query = '';
    this.uiError = '';
    this.masked = false;
    if (this.contentEl) this.contentEl.empty();
  }

  // 切后台/失焦：立刻加遮罩并清屏，回到前台需重新验证主密码
  maskSensitive() {
    if (!this.plugin.isUnlocked()) return;
    this.revealed.clear();
    this.query = '';
    this.masked = true;
    if (this.contentEl) this.contentEl.empty();
    this.render();
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
      this.revealed.clear();
      this.masked = false;
    }

    const root = el.createDiv({ cls: 'xsv-view' });
    if (!this.plugin.cryptoApi) {
      root.createDiv({ cls: 'xsv-title', text: this.plugin.t('view_title') });
      root.createDiv({ cls: 'xsv-error', text: this.plugin.t('err_crypto_unavailable') });
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
        errorEl.setText(this.plugin.t('notice_reverify_failed'));
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
    root.createDiv({ cls: 'xsv-title', text: this.plugin.t('setup_title') });
    root.createDiv({ cls: 'xsv-desc', text: this.plugin.t('setup_desc') });
    const password = this.createPasswordField(root, this.plugin.t('label_password'), () => submit());
    const confirm = this.createPasswordField(root, this.plugin.t('label_confirm_password'), () => submit());
    this.renderError(root);
    const actions = root.createDiv({ cls: 'xsv-actions xsv-actions-start' });
    const createButton = actions.createEl('button', { cls: 'xsv-btn xsv-btn-primary', text: this.plugin.t('btn_create') });

    const submit = async () => {
      const value = password.value;
      if (!value) {
        this.uiError = this.plugin.t('err_password_required');
        this.render();
        return;
      }
      if (value !== confirm.value) {
        this.uiError = this.plugin.t('err_password_mismatch');
        this.render();
        return;
      }
      this.uiError = '';
      try {
        await this.plugin.createVault(value);
        this.plugin.vaultState = 'present';
        new Notice(this.plugin.t('notice_vault_created'), 3000);
        this.render();
      } catch (error) {
        console.error('[' + PLUGIN_ID + '] create vault failed:', error);
        this.uiError = this.plugin.t('err_generic', { msg: errorMessage(error) });
        this.render();
      }
    };

    createButton.addEventListener('click', () => void submit());
    root.createDiv({ cls: 'xsv-hint', text: this.plugin.t('hint_locked_state') });
  }

  renderUnlock(root) {
    this.renderHeader(root, this.plugin.t('subtitle_locked'));
    root.createDiv({ cls: 'xsv-desc', text: this.plugin.t('unlock_desc') });
    const password = this.createPasswordField(root, this.plugin.t('label_password'), () => submit());
    this.renderError(root);
    const actions = root.createDiv({ cls: 'xsv-actions xsv-actions-start' });
    const unlockButton = actions.createEl('button', { cls: 'xsv-btn xsv-btn-primary', text: this.plugin.t('btn_unlock') });

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
    root.createDiv({ cls: 'xsv-hint', text: this.plugin.t('hint_locked_state') });
  }

  renderUnlocked(root) {
    const header = this.renderHeader(root, this.plugin.t('subtitle_unlocked', { count: this.plugin.entries.length }));
    const lockButton = header.createEl('button', { cls: 'xsv-btn xsv-btn-small', text: this.plugin.t('btn_lock') });
    lockButton.addEventListener('click', () => this.plugin.lock());

    root.createDiv({ cls: 'xsv-hint', text: this.plugin.t('hint_encrypted') });

    const toolbar = root.createDiv({ cls: 'xsv-toolbar' });
    const search = toolbar.createEl('input', { type: 'text', cls: 'xsv-input xsv-search' });
    search.value = this.query;
    search.setAttribute('placeholder', this.plugin.t('search_placeholder'));
    search.addEventListener('input', () => {
      this.query = search.value;
      this.render();
      globalThis.setTimeout(() => {
        const next = this.contentEl.querySelector ? this.contentEl.querySelector('.xsv-search') : null;
        if (next && typeof next.focus === 'function') {
          next.focus();
          try {
            const end = next.value.length;
            next.setSelectionRange(end, end);
          } catch (error) {
            /* ignore */
          }
        }
      }, 0);
    });

    const addButton = toolbar.createEl('button', { cls: 'xsv-btn xsv-btn-primary', text: this.plugin.t('btn_add') });
    addButton.addEventListener('click', () => this.openAddModal());

    const needle = this.query.trim().toLowerCase();
    const entries = this.plugin.entries.filter((entry) => {
      if (!needle) return true;
      const haystack = [entry.name, entry.type, entry.tags.join(' ')].join(' ').toLowerCase();
      return haystack.indexOf(needle) >= 0;
    });

    const list = root.createDiv({ cls: 'xsv-list' });
    if (!entries.length) {
      list.createDiv({ cls: 'xsv-empty', text: this.plugin.t(this.query.trim() ? 'empty_search' : 'empty_entries') });
      return;
    }
    for (const entry of entries) this.renderEntry(list, entry);
  }

  renderEntry(parent, entry) {
    const row = parent.createDiv({ cls: 'xsv-item' });
    const head = row.createDiv({ cls: 'xsv-item-head' });
    head.createDiv({ cls: 'xsv-item-name', text: entry.name });
    head.createDiv({ cls: 'xsv-badge', text: this.plugin.typeLabel(entry.type) });
    if (entry.tags.length) {
      const tags = head.createDiv({ cls: 'xsv-tags' });
      for (const tag of entry.tags) tags.createDiv({ cls: 'xsv-tag', text: tag });
    }

    const revealed = this.revealed.has(entry.id);
    const contentWrap = row.createDiv({ cls: 'xsv-content-wrap' });
    if (revealed) contentWrap.createDiv({ cls: 'xsv-content', text: entry.content || '' });
    else contentWrap.createDiv({ cls: 'xsv-masked', text: '••••••••' });

    const actions = row.createDiv({ cls: 'xsv-actions' });
    const revealButton = actions.createEl('button', {
      cls: 'xsv-btn xsv-btn-small',
      text: this.plugin.t(revealed ? 'btn_hide' : 'btn_reveal'),
    });
    revealButton.addEventListener('click', () => {
      if (revealed) this.revealed.delete(entry.id);
      else this.revealed.add(entry.id);
      this.render();
    });

    const copyButton = actions.createEl('button', { cls: 'xsv-btn xsv-btn-small', text: this.plugin.t('btn_copy') });
    copyButton.addEventListener('click', () => void this.plugin.copySecret(entry.content));

    const editButton = actions.createEl('button', { cls: 'xsv-btn xsv-btn-small', text: this.plugin.t('btn_edit') });
    editButton.addEventListener('click', () => {
      new SecretEntryModal(this.app, this.plugin, entry).open();
    });

    const deleteButton = actions.createEl('button', {
      cls: 'xsv-btn xsv-btn-small xsv-btn-danger',
      text: this.plugin.t('btn_delete'),
    });
    deleteButton.addEventListener('click', () => {
      new SecretDeleteModal(this.app, this.plugin, entry).open();
    });
  }

  openAddModal() {
    if (!this.plugin.isUnlocked()) {
      new Notice(this.plugin.t('notice_unlock_first'), 4000);
      return;
    }
    new SecretEntryModal(this.app, this.plugin, null).open();
  }
}

/* ------------------------------------------------------------------ */
/* 新增 / 编辑弹窗                                                      */
/* ------------------------------------------------------------------ */
class SecretEntryModal extends Modal {
  constructor(app, plugin, entry) {
    super(app);
    this.plugin = plugin;
    this.entry = entry || null;
    this.draftContent = entry ? entry.content : '';
    this.contentRevealed = !entry;
  }

  onOpen() {
    this.plugin.trackModal(this);
    this.plugin.touchActivity();
    const plugin = this.plugin;
    const entry = this.entry;
    const t = (key, vars) => plugin.t(key, vars);
    this.titleEl.setText(t(entry ? 'title_edit_entry' : 'title_new_entry'));

    const form = this.contentEl.createDiv({ cls: 'xsv-modal' });
    const field = (label) => {
      const wrap = form.createDiv({ cls: 'xsv-field' });
      wrap.createDiv({ cls: 'xsv-label', text: label });
      return wrap;
    };
    const bindActivity = (el) => {
      el.addEventListener('input', () => plugin.touchActivity());
      el.addEventListener('keydown', () => plugin.touchActivity());
      el.addEventListener('change', () => plugin.touchActivity());
    };
    const harden = (el) => {
      el.autocomplete = 'off';
      el.spellcheck = false;
      el.setAttribute('autocomplete', 'off');
      el.setAttribute('spellcheck', 'false');
      el.addEventListener('dragstart', (event) => {
        if (event && typeof event.preventDefault === 'function') event.preventDefault();
      });
    };

    const nameWrap = field(t('field_name'));
    const nameInput = nameWrap.createEl('input', { type: 'text', cls: 'xsv-input' });
    nameInput.value = entry ? entry.name : '';
    harden(nameInput);
    bindActivity(nameInput);

    const typeWrap = field(t('field_type'));
    const typeSelect = typeWrap.createEl('select', { cls: 'xsv-input' });
    for (const type of ENTRY_TYPES) {
      const option = typeSelect.createEl('option', { text: plugin.typeLabel(type) });
      option.value = type;
    }
    typeSelect.value = entry ? entry.type : 'password';
    bindActivity(typeSelect);

    const tagsWrap = field(t('field_tags'));
    const tagsInput = tagsWrap.createEl('input', { type: 'text', cls: 'xsv-input' });
    tagsInput.value = entry ? entry.tags.join(', ') : '';
    tagsInput.setAttribute('placeholder', t('tags_placeholder'));
    harden(tagsInput);
    bindActivity(tagsInput);

    // 内容默认掩码，必须点「显示」才呈现；关闭弹窗即复位
    const contentWrap = field(t('field_content'));
    let contentInput = null;
    const renderContentArea = () => {
      contentWrap.empty();
      if (this.contentRevealed) {
        contentInput = contentWrap.createEl('textarea', { cls: 'xsv-input xsv-textarea' });
        contentInput.rows = 6;
        contentInput.value = this.draftContent;
        contentInput.spellcheck = false;
        contentInput.setAttribute('autocomplete', 'off');
        contentInput.setAttribute('spellcheck', 'false');
        contentInput.addEventListener('dragstart', (event) => {
          if (event && typeof event.preventDefault === 'function') event.preventDefault();
        });
        bindActivity(contentInput);
        return;
      }
      contentInput = null;
      contentWrap.createDiv({ cls: 'xsv-masked', text: '••••••••' });
      const showButton = contentWrap.createEl('button', {
        cls: 'xsv-btn xsv-btn-small',
        text: t('btn_reveal'),
      });
      showButton.addEventListener('click', () => {
        this.contentRevealed = true;
        plugin.touchActivity();
        renderContentArea();
      });
    };
    renderContentArea();

    const noteWrap = field(t('field_note'));
    const noteInput = noteWrap.createEl('textarea', { cls: 'xsv-input xsv-textarea' });
    noteInput.rows = 2;
    noteInput.value = entry ? entry.note : '';
    harden(noteInput);
    bindActivity(noteInput);

    const errorEl = form.createDiv({ cls: 'xsv-error' });
    errorEl.setText('');

    const actions = form.createDiv({ cls: 'xsv-actions' });
    const cancelButton = actions.createEl('button', { cls: 'xsv-btn', text: t('btn_cancel') });
    cancelButton.addEventListener('click', () => this.close());
    const saveButton = actions.createEl('button', {
      cls: 'xsv-btn xsv-btn-primary',
      text: t('btn_save'),
    });

    const submit = async () => {
      const name = nameInput.value.trim();
      if (!name) {
        errorEl.setText(t('notice_name_required'));
        return;
      }
      const payload = {
        name,
        type: typeSelect.value,
        tags: sanitizeTags(tagsInput.value),
        content: this.contentRevealed && contentInput ? contentInput.value : this.draftContent,
        note: noteInput.value,
      };
      errorEl.setText('');
      saveButton.disabled = true;
      try {
        if (entry) {
          const result = await plugin.updateEntry(entry.id, payload);
          if (result === false) {
            // 锁定 / 外部冲突 / 写盘失败：不得再提示“已保存”
            errorEl.setText(t('err_save_discarded'));
            return;
          }
          new Notice(t(result === 'unchanged' ? 'notice_unchanged' : 'notice_saved'), 3000);
        } else {
          const created = await plugin.addEntry(payload);
          if (!created) {
            errorEl.setText(t('err_save_discarded'));
            return;
          }
          new Notice(t('notice_saved'), 3000);
        }
        this.close();
      } catch (error) {
        console.error('[' + PLUGIN_ID + '] save entry failed:', error);
        errorEl.setText(t('err_generic', { msg: errorMessage(error) }));
      } finally {
        saveButton.disabled = false;
      }
    };

    saveButton.addEventListener('click', () => void submit());
    if (!entry && typeof nameInput.focus === 'function') nameInput.focus();
  }

  onClose() {
    this.plugin.untrackModal(this);
    this.contentEl.empty();
    this.draftContent = '';
    this.contentRevealed = false;
  }
}

/* ------------------------------------------------------------------ */
/* 删除确认弹窗                                                        */
/* ------------------------------------------------------------------ */
class SecretDeleteModal extends Modal {
  constructor(app, plugin, entry) {
    super(app);
    this.plugin = plugin;
    this.entry = entry;
  }

  onOpen() {
    this.plugin.trackModal(this);
    this.plugin.touchActivity();
    this.titleEl.setText(this.plugin.t('delete_title'));
    this.contentEl.createDiv({
      cls: 'xsv-desc',
      text: this.plugin.t('delete_desc', { name: this.entry.name }),
    });
    const actions = this.contentEl.createDiv({ cls: 'xsv-actions' });
    const cancelButton = actions.createEl('button', { cls: 'xsv-btn', text: this.plugin.t('btn_cancel') });
    cancelButton.addEventListener('click', () => this.close());
    const deleteButton = actions.createEl('button', {
      cls: 'xsv-btn xsv-btn-danger',
      text: this.plugin.t('btn_confirm_delete'),
    });
    deleteButton.addEventListener('click', async () => {
      deleteButton.disabled = true;
      try {
        const deleted = await this.plugin.deleteEntry(this.entry.id);
        if (!deleted) {
          new Notice(this.plugin.t('err_save_discarded'), 6000);
          deleteButton.disabled = false;
          return;
        }
        new Notice(this.plugin.t('notice_deleted'), 3000);
        this.close();
        this.plugin.refreshViews();
      } catch (error) {
        console.error('[' + PLUGIN_ID + '] delete entry failed:', error);
        new Notice(this.plugin.t('err_generic', { msg: errorMessage(error) }), 6000);
        deleteButton.disabled = false;
      }
    });
  }

  onClose() {
    this.plugin.untrackModal(this);
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
  entries = [];
  vaultState = 'unknown';
  idleDeadline = 0;
  clipboardTimer = 0;
  clipboardText = null;
  openModals = new Set();
  writeChain = Promise.resolve();
  sessionGeneration = 0;
  knownBlobHash = null;
  passwordVerifier = null;
  failureCount = 0;
  blockedUntil = 0;
  hiddenAt = 0;
  suspended = false;
  lastUnlockError = '';

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
    this.addSettingTab(new SecretVaultSettingTab(this.app, this));

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
    this.addCommand({
      id: 'new-entry',
      name: this.t('cmd_add'),
      callback: () => {
        void this.openEntryCreator();
      },
    });

    this.registerInterval(globalThis.setInterval(() => this.checkAutoLock(), 15000));

    // 切后台 / 失焦：立即遮罩并清屏；hidden 超过 60 秒直接锁定
    if (typeof document !== 'undefined' && document && typeof document.addEventListener === 'function') {
      this.registerDomEvent(document, 'visibilitychange', () => this.handleVisibilityChange());
    }
    if (typeof window !== 'undefined' && window && typeof window.addEventListener === 'function') {
      this.registerDomEvent(window, 'blur', () => this.handleWindowBlur());
    }

    this.app.workspace.onLayoutReady(() => {
      if (!this.cryptoApi) new Notice(this.t('err_crypto_unavailable'), 10000);
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
  }

  async saveSettings() {
    await this.saveData(this.settings);
  }

  normalizeVaultPath(raw) {
    let path = String(raw == null ? '' : raw).trim().replace(/\\/g, '/');
    const parts = path.split('/').filter((part) => part && part !== '.' && part !== '..');
    path = parts.join('/');
    if (!path) path = DEFAULT_VAULT_PATH;
    if (!/\.enc$/i.test(path)) path += '.enc';
    return path;
  }

  getVaultPath() {
    return this.normalizeVaultPath(this.settings.vaultPath);
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
      this.vaultState = (await this.app.vault.adapter.exists(this.getVaultPath())) ? 'present' : 'absent';
    } catch (error) {
      console.error('[' + PLUGIN_ID + '] detect vault failed:', error);
      // 读取异常不能当成"文件不存在"，否则会引导用户创建并覆盖同名旧库
      this.vaultState = 'error';
    }
    this.refreshViews();
    return this.vaultState;
  }

  /* ---------------- 加密原语 ---------------- */

  async deriveKey(password, salt, iterations) {
    const cryptoObj = this.requireCrypto();
    const material = await cryptoObj.subtle.importKey(
      'raw',
      utf8Encode(normalizePassword(password)),
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

  async hashText(text) {
    const cryptoObj = this.requireCrypto();
    const digest = await cryptoObj.subtle.digest('SHA-256', utf8Encode(text));
    return bytesToBase64(digest);
  }

  async encryptToEnvelope(entries, key, salt, iterations) {
    const cryptoObj = this.requireCrypto();
    const iv = randomBytes(cryptoObj, IV_BYTES);
    const saltBase64 = bytesToBase64(salt);
    // updatedAt 放进加密载荷，不在信封头上明文暴露
    const plaintext = JSON.stringify({
      version: FORMAT_VERSION,
      updatedAt: new Date().toISOString(),
      entries,
    });
    const ciphertext = await cryptoObj.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: buildAad(FORMAT_VERSION, KDF_ALGO, iterations, saltBase64, CIPHER_ALGO),
        tagLength: TAG_LENGTH,
      },
      key,
      utf8Encode(plaintext)
    );
    return {
      formatVersion: FORMAT_VERSION,
      kdf: {
        algo: KDF_ALGO,
        iterations,
        salt: saltBase64,
      },
      cipher: {
        algo: CIPHER_ALGO,
        iv: bytesToBase64(iv),
      },
      payload: bytesToBase64(ciphertext),
    };
  }

  validateEnvelope(envelope) {
    if (!envelope || typeof envelope !== 'object') throw new Error('invalid envelope');
    if (Number(envelope.formatVersion) !== FORMAT_VERSION) throw new Error('invalid formatVersion');
    if (!envelope.kdf || typeof envelope.kdf !== 'object') throw new Error('invalid kdf');
    if (envelope.kdf.algo !== KDF_ALGO) throw new Error('invalid kdf algo');
    if (Number(envelope.kdf.iterations) !== KDF_ITERATIONS) throw new Error('invalid kdf iterations');
    if (typeof envelope.kdf.salt !== 'string') throw new Error('invalid salt');
    if (base64ToBytes(envelope.kdf.salt).length !== SALT_BYTES) throw new Error('invalid salt length');
    if (!envelope.cipher || typeof envelope.cipher !== 'object') throw new Error('invalid cipher');
    // cipher.algo 参与 AAD，这里也断言只能是 AES-256-GCM
    if (envelope.cipher.algo !== CIPHER_ALGO) throw new Error('invalid cipher algo');
    if (typeof envelope.cipher.iv !== 'string') throw new Error('invalid iv');
    if (base64ToBytes(envelope.cipher.iv).length !== IV_BYTES) throw new Error('invalid iv length');
    if (typeof envelope.payload !== 'string' || !envelope.payload) throw new Error('invalid payload');
    return envelope;
  }

  parseEnvelope(text) {
    return this.validateEnvelope(JSON.parse(text));
  }

  async decryptEnvelope(envelope, key) {
    const cryptoObj = this.requireCrypto();
    const iterations = Number(envelope.kdf.iterations);
    const saltBase64 = String(envelope.kdf.salt);
    const plaintext = await cryptoObj.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: base64ToBytes(envelope.cipher.iv),
        additionalData: buildAad(
          envelope.formatVersion,
          envelope.kdf.algo,
          iterations,
          saltBase64,
          envelope.cipher.algo
        ),
        tagLength: TAG_LENGTH,
      },
      key,
      base64ToBytes(envelope.payload)
    );
    return JSON.parse(utf8Decode(plaintext));
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

  // 解密刚生成的密文并与预期条目逐字段比对（D-01：不能只比对字符串）
  async verifyEnvelopeText(text, key, expectedEntries) {
    const envelope = this.parseEnvelope(text);
    const data = await this.decryptEnvelope(envelope, key);
    if (!data || !Array.isArray(data.entries)) throw new Error(this.t('err_write_verify'));
    if (!sameJson(data.entries, expectedEntries)) throw new Error(this.t('err_write_verify'));
  }

  // 原子写：先写 .tmp（内容仍是密文）→ 读回解密校验 → rename 覆盖；任一步失败都删 tmp，旧 blob 不动
  async writeEnvelope(entries, key, salt, iterations, targetPath, trackHash) {
    const envelope = await this.encryptToEnvelope(entries, key, salt, iterations);
    const text = JSON.stringify(envelope, null, 2);
    if (utf8Encode(text).length > MAX_VAULT_BYTES) throw new Error(this.t('err_vault_too_large'));
    await this.verifyEnvelopeText(text, key, entries);

    const path = targetPath || this.getVaultPath();
    const tmpPath = path + '.tmp';
    await this.ensureParentDir(path);
    try {
      await this.app.vault.adapter.write(tmpPath, text);
      const readBack = await this.app.vault.adapter.read(tmpPath);
      if (readBack !== text) throw new Error(this.t('err_write_verify'));
      await this.verifyEnvelopeText(readBack, key, entries);
      await this.app.vault.adapter.rename(tmpPath, path);
      const finalText = await this.app.vault.adapter.read(path);
      if (finalText !== text) throw new Error(this.t('err_write_verify'));
      await this.verifyEnvelopeText(finalText, key, entries);
      if (trackHash !== false) this.knownBlobHash = await this.hashText(finalText);
    } catch (error) {
      // 不论 write 是否已成功返回，都尝试清掉 .tmp（写入中途抛错时可能已落下半截）
      try {
        if (typeof this.app.vault.adapter.remove === 'function') {
          await this.app.vault.adapter.remove(tmpPath);
        }
      } catch (cleanupError) {
        /* 文件不存在时无需处理 */
      }
      throw error;
    }
    return text;
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
    if (!this.isUnlocked()) throw new Error(this.t('notice_unlock_first'));
    const generation = this.sessionGeneration;
    const key = this.sessionKey;
    const salt = this.sessionSalt;
    const iterations = this.sessionIterations;
    const path = this.getVaultPath();
    const job = () => this.runWriteJob(mutator, generation, key, salt, iterations, path);
    const task = this.writeChain.then(job, job);
    this.writeChain = task.then(
      () => undefined,
      () => undefined
    );
    const result = await task;
    if (result && result.written) this.refreshViews();
    return result;
  }

  async runWriteJob(mutator, generation, key, salt, iterations, path) {
    // 锁定后的待写任务直接丢弃，绝不把明文重新落盘
    if (generation !== this.sessionGeneration || !this.sessionKey) {
      return { written: false, discarded: true, unchanged: false, conflict: false };
    }
    const outcome = mutator(this.entries) || {};
    if (!outcome.entries) {
      return { written: false, discarded: false, unchanged: true, conflict: false };
    }
    const next = outcome.entries;
    if (await this.detectExternalChange(path)) {
      const conflictPath = await this.buildConflictPath(path);
      await this.writeEnvelope(next, key, salt, iterations, conflictPath, false);
      new Notice(this.t('notice_conflict', { path: conflictPath }), 10000);
      return { written: false, discarded: false, unchanged: false, conflict: true, conflictPath };
    }
    await this.writeEnvelope(next, key, salt, iterations, path, true);
    if (generation !== this.sessionGeneration) {
      return { written: false, discarded: true, unchanged: false, conflict: false };
    }
    this.entries = next;
    return { written: true, discarded: false, unchanged: false, conflict: false };
  }

  /* ---------------- 保险库生命周期 ---------------- */

  async createVault(password) {
    const cryptoObj = this.requireCrypto();
    const normalized = normalizePassword(password);
    const salt = randomBytes(cryptoObj, SALT_BYTES);
    const key = await this.deriveKey(normalized, salt, KDF_ITERATIONS);
    const path = this.getVaultPath();
    // 已存在同名文件时拒绝创建，避免覆盖旧库
    if (await this.app.vault.adapter.exists(path)) throw new Error(this.t('err_vault_exists'));
    await this.writeEnvelope([], key, salt, KDF_ITERATIONS, path, true);
    this.sessionGeneration += 1;
    this.sessionKey = key;
    this.sessionSalt = salt;
    this.sessionIterations = KDF_ITERATIONS;
    this.entries = [];
    this.vaultState = 'present';
    this.passwordVerifier = await this.hashText(normalized);
    this.failureCount = 0;
    this.blockedUntil = 0;
    this.settings.initializedPath = path;
    this.resetIdleTimer();
    this.refreshViews();
    try {
      await this.saveSettings();
    } catch (error) {
      console.error('[' + PLUGIN_ID + '] save settings failed:', error);
    }
    return true;
  }

  getUnlockWaitSeconds() {
    const left = this.blockedUntil - Date.now();
    return left > 0 ? Math.ceil(left / 1000) : 0;
  }

  registerUnlockFailure() {
    this.failureCount += 1;
    const backoff = Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * Math.pow(2, this.failureCount - 1));
    this.blockedUntil = Date.now() + backoff;
  }

  // 统一失败口径：文件缺失/JSON 畸形/base64 损坏/版本不符/密码错误都 return false，不抛原始异常
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
      const iterations = Number(envelope.kdf.iterations);
      const salt = base64ToBytes(envelope.kdf.salt);
      const key = await this.deriveKey(password, salt, iterations);
      let data;
      try {
        data = await this.decryptEnvelope(envelope, key);
      } catch (error) {
        this.registerUnlockFailure();
        this.lastUnlockError = this.t('err_unlock_failed');
        return false;
      }
      if (!data || !Array.isArray(data.entries)) throw new Error('invalid payload');
      const entries = data.entries.map((item, index) => normalizeStoredEntry(item, 'restored-' + index));
      this.failureCount = 0;
      this.blockedUntil = 0;
      this.sessionGeneration += 1;
      this.sessionKey = key;
      this.sessionSalt = salt;
      this.sessionIterations = iterations;
      this.entries = entries;
      this.vaultState = 'present';
      this.knownBlobHash = await this.hashText(text);
      this.passwordVerifier = await this.hashText(normalizePassword(password));
      this.settings.initializedPath = path;
      this.resetIdleTimer();
      this.refreshViews();
      try {
        await this.saveSettings();
      } catch (error) {
        console.error('[' + PLUGIN_ID + '] save settings failed:', error);
      }
      return true;
    } catch (error) {
      console.error('[' + PLUGIN_ID + '] unlock failed:', error);
      this.registerUnlockFailure();
      this.lastUnlockError =
        errorMessage(error) === this.t('err_vault_too_large')
          ? this.t('err_vault_too_large')
          : this.t('err_unlock_failed');
      return false;
    }
  }

  // 回到前台后的重新验证：内存中只保留口令的 SHA-256 校验值，不落盘
  async reverify(password) {
    if (!this.isUnlocked() || !this.passwordVerifier) return false;
    try {
      const digest = await this.hashText(normalizePassword(password));
      if (digest !== this.passwordVerifier) return false;
      this.hiddenAt = 0;
      this.suspended = false;
      this.resetIdleTimer();
      this.refreshViews();
      return true;
    } catch (error) {
      console.error('[' + PLUGIN_ID + '] reverify failed:', error);
      return false;
    }
  }

  lock() {
    const hadSession = this.isUnlocked();
    this.sessionGeneration += 1;
    this.sessionKey = null;
    this.sessionSalt = null;
    this.sessionIterations = KDF_ITERATIONS;
    this.entries = [];
    this.idleDeadline = 0;
    this.knownBlobHash = null;
    this.passwordVerifier = null;
    this.hiddenAt = 0;
    this.suspended = false;
    this.lastUnlockError = '';

    for (const modal of Array.from(this.openModals)) {
      try {
        modal.close();
      } catch (error) {
        /* ignore */
      }
    }
    this.openModals.clear();

    this.clearClipboardTimer();
    if (this.clipboardText) void this.clearClipboardIfOwned(false);
    this.clipboardText = null;

    this.clearViewScreens();
    this.refreshViews();
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

  typeLabel(type) {
    if (type === 'api-key') return this.t('type_api_key');
    if (type === 'private-key') return this.t('type_private_key');
    if (type === 'note') return this.t('type_note');
    return this.t('type_password');
  }

  /* ---------------- 剪贴板与自动锁定 ---------------- */

  async copySecret(text) {
    if (!text) return;
    this.touchActivity();
    if (!this.isUnlocked()) return;
    if (
      typeof navigator === 'undefined' ||
      !navigator.clipboard ||
      typeof navigator.clipboard.writeText !== 'function'
    ) {
      new Notice(this.t('err_clipboard_unavailable'), 6000);
      return;
    }
    await navigator.clipboard.writeText(text);
    // 写剪贴板期间若已锁定，立即清空，不再把明文写回内存或起定时器
    if (!this.isUnlocked()) {
      try {
        await navigator.clipboard.writeText('');
      } catch (error) {
        console.error('[' + PLUGIN_ID + '] clipboard cleanup failed:', error);
      }
      return;
    }
    this.clipboardText = text;
    this.clearClipboardTimer();
    const seconds = Math.max(5, Number(this.settings.clipboardClearSeconds) || 30);
    new Notice(this.t('notice_copied', { seconds }), 4000);
    this.clipboardTimer = globalThis.setTimeout(() => {
      void this.clearClipboardIfOwned(true);
    }, seconds * 1000);
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
    // 读不到剪贴板时不能静默保留明文：重试一次后无条件清空并提示
    if (!readFailed && current !== owned) return;
    try {
      await navigator.clipboard.writeText('');
      if (readFailed) new Notice(this.t('notice_clipboard_forced'), 6000);
      else if (notify) new Notice(this.t('notice_clipboard_cleared'), 3000);
    } catch (error) {
      console.error('[' + PLUGIN_ID + '] clipboard clear failed:', error);
      if (readFailed) new Notice(this.t('notice_clipboard_forced'), 6000);
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
      return;
    }
    const minutes = Math.max(1, Number(this.settings.autoLockMinutes) || 15);
    this.idleDeadline = Date.now() + minutes * 60000;
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

  suspendForBackground() {
    if (!this.isUnlocked()) return;
    this.suspended = true;
    this.clearViewScreens();
    this.maskAllViews();
  }

  handleVisibilityChange() {
    const hidden = typeof document !== 'undefined' && document ? !!document.hidden : false;
    if (hidden) {
      this.hiddenAt = this.hiddenAt || Date.now();
      this.suspendForBackground();
      return;
    }
    const elapsed = this.hiddenAt ? Date.now() - this.hiddenAt : 0;
    this.hiddenAt = 0;
    if (elapsed >= HIDDEN_LOCK_MS) {
      this.lockFromBackground();
      return;
    }
    // 未超过 60 秒也保持遮罩，必须重新验证主密码才能继续查看
    if (this.isUnlocked()) this.suspendForBackground();
  }

  handleWindowBlur() {
    if (typeof document !== 'undefined' && document && document.hidden) return;
    this.suspendForBackground();
  }

  checkAutoLock() {
    if (!this.isUnlocked()) return;
    if (this.hiddenAt && Date.now() - this.hiddenAt >= HIDDEN_LOCK_MS) {
      this.lockFromBackground();
      return;
    }
    if (Date.now() >= this.idleDeadline) {
      this.lock();
      new Notice(this.t('notice_auto_locked'), 6000);
    }
  }

  /* ---------------- Modal 追踪 ---------------- */

  trackModal(modal) {
    this.openModals.add(modal);
  }

  untrackModal(modal) {
    this.openModals.delete(modal);
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

  async openVaultView() {
    let leaves = this.app.workspace.getLeavesOfType(VIEW_TYPE);
    if (!leaves.length) {
      await delay(60);
      leaves = this.app.workspace.getLeavesOfType(VIEW_TYPE);
    }
    if (leaves.length) {
      await this.app.workspace.revealLeaf(leaves[0]);
      return leaves[0];
    }

    let leaf = null;
    if (typeof this.app.workspace.ensureSideLeaf === 'function') {
      leaf = await this.app.workspace.ensureSideLeaf(VIEW_TYPE, 'right', { active: true, reveal: true });
    } else if (typeof this.app.workspace.getRightLeaf === 'function') {
      leaf = this.app.workspace.getRightLeaf(false);
      if (leaf) await leaf.setViewState({ type: VIEW_TYPE });
    }
    if (leaf) await this.app.workspace.revealLeaf(leaf);
    return leaf;
  }

  async openEntryCreator() {
    await this.openVaultView();
    if (!this.isUnlocked()) {
      new Notice(this.t('notice_unlock_first'), 5000);
      return;
    }
    const leaves = this.app.workspace.getLeavesOfType(VIEW_TYPE);
    for (const leaf of leaves) {
      const view = leaf && leaf.view;
      if (
        view &&
        typeof view.getViewType === 'function' &&
        view.getViewType() === VIEW_TYPE &&
        typeof view.openAddModal === 'function'
      ) {
        view.openAddModal();
        return;
      }
    }
  }
}

module.exports = XUSecretVault;
