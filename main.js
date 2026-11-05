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
const AAD_PREFIX = 'xsv-aad-v1';
const SALT_BYTES = 16;
const IV_BYTES = 12;
const ENTRY_TYPES = ['password', 'api-key', 'private-key', 'note'];

const DEFAULT_SETTINGS = {
  language: 'zh',
  vaultPath: DEFAULT_VAULT_PATH,
  autoLockMinutes: 5,
  clipboardClearSeconds: 30,
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
    setting_auto_lock_desc: '无操作超过该时长后自动锁定，并清除内存中的密钥与明文。',
    setting_clipboard_clear: '剪贴板清空（秒）',
    setting_clipboard_clear_desc: '复制密钥后经过该时长自动清空剪贴板；若期间剪贴板已被替换则不会覆盖新内容。',
    setting_lock_now: '立即锁定',
    setting_lock_now_desc: '清除内存中的密钥与明文，需要重新输入主密码才能查看。',
    setting_version: '版本',
    setting_docs: '使用文档',
    setting_docs_desc: '在 GitHub 查看完整使用与安全说明。',
    btn_github: 'GitHub',
    status_loading: '正在读取保险库状态…',
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
    setting_auto_lock_desc: 'Lock automatically after this idle period and clear keys and plaintext from memory.',
    setting_clipboard_clear: 'Clipboard clear (seconds)',
    setting_clipboard_clear_desc: 'Clear the clipboard after copying a secret. If the clipboard has been replaced meanwhile, the new content is left untouched.',
    setting_lock_now: 'Lock now',
    setting_lock_now_desc: 'Clear keys and plaintext from memory. The master password is required to view entries again.',
    setting_version: 'Version',
    setting_docs: 'Documentation',
    setting_docs_desc: 'View the full usage and security guide on GitHub.',
    btn_github: 'GitHub',
    status_loading: 'Reading vault state…',
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

// 信封头参数参与 AES-GCM 认证，防止篡改迭代数 / salt / 版本实现降级攻击
function buildAad(formatVersion, algo, iterations, saltBase64) {
  return utf8Encode(
    AAD_PREFIX + '|' + formatVersion + '|' + algo + '|' + String(iterations) + '|' + saltBase64
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
      this.plugin.vaultExists = null;
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

  async onClose() {}

  // 锁定时同步清屏：立即移除已显形的明文，而不是只丢缓存
  clearSensitive() {
    this.revealed.clear();
    this.query = '';
    this.uiError = '';
    if (this.contentEl) this.contentEl.empty();
  }

  async ensureVaultState() {
    if (this.plugin.vaultExists !== null || this.detecting) return;
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
    if (!this.plugin.isUnlocked()) this.revealed.clear();

    const root = el.createDiv({ cls: 'xsv-view' });
    if (!this.plugin.cryptoApi) {
      root.createDiv({ cls: 'xsv-title', text: this.plugin.t('view_title') });
      root.createDiv({ cls: 'xsv-error', text: this.plugin.t('err_crypto_unavailable') });
      return;
    }

    if (this.plugin.isUnlocked()) {
      this.renderUnlocked(root);
      return;
    }

    if (this.plugin.vaultExists === null) {
      root.createDiv({ cls: 'xsv-title', text: this.plugin.t('view_title') });
      root.createDiv({ cls: 'xsv-desc', text: this.plugin.t('status_loading') });
      void this.ensureVaultState();
      return;
    }

    if (this.plugin.vaultExists) this.renderUnlock(root);
    else this.renderSetup(root);
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
        this.plugin.vaultExists = true;
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
          this.uiError = this.plugin.t('err_unlock_failed');
          this.render();
          return;
        }
        this.plugin.vaultExists = true;
        this.render();
      } catch (error) {
        console.error('[' + PLUGIN_ID + '] unlock failed:', error);
        this.uiError = this.plugin.t('err_generic', { msg: errorMessage(error) });
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
  }

  onOpen() {
    this.plugin.trackModal(this);
    this.plugin.touchActivity();
    this.titleEl.setText(this.plugin.t(this.entry ? 'title_edit_entry' : 'title_new_entry'));

    const form = this.contentEl.createDiv({ cls: 'xsv-modal' });
    const field = (label) => {
      const wrap = form.createDiv({ cls: 'xsv-field' });
      wrap.createDiv({ cls: 'xsv-label', text: label });
      return wrap;
    };

    const nameWrap = field(this.plugin.t('field_name'));
    const nameInput = nameWrap.createEl('input', { type: 'text', cls: 'xsv-input' });
    nameInput.value = this.entry ? this.entry.name : '';

    const typeWrap = field(this.plugin.t('field_type'));
    const typeSelect = typeWrap.createEl('select', { cls: 'xsv-input' });
    for (const type of ENTRY_TYPES) {
      const option = typeSelect.createEl('option', { text: this.plugin.typeLabel(type) });
      option.value = type;
    }
    typeSelect.value = this.entry ? this.entry.type : 'password';

    const tagsWrap = field(this.plugin.t('field_tags'));
    const tagsInput = tagsWrap.createEl('input', { type: 'text', cls: 'xsv-input' });
    tagsInput.value = this.entry ? this.entry.tags.join(', ') : '';
    tagsInput.setAttribute('placeholder', this.plugin.t('tags_placeholder'));

    const contentWrap = field(this.plugin.t('field_content'));
    const contentInput = contentWrap.createEl('textarea', { cls: 'xsv-input xsv-textarea' });
    contentInput.rows = 6;
    contentInput.value = this.entry ? this.entry.content : '';

    const noteWrap = field(this.plugin.t('field_note'));
    const noteInput = noteWrap.createEl('textarea', { cls: 'xsv-input xsv-textarea' });
    noteInput.rows = 2;
    noteInput.value = this.entry ? this.entry.note : '';

    const errorEl = form.createDiv({ cls: 'xsv-error' });
    errorEl.setText('');

    const actions = form.createDiv({ cls: 'xsv-actions' });
    const cancelButton = actions.createEl('button', { cls: 'xsv-btn', text: this.plugin.t('btn_cancel') });
    cancelButton.addEventListener('click', () => this.close());
    const saveButton = actions.createEl('button', {
      cls: 'xsv-btn xsv-btn-primary',
      text: this.plugin.t('btn_save'),
    });

    const submit = async () => {
      const name = nameInput.value.trim();
      if (!name) {
        errorEl.setText(this.plugin.t('notice_name_required'));
        return;
      }
      const payload = {
        name,
        type: typeSelect.value,
        tags: sanitizeTags(tagsInput.value),
        content: contentInput.value,
        note: noteInput.value,
      };
      errorEl.setText('');
      saveButton.disabled = true;
      try {
        if (this.entry) {
          const changed = await this.plugin.updateEntry(this.entry.id, payload);
          new Notice(this.plugin.t(changed ? 'notice_saved' : 'notice_unchanged'), 3000);
        } else {
          await this.plugin.addEntry(payload);
          new Notice(this.plugin.t('notice_saved'), 3000);
        }
        this.close();
        this.plugin.refreshViews();
      } catch (error) {
        console.error('[' + PLUGIN_ID + '] save entry failed:', error);
        errorEl.setText(this.plugin.t('err_generic', { msg: errorMessage(error) }));
      } finally {
        saveButton.disabled = false;
      }
    };

    saveButton.addEventListener('click', () => void submit());
    if (!this.entry && typeof nameInput.focus === 'function') nameInput.focus();
  }

  onClose() {
    this.plugin.untrackModal(this);
    this.contentEl.empty();
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
        await this.plugin.deleteEntry(this.entry.id);
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
  vaultExists = null;
  idleDeadline = 0;
  clipboardTimer = 0;
  clipboardText = null;
  openModals = new Set();
  writeChain = Promise.resolve();
  sessionGeneration = 0;

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
      this.vaultExists = await this.app.vault.adapter.exists(this.getVaultPath());
    } catch (error) {
      console.error('[' + PLUGIN_ID + '] detect vault failed:', error);
      this.vaultExists = false;
    }
    return this.vaultExists;
  }

  /* ---------------- 加密原语 ---------------- */

  async deriveKey(password, salt, iterations) {
    const cryptoObj = this.requireCrypto();
    const material = await cryptoObj.subtle.importKey(
      'raw',
      utf8Encode(password),
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

  async encryptToEnvelope(entries, key, salt, iterations) {
    const cryptoObj = this.requireCrypto();
    const iv = randomBytes(cryptoObj, IV_BYTES);
    const saltBase64 = bytesToBase64(salt);
    const plaintext = JSON.stringify({ version: FORMAT_VERSION, entries });
    const ciphertext = await cryptoObj.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: buildAad(FORMAT_VERSION, KDF_ALGO, iterations, saltBase64),
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
        algo: 'AES-256-GCM',
        iv: bytesToBase64(iv),
      },
      updatedAt: new Date().toISOString(),
      payload: bytesToBase64(ciphertext),
    };
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

  async writeEnvelope(entries, key, salt, iterations, targetPath) {
    const envelope = await this.encryptToEnvelope(entries, key, salt, iterations);
    const text = JSON.stringify(envelope, null, 2);
    const path = targetPath || this.getVaultPath();
    await this.ensureParentDir(path);
    await this.app.vault.adapter.write(path, text);

    // 写盘后立即读回校验（本机存在外部进程干扰写盘的历史坑）
    const readBack = await this.app.vault.adapter.read(path);
    if (readBack !== text) throw new Error(this.t('err_write_verify'));
    try {
      const parsed = JSON.parse(readBack);
      if (!parsed || parsed.formatVersion !== FORMAT_VERSION || typeof parsed.payload !== 'string') {
        throw new Error('invalid envelope');
      }
    } catch (error) {
      throw new Error(this.t('err_write_verify'));
    }
    return envelope;
  }

  async saveEntries(nextEntries) {
    if (!this.sessionKey || !this.sessionSalt) throw new Error(this.t('notice_unlock_first'));
    // 捕获当前会话上下文：锁定/重新解锁后，排队中的写盘不得污染新会话
    const generation = this.sessionGeneration;
    const key = this.sessionKey;
    const salt = this.sessionSalt;
    const iterations = this.sessionIterations;
    const targetPath = this.getVaultPath();
    const task = this.writeChain.then(
      () => this.writeEnvelope(nextEntries, key, salt, iterations, targetPath),
      () => this.writeEnvelope(nextEntries, key, salt, iterations, targetPath)
    );
    this.writeChain = task.then(
      () => undefined,
      () => undefined
    );
    await task;
    if (generation !== this.sessionGeneration) return false;
    this.entries = nextEntries;
    return true;
  }

  /* ---------------- 保险库生命周期 ---------------- */

  async createVault(password) {
    const cryptoObj = this.requireCrypto();
    const salt = randomBytes(cryptoObj, SALT_BYTES);
    const key = await this.deriveKey(password, salt, KDF_ITERATIONS);
    await this.writeEnvelope([], key, salt, KDF_ITERATIONS);
    this.sessionGeneration += 1;
    this.sessionKey = key;
    this.sessionSalt = salt;
    this.sessionIterations = KDF_ITERATIONS;
    this.entries = [];
    this.vaultExists = true;
    this.resetIdleTimer();
    this.refreshViews();
    return true;
  }

  async unlock(password) {
    const cryptoObj = this.requireCrypto();
    const path = this.getVaultPath();
    const exists = await this.app.vault.adapter.exists(path);
    if (!exists) {
      this.vaultExists = false;
      this.refreshViews();
      return false;
    }

    const text = await this.app.vault.adapter.read(path);
    let envelope;
    try {
      envelope = JSON.parse(text);
    } catch (error) {
      throw new Error(this.t('err_vault_corrupt'));
    }
    if (
      !envelope ||
      envelope.formatVersion !== FORMAT_VERSION ||
      !envelope.kdf ||
      !envelope.cipher ||
      typeof envelope.payload !== 'string'
    ) {
      throw new Error(this.t('err_vault_corrupt'));
    }
    if (envelope.kdf.algo !== KDF_ALGO || Number(envelope.kdf.iterations) !== KDF_ITERATIONS) {
      // 拒绝任何 KDF 算法或迭代数偏离当前标准的信封，避免降级攻击
      throw new Error(this.t('err_vault_corrupt'));
    }

    const iterations = Number(envelope.kdf.iterations);
    const salt = base64ToBytes(envelope.kdf.salt);
    const saltBase64 = String(envelope.kdf.salt);
    const key = await this.deriveKey(password, salt, iterations);
    let plaintext;
    try {
      plaintext = await cryptoObj.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: base64ToBytes(envelope.cipher.iv),
          additionalData: buildAad(envelope.formatVersion, envelope.kdf.algo, iterations, saltBase64),
        },
        key,
        base64ToBytes(envelope.payload)
      );
    } catch (error) {
      return false;
    }

    let data;
    try {
      data = JSON.parse(utf8Decode(plaintext));
    } catch (error) {
      throw new Error(this.t('err_vault_corrupt'));
    }
    if (!data || !Array.isArray(data.entries)) throw new Error(this.t('err_vault_corrupt'));

    const entries = data.entries.map((item, index) => normalizeStoredEntry(item, 'restored-' + index));
    this.sessionGeneration += 1;
    this.sessionKey = key;
    this.sessionSalt = salt;
    this.sessionIterations = iterations;
    this.entries = entries;
    this.vaultExists = true;
    this.resetIdleTimer();
    this.refreshViews();
    return true;
  }

  lock() {
    const hadSession = this.isUnlocked();
    this.sessionGeneration += 1;
    this.sessionKey = null;
    this.sessionSalt = null;
    this.sessionIterations = KDF_ITERATIONS;
    this.entries = [];
    this.idleDeadline = 0;

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
    const next = this.entries.concat([entry]);
    await this.saveEntries(next);
    this.refreshViews();
    return entry;
  }

  async updateEntry(id, input) {
    this.assertUnlocked();
    const index = this.entries.findIndex((entry) => entry.id === id);
    if (index < 0) throw new Error(this.t('err_vault_corrupt'));
    const previous = this.entries[index];
    const base = normalizeEntryInput(input);
    const unchanged =
      previous.name === base.name &&
      previous.type === base.type &&
      previous.content === base.content &&
      previous.note === base.note &&
      JSON.stringify(previous.tags) === JSON.stringify(base.tags);
    if (unchanged) return false;

    const next = this.entries.slice();
    next[index] = Object.assign({}, previous, base, { updatedAt: new Date().toISOString() });
    await this.saveEntries(next);
    this.refreshViews();
    return true;
  }

  async deleteEntry(id) {
    this.assertUnlocked();
    const next = this.entries.filter((entry) => entry.id !== id);
    if (next.length === this.entries.length) return false;
    await this.saveEntries(next);
    this.refreshViews();
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
    if (
      typeof navigator === 'undefined' ||
      !navigator.clipboard ||
      typeof navigator.clipboard.writeText !== 'function'
    ) {
      new Notice(this.t('err_clipboard_unavailable'), 6000);
      return;
    }
    await navigator.clipboard.writeText(text);
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
    try {
      if (
        typeof navigator !== 'undefined' &&
        navigator.clipboard &&
        typeof navigator.clipboard.readText === 'function'
      ) {
        const current = await navigator.clipboard.readText();
        if (current !== owned) return;
      }
      await navigator.clipboard.writeText('');
      if (notify) new Notice(this.t('notice_clipboard_cleared'), 3000);
    } catch (error) {
      console.error('[' + PLUGIN_ID + '] clipboard clear failed:', error);
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
    const minutes = Math.max(1, Number(this.settings.autoLockMinutes) || 5);
    this.idleDeadline = Date.now() + minutes * 60000;
  }

  touchActivity() {
    if (this.isUnlocked()) this.resetIdleTimer();
  }

  checkAutoLock() {
    if (!this.isUnlocked()) return;
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
