/* XU Secret Vault 0.3.3 — e2e / 安全加固负向测试（Node 原生 WebCrypto + Obsidian 桩） */
'use strict';

const fs = require('fs');
const path = require('path');
const Module = require('module');
const { webcrypto } = require('crypto');
const { subtle } = webcrypto;

const MAIN = path.join(__dirname, '..', 'main.js');
const VAULT_PATH = 'xu-secrets.enc';

const MASTER = 'MASTER-PASSWORD-DO-NOT-LEAK-789';
const SECRET_ONE = 'SECRET-ALPHA-DO-NOT-LEAK-123';
const SECRET_TWO = 'SECRET-BETA-DO-NOT-LEAK-456';
const SECRET_THREE = 'SECRET-GAMMA-DO-NOT-LEAK-000';

let assertions = 0;
const failures = [];

function ok(condition, message) {
  assertions += 1;
  if (condition) {
    console.log('PASS  ' + message);
  } else {
    failures.push(message);
    console.error('FAIL  ' + message);
  }
}

async function rejects(promise, needle, message) {
  try {
    await promise;
    ok(false, message + '（未抛出异常）');
  } catch (error) {
    ok(String(error && error.message).indexOf(needle) >= 0, message);
  }
}

async function waitFor(fn, label, timeout) {
  const limit = Date.now() + (timeout || 5000);
  while (Date.now() < limit) {
    if (fn()) return true;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  ok(false, '等待超时：' + label);
  return false;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function toBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

function fromBase64(text) {
  return new Uint8Array(Buffer.from(String(text), 'base64'));
}

function tmpFiles() {
  return Array.from(fileStore.keys()).filter((key) => key.indexOf(VAULT_PATH + '.tmp') === 0);
}

function bakFiles() {
  return Array.from(fileStore.keys()).filter((key) => key.indexOf(VAULT_PATH + '.bak') === 0);
}

function conflictFiles() {
  return Array.from(fileStore.keys()).filter((key) => key.indexOf('.conflict-') >= 0);
}

// 手工构造 v1（0.1.0）信封：AAD = xsv-aad-v1|1|PBKDF2-SHA512|600000|salt（不含 cipher.algo）
async function buildLegacyV1Envelope(password, entries) {
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const material = await subtle.importKey(
    'raw',
    new TextEncoder().encode(password.normalize('NFC')),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  const key = await subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-512' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(
    ['xsv-aad-v1', 1, 'PBKDF2-SHA512', '600000', toBase64(salt)].join('|')
  );
  const plaintext = JSON.stringify({ version: 1, entries });
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
    key,
    new TextEncoder().encode(plaintext)
  );
  return {
    formatVersion: 1,
    kdf: { algo: 'PBKDF2-SHA512', iterations: 600000, salt: toBase64(salt) },
    cipher: { algo: 'AES-256-GCM', iv: toBase64(iv) },
    payload: toBase64(ciphertext),
  };
}

// 手工构造 v2 信封，但载荷只有 entries（没有 notes / contentVersion），用于验证旧结构兼容
async function buildV2EnvelopeWithoutNotes(password, entries) {
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const material = await subtle.importKey(
    'raw',
    new TextEncoder().encode(password.normalize('NFC')),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  const key = await subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-512' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(
    ['xsv-aad-v2', 2, 'PBKDF2-SHA512', '600000', toBase64(salt), 'AES-256-GCM'].join('|')
  );
  const plaintext = JSON.stringify({ version: 2, entries });
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
    key,
    new TextEncoder().encode(plaintext)
  );
  return {
    formatVersion: 2,
    kdf: { algo: 'PBKDF2-SHA512', iterations: 600000, salt: toBase64(salt) },
    cipher: { algo: 'AES-256-GCM', iv: toBase64(iv) },
    payload: toBase64(ciphertext),
  };
}

/* ---------------- 极简 DOM 桩 ---------------- */

function makeEl(tag, options) {
  const opts = options || {};
  const el = {
    tagName: String(tag).toUpperCase(),
    children: [],
    parent: null,
    textContent: '',
    value: '',
    type: '',
    disabled: false,
    rows: 0,
    autocomplete: '',
    spellcheck: true,
    attributes: {},
    style: {},
    _classes: new Set(),
    _listeners: {},
  };
  if (opts.cls) String(opts.cls).split(/\s+/).filter(Boolean).forEach((name) => el._classes.add(name));
  if (opts.text !== undefined) el.textContent = String(opts.text);
  if (opts.type) el.type = opts.type;
  el.classList = {
    add: (name) => el._classes.add(name),
    remove: (name) => el._classes.delete(name),
    contains: (name) => el._classes.has(name),
    toggle: (name, force) => {
      if (force === undefined ? !el._classes.has(name) : force) el._classes.add(name);
      else el._classes.delete(name);
    },
  };
  el.createEl = (childTag, childOptions) => {
    const child = makeEl(childTag, childOptions);
    child.parent = el;
    el.children.push(child);
    return child;
  };
  el.createDiv = (childOptions) => el.createEl('div', childOptions);
  el.createSpan = (childOptions) => el.createEl('span', childOptions);
  el.empty = () => {
    el.children = [];
    el.textContent = '';
  };
  el.setText = (text) => {
    el.textContent = String(text);
    el.children = [];
  };
  el.appendText = (text) => {
    el.textContent += String(text);
  };
  el.addClass = (name) => el._classes.add(name);
  el.removeClass = (name) => el._classes.delete(name);
  el.toggleClass = (name, force) => el.classList.toggle(name, force);
  el.hasClass = (name) => el._classes.has(name);
  el.setAttribute = (name, value) => {
    el.attributes[name] = String(value);
  };
  el.getAttribute = (name) => el.attributes[name];
  el.addEventListener = (type, handler) => {
    if (!el._listeners[type]) el._listeners[type] = [];
    el._listeners[type].push(handler);
  };
  el.removeEventListener = (type, handler) => {
    const list = el._listeners[type];
    if (!list) return;
    const index = list.indexOf(handler);
    if (index >= 0) list.splice(index, 1);
  };
  el.fire = (type, event) => {
    const list = el._listeners[type] || [];
    for (const handler of list.slice()) handler(event || {});
  };
  el.click = () => el.fire('click', {});
  el.focus = () => {};
  el.setSelectionRange = () => {};
  el.querySelector = (selector) => findByClass(el, selector.replace(/^\./, ''));
  return el;
}

function findByClass(root, className) {
  if (root._classes && root._classes.has(className)) return root;
  for (const child of root.children) {
    const hit = findByClass(child, className);
    if (hit) return hit;
  }
  return null;
}

function findAll(root, predicate, out) {
  const list = out || [];
  if (predicate(root)) list.push(root);
  for (const child of root.children) findAll(child, predicate, list);
  return list;
}

function findButton(root, text) {
  const buttons = findAll(root, (el) => el.tagName === 'BUTTON' && String(el.textContent).trim() === text);
  return buttons[0] || null;
}

function textOf(root) {
  let out = String(root.textContent || '');
  if (root.value) out += ' ' + String(root.value);
  for (const child of root.children) out += ' ' + textOf(child);
  return out;
}

/* ---------------- Obsidian / app 桩 ---------------- */

const fileStore = new Map();
const createdDirs = new Set();
const leaves = [];
const notices = [];
let clipboard = '';
let clipboardReadFailure = false;
let writeBehavior = null; // null | 'throw-before' | 'throw-partial'
let renameCorruptOnce = false; // 模拟 rename 后终检失败（用于测试 .bak 回滚）
let removeFailure = false; // 模拟删除原文件失败（回滚分支）
let renameTargetFailureOnce = false; // 模拟 tmp 落位 rename 失败
let afterReadHook = null; // 读取后注入外部改动（模拟 TOCTOU 窗口）
let activePlugin = null;

const app = {
  vault: {
    adapter: {
      exists: async (filePath) => fileStore.has(filePath) || createdDirs.has(filePath),
      read: async (filePath) => {
        if (!fileStore.has(filePath)) throw new Error('file not found: ' + filePath);
        const text = fileStore.get(filePath);
        if (afterReadHook) {
          const hook = afterReadHook;
          afterReadHook = null;
          hook(filePath, text);
        }
        return text;
      },
      write: async (filePath, text) => {
        if (writeBehavior === 'throw-before') throw new Error('simulated disk failure');
        if (writeBehavior === 'throw-partial') {
          // 模拟"写到一半"：先把截断内容落盘，再抛错
          fileStore.set(filePath, String(text).slice(0, Math.max(0, String(text).length - 24)));
          throw new Error('simulated partial write');
        }
        fileStore.set(filePath, String(text));
      },
      rename: async (fromPath, toPath) => {
        if (!fileStore.has(fromPath)) throw new Error('rename source missing: ' + fromPath);
        // 真实 Obsidian DataAdapter.rename：目标已存在时直接抛错，不会静默覆盖
        if (fileStore.has(toPath)) throw new Error('Destination file already exists!');
        if (renameCorruptOnce && toPath === VAULT_PATH) {
          renameCorruptOnce = false;
          // rename 成功但落盘内容损坏：触发 rename 后的终检失败与 .bak 回滚
          fileStore.set(toPath, 'CORRUPTED');
          fileStore.delete(fromPath);
          return;
        }
        if (renameTargetFailureOnce && toPath === VAULT_PATH) {
          renameTargetFailureOnce = false;
          throw new Error('simulated rename failure');
        }
        fileStore.set(toPath, fileStore.get(fromPath));
        fileStore.delete(fromPath);
      },
      remove: async (filePath) => {
        if (removeFailure && filePath === VAULT_PATH) throw new Error('simulated remove failure');
        fileStore.delete(filePath);
      },
      stat: async (filePath) =>
        fileStore.has(filePath) ? { size: Buffer.byteLength(fileStore.get(filePath), 'utf8') } : null,
      mkdir: async (dirPath) => {
        createdDirs.add(dirPath);
      },
      list: async (dirPath) => ({
        files: Array.from(fileStore.keys()).filter((key) => {
          const slash = key.lastIndexOf('/');
          return slash < 0 ? dirPath === '' : key.slice(0, slash) === dirPath;
        }),
        folders: [],
      }),
    },
  },
  workspace: {
    onLayoutReady: (callback) => callback(),
    on: () => ({ unregister() {} }),
    getLeavesOfType: (type) =>
      leaves.filter(
        (leaf) =>
          leaf.view &&
          typeof leaf.view.getViewType === 'function' &&
          leaf.view.getViewType() === type
      ),
    revealLeaf: async (leaf) => leaf,
    getLeaf: () => {
      let mounted = false;
      const leaf = {
        app,
        view: null,
        setViewState: async (state) => {
          const factory = activePlugin.__viewFactories[state.type];
          if (factory && !mounted) {
            leaf.view = factory(leaf);
            mounted = true;
            leaves.push(leaf);
          }
        },
      };
      return leaf;
    },
    ensureSideLeaf: async (type) => {
      const leaf = { app, view: null, setViewState: async () => {} };
      const factory = activePlugin.__viewFactories[type];
      leaf.view = factory(leaf);
      leaves.push(leaf);
      return leaf;
    },
    getRightLeaf: () => null,
  },
  metadataCache: {
    on: () => ({ unregister() {} }),
    getFileCache: () => null,
  },
  setting: {
    openTabById: () => {},
  },
};

// document / window 事件桩：用于伪造 visibilitychange / blur
function makeEventTarget() {
  return {
    _listeners: {},
    hidden: false,
    addEventListener(type, handler) {
      if (!this._listeners[type]) this._listeners[type] = [];
      this._listeners[type].push(handler);
    },
    removeEventListener(type, handler) {
      const list = this._listeners[type];
      if (!list) return;
      const index = list.indexOf(handler);
      if (index >= 0) list.splice(index, 1);
    },
    fire(type, event) {
      for (const handler of (this._listeners[type] || []).slice()) handler(event || {});
    },
  };
}
const documentStub = makeEventTarget();
const windowStub = makeEventTarget();
const openCalls = [];
windowStub.open = (url) => {
  openCalls.push(url);
  return null;
};

class ItemView {
  constructor(leaf) {
    this.leaf = leaf;
    this.app = (leaf && leaf.app) || app;
    this.containerEl = makeEl('div');
    this.contentEl = this.containerEl.createDiv({ cls: 'view-content' });
  }
  registerDomEvent(el, type, handler) {
    el.addEventListener(type, handler);
  }
}

class Modal {
  constructor(modalApp) {
    this.app = modalApp;
    this.contentEl = makeEl('div');
    this.titleEl = makeEl('div');
    this.isOpen = false;
  }
  open() {
    this.isOpen = true;
    this.onOpen();
  }
  close() {
    if (!this.isOpen) return;
    this.isOpen = false;
    this.onClose();
  }
}

class Notice {
  constructor(message) {
    notices.push(String(message));
  }
}

class PluginSettingTab {
  constructor(pluginApp, plugin) {
    this.app = pluginApp;
    this.plugin = plugin;
  }
  update() {}
}

class Setting {}

class Plugin {
  constructor(pluginApp, manifest) {
    this.app = pluginApp;
    this.manifest = manifest;
    this.__viewFactories = {};
    this.__commands = [];
    this.__savedData = [];
    this.__settingTab = null;
  }
  async loadData() {
    return {};
  }
  async saveData(data) {
    this.__savedData.push(JSON.parse(JSON.stringify(data)));
  }
  registerView(type, factory) {
    this.__viewFactories[type] = factory;
  }
  registerInterval(id) {
    return id;
  }
  registerEvent() {}
  registerDomEvent(el, type, handler) {
    el.addEventListener(type, handler);
  }
  addCommand(command) {
    this.__commands.push(command);
  }
  addSettingTab(tab) {
    this.__settingTab = tab;
  }
  addRibbonIcon() {}
  addStatusBarItem() {
    return makeEl('div');
  }
}

const obsidianStub = { ItemView, Modal, Notice, Plugin, PluginSettingTab, Setting };

/* ---------------- 加载 main.js（主 realm，桩替换 require） ---------------- */

Object.defineProperty(globalThis, 'navigator', {
  value: {
    clipboard: {
      writeText: async (text) => {
        clipboard = String(text);
      },
      readText: async () => {
        if (clipboardReadFailure) throw new Error('clipboard read denied');
        return clipboard;
      },
    },
  },
  configurable: true,
  writable: true,
});
Object.defineProperty(globalThis, 'document', { value: documentStub, configurable: true, writable: true });
Object.defineProperty(globalThis, 'window', { value: windowStub, configurable: true, writable: true });

const originalLoad = Module._load;
Module._load = function patchedLoad(request, parent, isMain) {
  if (request === 'obsidian') return obsidianStub;
  return originalLoad.call(this, request, parent, isMain);
};
let XUSecretVault;
try {
  XUSecretVault = require(MAIN);
} finally {
  Module._load = originalLoad;
}

/* ---------------- 流程 ---------------- */

(async () => {
  const plugin = new XUSecretVault(app, {
    id: 'xu-secret-vault',
    name: 'XU Secret Vault',
    version: '0.3.3',
    minAppVersion: '1.13.0',
  });
  activePlugin = plugin;
  plugin.settings.vaultPath = VAULT_PATH;
  // 旧版侧栏实例：模拟 0.2.1 遗留的侧栏 leaf，启动时应被清理，不再复活成第二个入口
  const legacyLeaf = {
    app,
    view: { getViewType: () => 'xu-secret-vault-view' },
    detach: () => {
      const index = leaves.indexOf(legacyLeaf);
      if (index >= 0) leaves.splice(index, 1);
    },
  };
  leaves.push(legacyLeaf);
  await plugin.onload();
  ok(!leaves.includes(legacyLeaf), '启动时清理旧侧栏视图 leaf（不会复活成侧栏）');
  ok(plugin.__viewFactories['xu-secret-vault-view'] === undefined, '不再注册旧侧栏视图类型');
  ok(plugin.__viewFactories['xu-secret-vault-page'] !== undefined, '注册了整页视图类型');

  const restart = () => {
    // 模拟重启：K-09 的失败计数与退避只在内存，重启即清零
    plugin.failureCount = 0;
    plugin.blockedUntil = 0;
  };
  const unlockFresh = async (password) => {
    restart();
    return plugin.unlock(password);
  };
  const restoreVault = (text) => fileStore.set(VAULT_PATH, text);
  const goodText = () => fileStore.get(VAULT_PATH);

  ok(plugin.cryptoApi !== null, 'WebCrypto 探测可用');

  // 1) 首次使用 UI：创建保险库（整页视图）
  const leaf = await plugin.openVaultView();
  ok(leaf !== null && leaf.view && leaf.view.getViewType() === 'xu-secret-vault-page', '从主编辑区打开整页视图');
  ok(leaves.length === 1, '首次打开只创建一个整页 leaf');
  const view = leaf.view;
  await view.onOpen();
  await waitFor(() => plugin.vaultState !== 'unknown', '检测保险库状态');
  ok(String(textOf(view.contentEl)).indexOf('创建主密码') >= 0, '首次使用显示创建主密码界面');
  ok(findAll(view.contentEl, (el) => el.hasClass('xsv-page')).length === 1, '整页布局根节点生效');
  ok(findAll(view.contentEl, (el) => el.hasClass('xsv-page-card')).length === 1, '创建/解锁卡片居中显示');

  const passwordInputs = findAll(
    view.contentEl,
    (el) => el.tagName === 'INPUT' && el.type === 'password'
  );
  ok(passwordInputs.length === 2, '首次界面包含主密码与确认输入框');
  passwordInputs[0].value = MASTER;
  passwordInputs[1].value = MASTER;
  const createButton = findButton(view.contentEl, '创建保险库');
  ok(!!createButton, '找到创建保险库按钮');
  const createStart = Date.now();
  createButton.click();
  await waitFor(
    () => plugin.isUnlocked() && plugin.settings.initializedPath === VAULT_PATH,
    '创建保险库完成'
  );
  const createMs = Date.now() - createStart;

  ok(fileStore.has(VAULT_PATH), '创建后生成密文文件 ' + VAULT_PATH);
  ok(tmpFiles().length === 0, '原子写完成后没有残留 .tmp');
  ok(plugin.isUnlocked(), '创建后自动解锁');
  ok(plugin.sessionKey.extractable === false, '会话密钥 non-extractable');
  ok(plugin.sessionSalt.length === 16, '盐为 16 字节');
  ok(plugin.entries.length === 0, '新保险库条目为空');
  ok(plugin.settings.initializedPath === VAULT_PATH, '记录已初始化路径（用于区分首次使用与文件缺失）');

  const env0 = JSON.parse(fileStore.get(VAULT_PATH));
  ok(env0.formatVersion === 2, '信封 formatVersion=2');
  ok(env0.kdf.algo === 'PBKDF2-SHA512', 'KDF 算法记录为 PBKDF2-SHA512');
  ok(Number(env0.kdf.iterations) === 600000, 'KDF 迭代数记录为 600000');
  ok(Buffer.from(env0.kdf.salt, 'base64').length === 16, '信封盐为 16 字节');
  ok(Buffer.from(env0.cipher.iv, 'base64').length === 12, '信封 IV 为 12 字节');
  ok(env0.cipher.algo === 'AES-256-GCM', '加密算法记录为 AES-256-GCM');
  ok(!('entries' in env0), '信封中不存在明文 entries 字段');
  ok(!('updatedAt' in env0), '信封头不再明文暴露 updatedAt');

  // 1b) 启动清理：只删本插件生成且超过 1 小时的 tmp，不得误删用户文件
  const nowStamp = (() => {
    const now = new Date();
    const pad = (value) => String(value).padStart(2, '0');
    return (
      String(now.getFullYear()) +
      pad(now.getMonth() + 1) +
      pad(now.getDate()) +
      '-' +
      pad(now.getHours()) +
      pad(now.getMinutes()) +
      pad(now.getSeconds())
    );
  })();
  fileStore.set(VAULT_PATH + '.tmp-20200101-000000-deadbeef', 'stale');
  fileStore.set(VAULT_PATH + '.tmp-notes.md', 'user file, not ours');
  fileStore.set(VAULT_PATH + '.tmp-20200101-000000-toolong123', 'invalid random length');
  fileStore.set(VAULT_PATH + '.tmp-' + nowStamp + '-abcdef12', 'possibly in-flight');
  await plugin.cleanupStaleTempFiles();
  ok(!fileStore.has(VAULT_PATH + '.tmp-20200101-000000-deadbeef'), '启动清理删除超 1 小时的合法 tmp');
  ok(fileStore.get(VAULT_PATH + '.tmp-notes.md') === 'user file, not ours', '用户文件 tmp-notes.md 不被误删');
  ok(fileStore.has(VAULT_PATH + '.tmp-20200101-000000-toolong123'), '随机段超长的非本插件命名不被删除');
  ok(fileStore.has(VAULT_PATH + '.tmp-' + nowStamp + '-abcdef12'), '1 小时内的 tmp（可能正在写）不被删除');
  fileStore.delete(VAULT_PATH + '.tmp-notes.md');
  fileStore.delete(VAULT_PATH + '.tmp-20200101-000000-toolong123');
  fileStore.delete(VAULT_PATH + '.tmp-' + nowStamp + '-abcdef12');

  // 2) 条目数据层：0.3.0 起条目 CRUD 界面已下线，直接用插件 API 准备引用数据
  const alphaEntry = await plugin.addEntry({
    name: 'Alpha',
    type: 'password',
    content: SECRET_ONE,
    tags: ['work', 'cloud'],
    note: 'primary credential',
  });
  ok(!!alphaEntry && typeof alphaEntry.id === 'string', '数据层新增条目返回带 id 的对象');
  ok(plugin.entries.length === 1, '新增后内存中有一条条目');
  ok(plugin.entries[0].name === 'Alpha', '条目名称已保存');
  ok(plugin.entries[0].content === SECRET_ONE, '条目内容已保存在内存');
  ok(plugin.entries[0].tags.join(',') === 'work,cloud', '标签按数组保存');
  const env1 = JSON.parse(fileStore.get(VAULT_PATH));
  ok(env1.cipher.iv !== env0.cipher.iv, '新增写盘生成了新的 IV');
  ok(env1.kdf.salt === env0.kdf.salt, '同一保险库盐保持不变');
  ok(!fileStore.has(VAULT_PATH + '.bak'), '目标已存在时首次保存成功替换且不残留 .bak');
  ok(tmpFiles().length === 0, '首次保存不残留 .tmp');

  // 3) 界面只剩笔记：条目明文不渲染，条目管理入口与模式切换全部下线
  view.render();
  ok(String(textOf(view.contentEl)).indexOf(SECRET_ONE) < 0, '负向：界面不显示条目明文');
  ok(!findButton(view.contentEl, '新增'), '不再提供新增条目入口');
  ok(!findButton(view.contentEl, '编辑'), '不再提供编辑条目入口');
  ok(!findButton(view.contentEl, '删除'), '不再提供删除条目入口');
  ok(!findButton(view.contentEl, '显示'), '不再提供显示条目入口');
  ok(!findButton(view.contentEl, '表格'), '面板顶部不再有「表格」切换');
  ok(!findButton(view.contentEl, '笔记'), '面板顶部不再有「笔记」切换');
  for (const id of ['new-entry', 'edit-entry', 'delete-entry']) {
    ok(!plugin.__commands.some((command) => command.id === id), '条目命令 ' + id + ' 已下线');
  }

  // 4) 复制：数据层 copySecret 返回成功并沿用自动清空逻辑
  clipboard = '';
  notices.length = 0;
  ok((await plugin.copySecret(SECRET_ONE)) === true, 'copySecret 成功返回 true');
  ok(clipboard === SECRET_ONE, '复制动作写入剪贴板');
  ok(notices.some((message) => message.indexOf('秒后自动清空') >= 0), '复制提示包含自动清空秒数');
  ok(plugin.clipboardTimer !== 0, '复制后启动自动清空定时器');
  await plugin.clearClipboardIfOwned(false);
  clipboard = '';

  // 5) 数据层更新条目：写盘换 IV，界面与磁盘都不残留明文
  const updateResult = await plugin.updateEntry(alphaEntry.id, {
    name: 'Alpha',
    type: 'password',
    content: SECRET_TWO,
    tags: ['work', 'cloud'],
    note: 'primary credential',
  });
  ok(updateResult !== 'unchanged', '内容变化时 updateEntry 触发写盘');
  ok(plugin.entries[0].content === SECRET_TWO, '更新后的内容已写入内存');
  const env2 = JSON.parse(fileStore.get(VAULT_PATH));
  ok(env2.cipher.iv !== env1.cipher.iv, '更新写盘生成了新的 IV');
  ok(!fileStore.has(VAULT_PATH + '.bak') && tmpFiles().length === 0, '连续保存不残留 .bak / .tmp');
  ok(String(fileStore.get(VAULT_PATH)).indexOf(SECRET_TWO) < 0, '负向：密文 blob 不含条目明文（更新后）');
  ok(String(fileStore.get(VAULT_PATH)).indexOf(SECRET_ONE) < 0, '负向：密文 blob 不含旧明文');
  ok(
    (await plugin.updateEntry(alphaEntry.id, {
      name: 'Alpha',
      type: 'password',
      content: SECRET_TWO,
      tags: ['work', 'cloud'],
      note: 'primary credential',
    })) === 'unchanged',
    '内容未变化时 updateEntry 不写盘'
  );

  // 5b) 准备一篇含明文的笔记，供锁定 / 遮罩 / 整页 DOM 断言使用
  const NOTE_PLAIN = '账号表\n\n| 名称 | 备注 |\n| --- | --- |\n| Alpha | ' + SECRET_TWO + ' |';
  await plugin.saveNote('note-primary', NOTE_PLAIN);
  view.render();
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) >= 0, '笔记正文的明文在整页渲染区可见');

  // 6) 锁定：同步清屏、清剪贴板、丢弃密钥、整页 DOM 无明文
  view.render();
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) >= 0, '锁定前明文可见（构造测试场景）');
  clipboard = '';
  await plugin.copySecret(SECRET_TWO);
  ok(clipboard === SECRET_TWO, '锁定前剪贴板含密钥');
  notices.length = 0;
  plugin.lock();
  ok(plugin.sessionKey === null, '锁定后 CryptoKey 已丢弃');
  ok(plugin.entries.length === 0, '锁定后内存条目集合已清空');
  ok(plugin.notes.length === 0, '锁定后内存笔记集合已清空');
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0, '负向：锁定后整页 DOM 不含明文');
  ok(!findAll(view.contentEl, (el) => el.hasClass('xsv-note-body')).length, '锁定后笔记渲染区被移除');
  ok(!findAll(view.contentEl, (el) => el.tagName === 'TEXTAREA').length, '锁定后编辑器被移除');
  await waitFor(() => clipboard === '', '锁定后清空剪贴板');
  ok(clipboard === '', '锁定后剪贴板已清空');

  // 7) 关闭视图即清屏并锁定（M-09 / G-01）
  await unlockFresh(MASTER);
  view.render();
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) >= 0, '关闭视图前明文可见');
  await view.onClose();
  ok(plugin.sessionKey === null, '关闭视图触发锁定');
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0, '关闭视图后 DOM 不含明文');
  view.render();

  // 8) 切后台：立即遮罩；30 秒倒计时内回到前台自动恢复，不重输主密码（M-05 / G-08）
  await unlockFresh(MASTER);
  view.render();
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) >= 0, '遮罩前明文可见');
  documentStub.hidden = true;
  documentStub.fire('visibilitychange');
  ok(view.masked === true, '切后台后立即加遮罩');
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0, '负向：遮罩后 DOM 不含明文');
  ok(String(textOf(view.contentEl)).indexOf('内容已隐藏') >= 0, '遮罩界面提示内容已隐藏');
  ok(plugin.sessionKey !== null, '遮罩但未超过 60 秒时保留会话密钥');
  ok(plugin.getBackgroundLockSeconds() === 30, '默认失焦倒计时为 30 秒');
  ok(plugin.getCountdownRemaining() > 0, '遮罩后倒计时开始');
  ok(
    String(textOf(view.contentEl)).indexOf('秒后锁定') >= 0,
    '遮罩界面显示倒计时'
  );
  documentStub.hidden = false;
  documentStub.fire('visibilitychange');
  ok(view.masked === false, '倒计时内回到前台自动解除遮罩');
  ok(plugin.sessionKey !== null && plugin.suspended === false, '倒计时内恢复不要求重输主密码');
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) >= 0, '恢复后按解锁态重新渲染笔记');
  ok(plugin.getCountdownRemaining() === -1, '恢复后倒计时停止');

  // blur 同样遮罩，focus 回到窗口自动恢复
  windowStub.fire('blur');
  ok(view.masked === true && String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0, '窗口失焦同样遮罩并清屏');
  ok(plugin.getCountdownRemaining() > 0, '失焦后倒计时开始');
  windowStub.fire('focus');
  ok(view.masked === false && plugin.suspended === false, '倒计时内聚焦自动解除遮罩');

  // hidden 超过 60 秒直接锁定
  documentStub.hidden = true;
  documentStub.fire('visibilitychange');
  plugin.hiddenAt = plugin.nowMs() - 61000;
  plugin.hiddenAtWall = Date.now() - 61000;
  plugin.checkAutoLock();
  ok(plugin.sessionKey === null, '后台超过 60 秒自动锁定');
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0, '负向：后台锁定后 DOM 不含明文');
  ok(notices.some((message) => message.indexOf('后台超过 60 秒') >= 0), '后台锁定给出提示');
  documentStub.hidden = false;
  documentStub.fire('visibilitychange');
  view.render();

  // 9) 加密层负向：AAD 保护（篡改迭代数 / 盐 / cipher 算法 / 版本 / base64）
  const goodEnvelopeText = goodText();
  const unified = plugin.t('err_unlock_failed');

  const tamperedIterations = JSON.parse(goodEnvelopeText);
  tamperedIterations.kdf.iterations = 1;
  restoreVault(JSON.stringify(tamperedIterations, null, 2));
  ok((await unlockFresh(MASTER)) === false, '负向：篡改迭代数被拒绝');
  ok(plugin.lastUnlockError === unified, '篡改迭代数返回统一失败文案');
  restoreVault(goodEnvelopeText);

  const tamperedCipherAlgo = JSON.parse(goodEnvelopeText);
  tamperedCipherAlgo.cipher.algo = 'AES-128-GCM';
  restoreVault(JSON.stringify(tamperedCipherAlgo, null, 2));
  ok((await unlockFresh(MASTER)) === false, '负向：篡改 cipher.algo 被拒绝（AAD 认证）');
  restoreVault(goodEnvelopeText);

  const tamperedSalt = JSON.parse(goodEnvelopeText);
  tamperedSalt.kdf.salt = Buffer.from(webcrypto.getRandomValues(new Uint8Array(16))).toString('base64');
  restoreVault(JSON.stringify(tamperedSalt, null, 2));
  ok((await unlockFresh(MASTER)) === false, '负向：替换盐后无法解密');
  restoreVault(goodEnvelopeText);

  const tamperedVersion = JSON.parse(goodEnvelopeText);
  tamperedVersion.formatVersion = 3;
  restoreVault(JSON.stringify(tamperedVersion, null, 2));
  ok((await unlockFresh(MASTER)) === false, '负向：未知版本被拒绝');
  ok(plugin.lastUnlockError === plugin.t('err_version_unsupported'), '未知版本明确提示「版本不支持」');
  ok(plugin.lastUnlockError !== unified, '未知版本不与密码错误混同');
  restoreVault(goodEnvelopeText);

  restoreVault(String(goodEnvelopeText).slice(0, 120));
  ok((await unlockFresh(MASTER)) === false, '负向：截断的 JSON 统一失败且不抛原始异常');
  ok(plugin.lastUnlockError === unified, '截断 JSON 返回统一失败文案');
  restoreVault(goodEnvelopeText);

  const badIv = JSON.parse(goodEnvelopeText);
  badIv.cipher.iv = '***not-base64***';
  restoreVault(JSON.stringify(badIv, null, 2));
  ok((await unlockFresh(MASTER)) === false, '负向：非法 base64 统一失败');
  restoreVault(goodEnvelopeText);

  const badPayload = JSON.parse(goodEnvelopeText);
  badPayload.payload = badPayload.payload.slice(0, 12) + 'AAAA' + badPayload.payload.slice(16);
  restoreVault(JSON.stringify(badPayload, null, 2));
  ok((await unlockFresh(MASTER)) === false, '负向：密文被篡改导致 GCM 校验失败');
  restoreVault(goodEnvelopeText);

  // 9b) 文件超限：独立文案、不累计失败次数、不触发退避（状态错误不是密码错误）
  restoreVault('x'.repeat(9 * 1024 * 1024));
  plugin.lock();
  restart();
  ok((await plugin.unlock(MASTER)) === false, '负向：超过 8 MB 的保险库被拒绝读取');
  ok(plugin.lastUnlockError === plugin.t('err_vault_too_large'), '超限文案与密码错误明确区分');
  ok(plugin.lastUnlockError !== plugin.t('err_unlock_failed'), '超限不与密码错误混同');
  ok(plugin.failureCount === 0 && plugin.getUnlockWaitSeconds() === 0, '超限不计入爆破退避，不罚用户等待');
  restoreVault(goodEnvelopeText);

  // 10) 抗爆破：连续 5 次错误密码产生指数退避（K-09）
  restart();
  for (let attempt = 1; attempt <= 5; attempt += 1) {
    const waitMs = Math.max(0, plugin.blockedUntil - plugin.nowMs());
    if (waitMs) await delay(waitMs + 40);
    const failed = await plugin.unlock('wrong-master-' + attempt);
    ok(failed === false, '第 ' + attempt + ' 次错误密码被拒绝');
  }
  ok(plugin.failureCount === 5, '连续失败累计 5 次');
  ok(plugin.blockedUntil - plugin.nowMs() > 3000, '第 5 次失败后出现明显退避延迟');
  ok(plugin.getUnlockWaitSeconds() > 0, '退避期间返回剩余等待秒数');
  const blockedBefore = plugin.blockedUntil;
  restart();
  ok(blockedBefore > 0, '退避计时只在内存，可被重启清零');
  const unlockStart = Date.now();
  ok((await unlockFresh(MASTER)) === true, '正确主密码重新解锁成功');
  const unlockMs = Date.now() - unlockStart;
  ok(plugin.entries.length === 1 && plugin.entries[0].content === SECRET_TWO, '重新解锁后内容仍正确');
  ok(plugin.sessionKey.extractable === false, '重新解锁的密钥仍 non-extractable');

  // 10b) 失焦：立即遮罩；倒计时内返回到点后分别自动恢复 / 锁定清屏（G-08）
  view.render();
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) >= 0, '失焦前明文可见');
  windowStub.fire('blur');
  await delay(20);
  ok(plugin.suspended === true, '失焦后进入挂起态');
  ok(view.masked === true, '失焦后整页面板加遮罩');
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0, '负向：遮罩后 DOM 不含明文');
  ok(plugin.sessionKey !== null, '挂起但未超时仍保留会话密钥');
  ok(plugin.getCountdownRemaining() > 0, '失焦后倒计时开始');

  // 遮罩期间写操作一律拒绝；条目命令已随 UI 下线
  ok(!plugin.__commands.some((command) => command.id === 'new-entry'), '新增条目命令已随 UI 下线');
  await rejects(
    plugin.addEntry({ name: 'MaskedAdd', type: 'note', content: SECRET_ONE }),
    '挂起',
    '负向：遮罩期间写操作被拒绝'
  );
  clipboard = '';
  await plugin.copySecret(SECRET_TWO);
  ok(clipboard === '', '负向：遮罩期间复制被拒绝');
  ok(plugin.entries.length === 1, '遮罩期间未写入任何新条目');

  // 倒计时内回前台：自动解除遮罩，不要求重验
  documentStub.hidden = false;
  documentStub.fire('visibilitychange');
  ok(view.masked === false && plugin.suspended === false, '倒计时内回前台自动恢复，不重验');
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) >= 0, '恢复后重新渲染明文');

  // 倒计时到点：锁定并清空草稿/渲染区
  windowStub.fire('blur');
  ok(view.masked === true, '再次失焦加遮罩');
  plugin.countdownDeadline = plugin.nowMs() - 1;
  plugin.countdownDeadlineWall = Date.now() - 1;
  notices.length = 0;
  plugin.tickCountdown();
  ok(plugin.sessionKey === null, '倒计时到点锁定并丢弃 CryptoKey');
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0, '负向：倒计时锁定后 DOM 不含明文');
  ok(notices.some((message) => message.indexOf('倒计时结束') >= 0), '倒计时锁定给出提示');

  // 「立即」= 原来的严格行为：失焦即锁定，回来必须重输主密码
  await unlockFresh(MASTER);
  plugin.settings.backgroundLockSeconds = 0;
  view.render();
  windowStub.fire('blur');
  ok(plugin.sessionKey === null, '倒计时设为立即时失焦立刻锁定');
  ok(view.masked === false && String(textOf(view.contentEl)).indexOf('主密码') >= 0, '立即锁定后回到解锁界面');
  plugin.settings.backgroundLockSeconds = 30;

  // 10c) 重验连续错误：复用失败计数与指数退避，退避期间不做 KDF
  await unlockFresh(MASTER);
  view.render();
  plugin.suspendForBackground('panel');
  ok(plugin.suspended === true, '多面板挂起进入需重验的遮罩态');
  windowStub.fire('blur');
  ok(plugin.getCountdownRemaining() === -1, '多面板重验不启动失焦倒计时');
  windowStub.fire('focus');
  ok(view.masked === true && plugin.suspended === true, '多面板重验不被倒计时自动恢复绕过');
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const waitMs = Math.max(0, plugin.blockedUntil - plugin.nowMs());
    if (waitMs) await delay(waitMs + 40);
    ok((await plugin.reverify('wrong-' + attempt)) === false, '第 ' + attempt + ' 次重验错误被拒绝');
  }
  const reverifyBlocked = plugin.blockedUntil - plugin.nowMs();
  ok(reverifyBlocked > 1000, '重验连续失败后出现指数退避');
  const quickStart = Date.now();
  ok((await plugin.reverify(MASTER)) === false, '退避期间正确密码也被拒绝');
  ok(Date.now() - quickStart < 50, '退避期间立即返回，不付出 KDF 成本');
  ok(plugin.lastReverifyError.indexOf('秒') >= 0, '退避提示包含剩余秒数');
  await delay(reverifyBlocked + 60);
  ok((await plugin.reverify(MASTER)) === true, '退避结束后正确密码可解除挂起');
  ok(plugin.suspended === false && view.masked === false, '重验成功解除遮罩');

  // 11) 自动锁定同样清屏
  view.render();
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) >= 0, '自动锁定前明文可见');
  plugin.idleDeadline = plugin.nowMs() - 1;
  plugin.idleDeadlineWall = Date.now() - 1;
  plugin.checkAutoLock();
  ok(plugin.sessionKey === null, '自动锁定丢弃 CryptoKey');
  ok(plugin.entries.length === 0, '自动锁定清空内存条目');
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0, '负向：自动锁定后面板 DOM 不含明文');
  ok(notices.some((message) => message.indexOf('自动锁定') >= 0), '自动锁定给出用户提示');

  // 11b) 多面板共享会话：已有解锁态面板时，新开面板必须以挂起态打开并需重验（M-11）
  await unlockFresh(MASTER);
  view.render();
  await view.onOpen();
  const leaf2 = { app, view: null };
  const view2 = plugin.__viewFactories['xu-secret-vault-page'](leaf2);
  leaf2.view = view2;
  leaves.push(leaf2);
  await view2.onOpen();
  ok(view2.masked === true, '新开面板以挂起态打开，不直接显示内容');
  ok(plugin.suspended === true, '新开面板触发挂起态');
  ok(view.masked === true, '原面板同步进入遮罩');
  ok(String(textOf(view2.contentEl)).indexOf(SECRET_TWO) < 0, '负向：新面板 DOM 不含明文');
  ok(String(textOf(view2.contentEl)).indexOf('验证并继续') >= 0, '新面板要求重新验证主密码');
  const panelPassword = findAll(view2.contentEl, (el) => el.tagName === 'INPUT' && el.type === 'password')[0];
  ok(!!panelPassword, '新面板提供重验输入框');
  panelPassword.value = MASTER;
  findButton(view2.contentEl, '验证并继续').click();
  await waitFor(() => view2.masked === false, '新面板重验通过');
  ok(view2.masked === false && view.masked === false, '重验后两个面板同时解除遮罩');
  ok(plugin.suspended === false, '重验后退出挂起态');
  leaves.splice(leaves.indexOf(leaf2), 1);
  await view2.onClose();
  ok(plugin.isUnlocked() === false, '关闭新开面板后插件保持锁定，不会误解锁');
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0, '旧面板回到锁定界面且不含明文');

  // 11c) 合盖休眠：单调钟（performance.now）不前进、墙钟前进 20 分钟 → 必须锁定（M-04）
  await unlockFresh(MASTER);
  view.render();
  plugin.idleDeadline = plugin.nowMs() + 10 * 60000;
  plugin.idleDeadlineWall = Date.now() - 20 * 60000;
  plugin.checkAutoLock();
  ok(plugin.sessionKey === null, '合盖唤醒后靠墙钟死线触发自动锁定');
  ok(plugin.entries.length === 0, '合盖唤醒锁定后内存条目已清空');
  ok(notices.some((message) => message.indexOf('自动锁定') >= 0), '合盖唤醒锁定给出提示');

  // hiddenAt 的 60 秒判定同样取墙钟：单调钟只过了 1 秒，墙钟过了 61 秒
  await unlockFresh(MASTER);
  plugin.hiddenAt = plugin.nowMs() - 1000;
  plugin.hiddenAtWall = Date.now() - 61000;
  plugin.checkAutoLock();
  ok(plugin.sessionKey === null, '后台 60 秒判定在休眠场景同样靠墙钟兜底');
  plugin.hiddenAt = 0;
  plugin.hiddenAtWall = 0;

  // 12) 数据层删除，再次解锁确认已删除
  await unlockFresh(MASTER);
  view.render();
  ok(plugin.entries.length === 1, '删除前内存中有一条条目');
  const deleteResult = await plugin.deleteEntry(alphaEntry.id);
  ok(deleteResult !== false, 'deleteEntry 成功写盘');
  await waitFor(() => plugin.entries.length === 0, '删除条目完成');
  ok(plugin.entries.length === 0, '条目已删除');
  const env3Text = fileStore.get(VAULT_PATH);
  ok(String(env3Text).indexOf(SECRET_TWO) < 0, '负向：删除后密文 blob 不含明文');

  plugin.lock();
  const unlockEmpty = await unlockFresh(MASTER);
  ok(unlockEmpty === true && plugin.entries.length === 0, '重新解锁后确认条目已删除');

  // 13) 并发保存：两次快速新增不得互相覆盖（D-04）
  const concurrentA = plugin.addEntry({ name: 'Concurrent-A', type: 'note', content: SECRET_ONE });
  const concurrentB = plugin.addEntry({ name: 'Concurrent-B', type: 'note', content: SECRET_THREE });
  await Promise.all([concurrentA, concurrentB]);
  ok(plugin.entries.length === 2, '并发两次新增都保留');
  ok(
    plugin.entries.some((entry) => entry.name === 'Concurrent-A') &&
      plugin.entries.some((entry) => entry.name === 'Concurrent-B'),
    '并发保存未丢失任何一次变更'
  );
  ok(tmpFiles().length === 0, '并发保存后无残留 .tmp');

  // 14) 原子写：模拟写到一半失败，旧 blob 必须完好且可解锁（D-02 / D-03）
  const beforeFailure = goodText();
  const entriesBefore = plugin.entries.length;
  writeBehavior = 'throw-partial';
  await rejects(
    plugin.addEntry({ name: 'Gamma', type: 'note', content: SECRET_THREE }),
    '无法写入保险库文件',
    '负向：写盘中途报错时保存被拒绝，且抛出中文文案'
  );
  writeBehavior = null;
  ok(plugin.entries.length === entriesBefore, '写盘失败后内存数据未更新');
  ok(goodText() === beforeFailure, '写盘失败后旧 blob 未被改动');
  ok(tmpFiles().length === 0, '写盘失败后清理了 .tmp');
  plugin.lock();
  ok((await unlockFresh(MASTER)) === true, '写盘失败后旧 blob 仍可解锁');
  ok(plugin.entries.length === entriesBefore, '旧 blob 解锁后条目数量正确');

  // 14b) rename 后终检失败：必须回滚 .bak，且 knownBlobHash 同步修正（D-02 / 回滚）
  const beforeTerminal = goodText();
  renameCorruptOnce = true;
  await rejects(
    plugin.addEntry({ name: 'Terminal', type: 'note', content: SECRET_ONE }),
    '写入校验失败',
    '负向：rename 后终检失败被识别'
  );
  renameCorruptOnce = false;
  ok(goodText() === beforeTerminal, '终检失败后回滚到 .bak，旧密文恢复');
  ok(bakFiles().length === 0, '回滚成功后清理 .bak');
  ok(tmpFiles().length === 0, '终检失败后无残留 .tmp');
  ok(plugin.entries.length === entriesBefore, '终检失败后内存条目未更新');
  ok(
    (await plugin.hashText(goodText())) === plugin.knownBlobHash,
    '回滚后 knownBlobHash 已同步，避免下一次误判冲突'
  );
  plugin.lock();
  ok((await unlockFresh(MASTER)) === true, '终检回滚后旧库仍可解锁');
  ok(plugin.entries.length === entriesBefore, '终检回滚后条目内容仍正确');
  view.render();

  // 14c) 回滚失败：保留 .bak，错误文案给出可恢复路径
  const beforeRollback = goodText();
  renameCorruptOnce = true;
  removeFailure = true;
  let rollbackError = null;
  try {
    await plugin.addEntry({ name: 'RollbackFail', type: 'note', content: SECRET_TWO });
  } catch (error) {
    rollbackError = error;
  }
  removeFailure = false;
  renameCorruptOnce = false;
  const bakPath = VAULT_PATH + '.bak';
  ok(rollbackError !== null, '回滚失败时写操作报错');
  ok(String(rollbackError && rollbackError.message).indexOf(bakPath) >= 0, '错误文案包含 .bak 恢复路径');
  ok(fileStore.has(bakPath), '回滚失败时保留 .bak 文件');
  fileStore.set(VAULT_PATH, fileStore.get(bakPath));
  fileStore.delete(bakPath);
  plugin.lock();
  ok((await unlockFresh(MASTER)) === true, '按恢复路径从旧密文恢复后仍可解锁');
  ok(plugin.entries.length === entriesBefore, '恢复后条目数量正确');

  // 14d) 原文件本不存在：没有 .bak，文案不得指向不存在的文件
  plugin.lock();
  fileStore.delete(VAULT_PATH);
  renameCorruptOnce = true;
  removeFailure = true;
  let createError = null;
  try {
    await plugin.createVault(MASTER);
  } catch (error) {
    createError = error;
  }
  removeFailure = false;
  renameCorruptOnce = false;
  ok(createError !== null, '无原文件时创建失败仍抛出异常');
  ok(
    String(createError && createError.message).indexOf('.bak') < 0 &&
      String(createError && createError.message).indexOf('已保留旧密文备份') < 0,
    '未生成 .bak 时文案不指向不存在的文件'
  );
  ok(!fileStore.has(VAULT_PATH + '.bak'), '未生成 .bak 时不出现备份文件');
  fileStore.set(VAULT_PATH, beforeRollback);
  plugin.lock();
  ok((await unlockFresh(MASTER)) === true, '恢复正式库后仍可解锁');
  ok(plugin.entries.length === entriesBefore, '恢复正式库后条目数量正确');

  // 14f) createVault 的 mustNotExist：目标已存在时给中文提示，不暴露 adapter 英文原串
  let existsError = null;
  try {
    await plugin.createVault(MASTER);
  } catch (error) {
    existsError = error;
  }
  ok(String(existsError && existsError.message) === plugin.t('err_vault_exists'), '创建时目标已存在给出中文提示');
  ok(goodText() === beforeRollback, '创建被拒后旧库文件未被改动');

  // 14e) tmp 落位 rename 失败：回滚把旧库从 .bak 改名回来，旧库仍可解锁且错误为中文
  const beforeRenameFail = goodText();
  renameTargetFailureOnce = true;
  let renameError = null;
  try {
    await plugin.addEntry({ name: 'RenameFail', type: 'note', content: SECRET_TWO });
  } catch (error) {
    renameError = error;
  }
  renameTargetFailureOnce = false;
  ok(renameError !== null, 'rename 落位失败时写操作报错');
  ok(String(renameError && renameError.message) === plugin.t('err_save_failed'), '错误文案是中文 err_save_failed，不是 adapter 英文原串');
  ok(goodText() === beforeRenameFail, 'rename 失败回滚后旧库字节不变');
  ok(!fileStore.has(VAULT_PATH + '.bak'), '回滚成功后清理 .bak');
  plugin.lock();
  ok((await unlockFresh(MASTER)) === true, 'rename 失败回滚后旧库仍可解锁');
  ok(plugin.entries.length === entriesBefore, 'rename 失败回滚后条目内容仍正确');

  // 15) 同步冲突：外部改动后拒绝覆盖，另存 conflict 副本（D-06 / S-02 / S-09）
  const hashBeforeConflict = plugin.knownBlobHash;
  const externalText = goodText() + '\n';
  restoreVault(externalText);
  await plugin.addEntry({ name: 'Conflict', type: 'note', content: SECRET_THREE });
  const conflicts = conflictFiles();
  ok(conflicts.length === 1, '检测到外部改动后生成 conflict 副本');
  ok(goodText() === externalText, '拒绝覆盖外部改动后的原文件');
  ok(plugin.entries.length === entriesBefore, '冲突时本次改动未静默合并进内存');
  ok(plugin.conflictPending === true, '冲突后进入只读冲突态');
  ok(notices.some((message) => message.indexOf('另存副本') >= 0), '冲突文案明确：已另存副本、原文件未覆盖');
  ok(String(fileStore.get(conflicts[0])).indexOf(SECRET_THREE) < 0, '负向：conflict 副本仍是密文');
  ok(plugin.knownBlobHash === hashBeforeConflict, '冲突副本写盘不污染 knownBlobHash（基线仍指向真实保险库）');
  await rejects(
    plugin.addEntry({ name: 'AfterConflict', type: 'note', content: SECRET_ONE }),
    '重新加载',
    '负向：冲突未重载前禁止继续编辑'
  );
  const reloaded = await plugin.reloadFromConflict();
  ok(reloaded === true && plugin.conflictPending === false, '重新加载后解除冲突态');
  ok(plugin.entries.length === entriesBefore, '重新加载后内存与磁盘一致');

  // 15b) TOCTOU：加密/校验期间外部写入（rename 前复核）不得被静默覆盖
  const raceBase = goodText();
  const raceExternal = raceBase + '\n';
  afterReadHook = (filePath) => {
    if (filePath === VAULT_PATH) fileStore.set(VAULT_PATH, raceExternal);
  };
  const raceResult = await plugin.addEntry({ name: 'Race', type: 'note', content: SECRET_TWO });
  afterReadHook = null;
  ok(goodText() === raceExternal, '加密窗口内的外部写入未被静默覆盖');
  ok(raceResult === false, 'TOCTOU 冲突时保存返回失败');
  ok(plugin.conflictPending === true, 'TOCTOU 冲突同样进入只读冲突态');
  ok(plugin.entries.length === entriesBefore, 'TOCTOU 冲突不更新内存快照');
  ok(conflictFiles().length === 2, 'TOCTOU 冲突也另存副本');
  ok((await plugin.reloadFromConflict()) === true && plugin.conflictPending === false, 'TOCTOU 冲突可重载恢复');


  // 16) 剪贴板只在确认内容仍是本插件写入值时才清（G-02）
  notices.length = 0;
  clipboard = '';
  await plugin.copySecret(SECRET_ONE);
  clipboardReadFailure = true;
  await plugin.clearClipboardIfOwned(true);
  clipboardReadFailure = false;
  ok(clipboard === SECRET_ONE, '负向：读剪贴板失败时不清空，避免误删用户内容');
  ok(notices.some((message) => message.indexOf('手动检查') >= 0), '读取失败时提示手动检查');

  await plugin.copySecret(SECRET_ONE);
  clipboard = 'USER-OWN-CLIPBOARD';
  await plugin.clearClipboardIfOwned(true);
  ok(clipboard === 'USER-OWN-CLIPBOARD', '负向：内容已被用户替换时不清空');

  clipboard = '';
  await plugin.copySecret(SECRET_ONE);
  await plugin.clearClipboardIfOwned(true);
  ok(clipboard === '', '确认仍为本插件写入值时清空');
  ok(notices.some((message) => message.indexOf('剪贴板中的密钥已清空') >= 0), '确认清空后给出提示');

  // 17) 保险库文件缺失：错误态而不是引导重新创建（D-10 / S-05）
  plugin.lock();
  fileStore.delete(VAULT_PATH);
  plugin.vaultState = 'unknown';
  view.render();
  await waitFor(() => plugin.vaultState !== 'unknown', '重新检测缺失状态');
  ok(String(textOf(view.contentEl)).indexOf('找不到保险库文件') >= 0, '文件缺失显示错误态');
  ok(String(textOf(view.contentEl)).indexOf('创建保险库') < 0, '文件缺失时不出现创建入口');
  ok((await unlockFresh(MASTER)) === false, '缺失时解锁返回 false');
  ok(plugin.lastUnlockError === plugin.t('err_vault_missing'), '缺失时返回专门文案');
  restoreVault(goodEnvelopeText);

  // 18) 明文不进入任何信封历史
  for (const [label, text] of [
    ['创建', JSON.stringify(env0)],
    ['新增', JSON.stringify(env1)],
    ['编辑', JSON.stringify(env2)],
    ['删除', env3Text],
    ['最终', goodText()],
  ]) {
    ok(
      text.indexOf(SECRET_ONE) < 0 &&
        text.indexOf(SECRET_TWO) < 0 &&
        text.indexOf(SECRET_THREE) < 0 &&
        text.indexOf(MASTER) < 0,
      '负向：' + label + '后的密文不含任何明文或主密码'
    );
  }

  // 19) 主密码与明文不进入设置持久化
  await plugin.saveSettings();
  const settingsText = JSON.stringify(plugin.settings);
  ok(settingsText.indexOf(MASTER) < 0, '设置对象不含主密码');
  ok(settingsText.indexOf(SECRET_ONE) < 0 && settingsText.indexOf(SECRET_TWO) < 0, '设置对象不含条目明文');
  const savedText = JSON.stringify(plugin.__savedData);
  ok(savedText.indexOf(MASTER) < 0 && savedText.indexOf(SECRET_TWO) < 0, 'data.json 写入记录不含主密码或明文');

  // 19b) v1 兼容读取与自动升级 / 未知版本明确提示（发社区前必须有）
  const legacy = await buildLegacyV1Envelope(MASTER, [
    {
      id: 'legacy-1',
      name: 'Legacy Entry',
      type: 'note',
      content: SECRET_ONE,
      tags: ['legacy'],
      note: '',
      createdAt: '',
      updatedAt: '',
    },
  ]);
  restoreVault(JSON.stringify(legacy, null, 2));
  plugin.lock();
  restart();
  ok((await plugin.unlock(MASTER)) === true, 'v1 旧信封可兼容解锁');
  ok(plugin.entries.length === 1 && plugin.entries[0].content === SECRET_ONE, 'v1 条目内容正确');
  const upgraded = JSON.parse(fileStore.get(VAULT_PATH));
  ok(upgraded.formatVersion === 2, 'v1 读取成功后自动升级为 v2');
  ok(notices.some((message) => message.indexOf('升级') >= 0), '升级给出提示');
  ok(String(fileStore.get(VAULT_PATH)).indexOf(SECRET_ONE) < 0, '负向：升级后的密文不含明文');

  const unknownVersion = JSON.parse(fileStore.get(VAULT_PATH));
  unknownVersion.formatVersion = 3;
  restoreVault(JSON.stringify(unknownVersion, null, 2));
  plugin.lock();
  restart();
  ok((await plugin.unlock(MASTER)) === false, '负向：未知版本解锁被拒绝');
  ok(plugin.lastUnlockError === plugin.t('err_version_unsupported'), '未知版本提示「版本不支持」');
  ok(plugin.lastUnlockError !== plugin.t('err_unlock_failed'), '未知版本不和密码错误混同');
  restoreVault(JSON.stringify(upgraded, null, 2));

  // 19c) v1 升级失败：本次仍可解锁，失败提示只出现一次
  restoreVault(JSON.stringify(legacy, null, 2));
  plugin.lock();
  restart();
  notices.length = 0;
  writeBehavior = 'throw-before';
  ok((await plugin.unlock(MASTER)) === true, 'v1 升级写盘失败不影响本次解锁');
  ok(notices.some((message) => message.indexOf('升级失败') >= 0), '升级失败给出一次提示');
  ok(JSON.parse(fileStore.get(VAULT_PATH)).formatVersion === 1, '升级失败后继续使用旧格式');
  plugin.lock();
  restart();
  notices.length = 0;
  ok((await plugin.unlock(MASTER)) === true, '再次解锁 v1 仍成功');
  ok(!notices.some((message) => message.indexOf('升级失败') >= 0), '升级失败提示不重复');
  writeBehavior = null;
  restoreVault(JSON.stringify(upgraded, null, 2));
  plugin.lock();

  // 19d) 冲突副本枚举与显式选择（S-07）：不自动挑选，选定后加载对应文件
  for (const stale of conflictFiles()) fileStore.delete(stale);
  const conflictCopy = VAULT_PATH.replace(/\.enc$/i, '') + '.conflict-20200101-000000.enc';
  fileStore.set(conflictCopy, fileStore.get(VAULT_PATH));
  await plugin.lock();
  await plugin.scanVaultSources();
  ok(plugin.vaultSources.length === 2, '解锁前枚举到正式库与冲突副本');
  ok(plugin.vaultSources[0] === VAULT_PATH, '正式库排在首位');
  ok(plugin.selectedVaultPath === '' && plugin.getVaultPath() === VAULT_PATH, '默认不自动挑选冲突副本');
  view.render();
  ok(String(textOf(view.contentEl)).indexOf('选择要加载的保险库文件') >= 0, '解锁界面显示候选库列表');
  ok(String(textOf(view.contentEl)).indexOf('请确认要解锁的是哪一个文件') >= 0, '提示需由用户确认选择');
  const sourceButton = findButton(view.contentEl, conflictCopy);
  ok(!!sourceButton, '候选列表包含冲突副本');
  sourceButton.click();
  ok(plugin.selectedVaultPath === conflictCopy, '点击后显式选中冲突副本');
  view.render();
  const sourcePassword = findAll(view.contentEl, (el) => el.tagName === 'INPUT' && el.type === 'password')[0];
  sourcePassword.value = MASTER;
  findButton(view.contentEl, '解锁').click();
  await waitFor(() => plugin.isUnlocked(), '加载所选冲突副本');
  ok(plugin.entries.length === 1 && plugin.entries[0].content === SECRET_ONE, '从所选副本加载内容');

  // 19d-2) 副本只读：隐藏写入口、显示横幅、保留复制；写操作拒绝且两个文件字节都不变
  view.render();
  ok(plugin.isReadOnlyCopy() === true, '选中副本后进入只读态');
  ok(String(textOf(view.contentEl)).indexOf('正在查看冲突副本（只读）') >= 0, '显示只读横幅');
  ok(String(textOf(view.contentEl)).indexOf('不会写回正式保险库') >= 0, '横幅明确不会写回正式库');
  ok(!findButton(view.contentEl, '编辑笔记'), '只读态隐藏笔记编辑入口');
  ok(
    !findButton(view.contentEl, '新增') &&
      !findButton(view.contentEl, '编辑') &&
      !findButton(view.contentEl, '删除') &&
      !findButton(view.contentEl, '显示'),
    '只读态不存在任何条目管理入口'
  );
  ok(findAll(view.contentEl, (el) => el.hasClass('xsv-notes')).length === 1, '只读态仍渲染笔记列表与阅读区');
  const canonicalBeforeWrite = fileStore.get(VAULT_PATH);
  const copyBeforeWrite = fileStore.get(conflictCopy);
  await rejects(
    plugin.addEntry({ name: 'CopyWrite', type: 'note', content: SECRET_TWO }),
    '只读',
    '负向：只读副本上的新增被拒'
  );
  await rejects(
    plugin.updateEntry(plugin.entries[0].id, { name: 'CopyEdit', type: 'note', content: SECRET_TWO }),
    '只读',
    '负向：只读副本上的编辑被拒'
  );
  await rejects(
    plugin.deleteEntry(plugin.entries[0].id),
    '只读',
    '负向：只读副本上的删除被拒'
  );
  ok(fileStore.get(VAULT_PATH) === canonicalBeforeWrite, '正式库文件字节未变');
  ok(fileStore.get(conflictCopy) === copyBeforeWrite, '副本文件字节未变');

  plugin.lock();
  await plugin.scanVaultSources();
  ok(plugin.selectedVaultPath === '' && plugin.getVaultPath() === VAULT_PATH, '锁定后选择回到正式库');
  ok(plugin.isReadOnlyCopy() === false, '锁定后只读态复位');
  fileStore.delete(conflictCopy);

  // 19e) 嵌套冲突副本（xxx.conflict-a.conflict-b.enc）也能被枚举，且按时间倒序
  const oldCopy = VAULT_PATH.replace(/\.enc$/i, '') + '.conflict-20200101-000000.enc';
  const nestedCopy =
    VAULT_PATH.replace(/\.enc$/i, '') + '.conflict-20200101-000000.conflict-20200102-000000.enc';
  fileStore.set(oldCopy, fileStore.get(VAULT_PATH));
  fileStore.set(nestedCopy, fileStore.get(VAULT_PATH));
  await plugin.lock();
  await plugin.scanVaultSources();
  ok(plugin.vaultSources.length === 3, '正式库与两层/单层冲突副本都被枚举');
  ok(plugin.vaultSources.indexOf(nestedCopy) >= 0, '嵌套冲突副本进入候选列表');
  ok(plugin.vaultSources[0] === VAULT_PATH, '存在嵌套副本时默认仍指向正式库');
  ok(plugin.selectedVaultPath === '', '嵌套副本不会被自动选中');
  ok(
    plugin.vaultSources.indexOf(nestedCopy) < plugin.vaultSources.indexOf(oldCopy),
    '候选副本按冲突时间倒序'
  );
  fileStore.delete(oldCopy);
  fileStore.delete(nestedCopy);

  // 20) 笔记 / 表格 / 链接（0.2.0）
  plugin.lock();
  restart();
  // 20a) 旧数据（只有 entries，没有 notes / contentVersion）读取后自动补默认笔记
  const noNotesEnvelope = await buildV2EnvelopeWithoutNotes(MASTER, [
    {
      id: 'legacy-note-1',
      name: 'Legacy Note Entry',
      type: 'note',
      content: SECRET_THREE,
      tags: [],
      note: '',
      createdAt: '',
      updatedAt: '',
    },
  ]);
  restoreVault(JSON.stringify(noNotesEnvelope, null, 2));
  ok((await unlockFresh(MASTER)) === true, '旧结构（无 notes）信封可解锁');
  ok(plugin.notes.length === 1, '旧结构读取后自动补一篇默认笔记');
  ok(
    plugin.notes[0].id === 'note-primary' && plugin.notes[0].title === '我的密钥',
    '默认笔记 id 与标题符合约定'
  );
  ok(plugin.contentVersion === 1, '旧结构 contentVersion 缺省为兼容版本 1');

  // 20b) 准备两个条目，供引用语法使用
  await plugin.addEntry({ name: 'GitHub', type: 'password', content: SECRET_ONE, tags: [], note: '' });
  await plugin.addEntry({ name: 'API Key', type: 'api-key', content: SECRET_TWO, tags: [], note: '' });
  ok(plugin.entries.length === 3, '准备条目完成（旧条目 + 两个新条目）');

  const NOTE_BODY_MARKER = 'NOTE-BODY-MARKER-9F3A';
  const NOTE_SOURCE = [
    '# 我的密钥',
    '',
    '段落：这是 **加粗** 与 `行内代码`，还有一个安全链接 [官网](https://example.com)。',
    'HTML 原样显示：<script>alert(1)</script>',
    '',
    '## 账号表',
    '',
    '| 名称 | 账号 | 密码 | 备注 |',
    '| :--- | ---: | :---: | :--- |',
    '| GitHub | {{GitHub.账号}} | {{GitHub.密码}} | PLAIN-TABLE-VALUE |',
    '| 缺失 | {{Missing.密码}} | LITERAL-SECRET-CELL |  |',
    '',
    '- 列表项一',
    '- 列表项二',
    '1. 有序一',
    '2. 有序二',
    '',
    '危险链接：[危险](javascript:alert(1))',
    '本地链接：[本地](file:///etc/passwd)',
    '',
    NOTE_BODY_MARKER,
  ].join('\n');

  ok((await plugin.saveNote('note-primary', NOTE_SOURCE)) !== undefined, '笔记保存调用成功');
  ok(plugin.notes[0].body === NOTE_SOURCE, '保存后内存中的笔记体已更新');
  ok(plugin.notes[0].updatedAt !== '', '保存后写入 updatedAt');

  const notePayload = await plugin.decryptEnvelope(plugin.parseEnvelope(goodText()), plugin.sessionKey);
  ok(notePayload.contentVersion === 2, '写盘载荷 contentVersion 升级为 2');
  ok(Array.isArray(notePayload.notes) && notePayload.notes.length === 1, '密文中包含 notes 数组');
  ok(notePayload.notes[0].body === NOTE_SOURCE, '笔记体完整写入密文');
  ok(notePayload.notes[0].body.indexOf('{{GitHub.密码}}') >= 0, '旧引用文本按字面保留在密文中');
  ok(notePayload.entries.length === 3, '保存笔记不影响既有 entries');
  const noteCipherText = goodText();
  ok(noteCipherText.indexOf(NOTE_BODY_MARKER) < 0, '负向：密文不含笔记明文标记');
  ok(noteCipherText.indexOf(SECRET_ONE) < 0 && noteCipherText.indexOf(SECRET_TWO) < 0, '负向：密文不含条目明文');

  const mainSource = fs.readFileSync(MAIN, 'utf8');
  ok(!/\.innerHTML\s*=/.test(mainSource), '负向：渲染代码不使用 innerHTML');
  ok(mainSource.indexOf('insertAdjacentHTML') < 0, '负向：渲染代码不使用 insertAdjacentHTML');

  // 20c) 视图：表格 / 笔记切换
  view.render();
  ok(!findButton(view.contentEl, '表格') && !findButton(view.contentEl, '笔记'), '0.3.0 顶部无表格 / 笔记切换');
  ok(findAll(view.contentEl, (el) => el.hasClass('xsv-page')).length === 1, '解锁后为整页布局');
  ok(view.contentEl.querySelector('.xsv-notes') !== null, '渲染笔记布局');
  ok(!!findButton(view.contentEl, '我的密钥'), '笔记列表显示默认笔记标题');
  const noteText = textOf(view.contentEl);
  ok(noteText.indexOf('NOTE-BODY-MARKER') >= 0, '笔记正文已渲染');
  ok(noteText.indexOf('**加粗**') < 0 && noteText.indexOf('| 名称 |') < 0, '负向：渲染区不出现 Markdown 源码标记');

  // 20d) 管道表格：真实 table、列对齐、字面文本单元格
  const mdTables = findAll(view.contentEl, (el) => el.tagName === 'TABLE');
  ok(mdTables.length === 1 && mdTables[0].hasClass('xsv-md-table'), '管道表格渲染为真实 table');
  const headerCells = findAll(mdTables[0], (el) => el.tagName === 'TH');
  ok(headerCells.length === 4, '表头为 4 列');
  ok(
    textOf(headerCells[0]).trim() === '名称' &&
      textOf(headerCells[1]).trim() === '账号' &&
      textOf(headerCells[2]).trim() === '密码' &&
      textOf(headerCells[3]).trim() === '备注',
    '表头文本正确'
  );
  ok(headerCells[0].style.textAlign === 'left', '左对齐列按 :--- 对齐');
  ok(headerCells[1].style.textAlign === 'right', '右对齐列按 ---: 对齐');
  ok(headerCells[2].style.textAlign === 'center', '居中列按 :---: 对齐');
  ok(headerCells[3].style.textAlign === 'left', '第四列左对齐');
  const bodyCells = findAll(mdTables[0], (el) => el.tagName === 'TD');
  ok(bodyCells.length === 8, '两行数据渲染出 8 个单元格');
  ok(
    textOf(mdTables[0]).indexOf('PLAIN-TABLE-VALUE') >= 0,
    '表格中的明文值照常显示'
  );
  ok(
    findAll(mdTables[0], (el) => el.hasClass('xsv-cell-secret')).length === 0,
    '默认全明文：名为「密码」的列也不自动遮挡'
  );
  ok(
    textOf(mdTables[0]).indexOf('LITERAL-SECRET-CELL') >= 0,
    '密码列的真实值默认直接显示'
  );
  ok(
    findAll(view.contentEl, (el) => el.hasClass('xsv-sensitive-note')).length === 0,
    '负向：默认不出现「本表 N 列按密码处理」说明行'
  );

  // 20e) 0.3.1 字面文本：{{...}} 不再解析，按源码原样显示
  const refButtons = findAll(view.contentEl, (el) => el.tagName === 'BUTTON' && el.hasClass('xsv-ref'));
  ok(refButtons.length === 0, '引用不再渲染为掩码按钮');
  ok(noteText.indexOf('{{GitHub.账号}}') >= 0, '旧引用按字面文本显示在账号列');
  ok(noteText.indexOf('{{Missing.密码}}') >= 0, '缺失引用同样按字面文本显示');
  ok(noteText.indexOf('引用缺失') < 0, '负向：不再出现「引用缺失」提示');
  ok(noteText.indexOf(SECRET_ONE) < 0, '负向：旧引用不再解析出条目值');
  ok(
    !findAll(view.contentEl, (el) => el.hasClass('xsv-ref-missing')).length,
    '负向：不存在引用缺失节点'
  );

  // 20f) 链接白名单：只有 http/https 可点击
  const anchors = findAll(view.contentEl, (el) => el.tagName === 'A');
  ok(anchors.length === 1, '负向：只有 http/https 链接生成可点击元素');
  ok(anchors[0].getAttribute('href') === 'https://example.com', 'http/https 链接保留原地址');
  ok(noteText.indexOf('javascript:alert(1)') >= 0, '负向：javascript: 链接按纯文本显示');
  ok(noteText.indexOf('file:///etc/passwd') >= 0, '负向：file:// 链接按纯文本显示');
  ok(
    !findAll(view.contentEl, (el) => el.tagName === 'SCRIPT').length,
    '负向：Markdown 中的脚本标签不会变成真实节点'
  );

  // 20g) 其它 Markdown 结构
  ok(findAll(view.contentEl, (el) => el.tagName === 'H2').length === 1, '二级标题渲染为 h2');
  ok(findAll(view.contentEl, (el) => el.tagName === 'STRONG').length >= 1, '粗体渲染为 strong');
  ok(findAll(view.contentEl, (el) => el.tagName === 'CODE').length >= 1, '行内代码渲染为 code');
  ok(findAll(view.contentEl, (el) => el.tagName === 'UL' && el.children.length === 2).length === 1, '无序列表两项');
  ok(findAll(view.contentEl, (el) => el.tagName === 'OL' && el.children.length === 2).length === 1, '有序列表两项');

  // 20h) 编辑态：等宽 textarea 直接写 Markdown，保存走原子写链路
  const editNoteButton = findButton(view.contentEl, '编辑笔记');
  ok(!!editNoteButton, '笔记模式提供编辑入口');
  editNoteButton.click();
  ok(view.noteEditing === true, '点击后进入编辑态');
  const editor = findAll(view.contentEl, (el) => el.tagName === 'TEXTAREA')[0];
  ok(!!editor && editor.hasClass('xsv-note-editor'), '编辑态使用等宽 textarea');
  ok(editor.value === NOTE_SOURCE, 'textarea 显示完整 Markdown 源码');
  editor.value = NOTE_SOURCE + '\n\n追加-EDIT-MARKER-2B7C';
  editor.fire('input');
  findButton(view.contentEl, '保存笔记').click();
  await waitFor(() => plugin.notes[0].body.indexOf('追加-EDIT-MARKER-2B7C') >= 0, '保存笔记');
  ok(view.noteEditing === false && view.noteDraft === null, '保存后退出编辑态并丢弃草稿');
  ok(!findAll(view.contentEl, (el) => el.tagName === 'TEXTAREA').length, '保存后 textarea 已移除');
  const editedPayload = await plugin.decryptEnvelope(plugin.parseEnvelope(goodText()), plugin.sessionKey);
  ok(editedPayload.notes[0].body.indexOf('追加-EDIT-MARKER-2B7C') >= 0, '编辑后的笔记已加密落盘');
  ok(goodText().indexOf('追加-EDIT-MARKER-2B7C') < 0, '负向：编辑后的密文不含笔记明文');

  // 20i) 取消编辑不写盘
  findButton(view.contentEl, '编辑笔记').click();
  const cancelEditor = findAll(view.contentEl, (el) => el.tagName === 'TEXTAREA')[0];
  cancelEditor.value = '取消-不应落盘-CANCEL-MARKER';
  cancelEditor.fire('input');
  findButton(view.contentEl, '取消编辑').click();
  ok(view.noteEditing === false && view.noteDraft === null, '取消编辑后丢弃草稿');
  ok(plugin.notes[0].body.indexOf('CANCEL-MARKER') < 0, '负向：取消编辑不改内存笔记');
  ok(goodText().indexOf('CANCEL-MARKER') < 0, '负向：取消编辑不写盘');

  // 20j) 锁定后笔记区、编辑器、列表与草稿全部清空
  const noteTextBeforeLock = textOf(view.contentEl);
  ok(noteTextBeforeLock.indexOf(NOTE_BODY_MARKER) >= 0, '锁定前笔记正文可见');
  plugin.lock();
  view.render();
  const lockedText = textOf(view.contentEl);
  ok(lockedText.indexOf(NOTE_BODY_MARKER) < 0, '锁定后笔记区无明文');
  ok(lockedText.indexOf('追加-EDIT-MARKER-2B7C') < 0, '锁定后编辑内容无残留');
  ok(!findAll(view.contentEl, (el) => el.hasClass('xsv-notes')).length, '锁定后笔记列表被移除');
  ok(!findAll(view.contentEl, (el) => el.tagName === 'TEXTAREA').length, '锁定后编辑器被移除');
  ok(view.noteDraft === null && view.noteEditing === false, '锁定后笔记草稿被丢弃');
  ok(plugin.notes.length === 0, '锁定后内存中的 notes 被清空');

  // 20k) 只读冲突副本：笔记只能看，保存被拒且文件字节不变
  const canonicalNoteText = fileStore.get(VAULT_PATH);
  ok((await plugin.unlock(MASTER)) === true, '重新解锁正式库');
  const readOnlyCopy = VAULT_PATH.replace(/\.enc$/i, '') + '.conflict-20200103-000000.enc';
  fileStore.set(readOnlyCopy, canonicalNoteText);
  plugin.lock();
  await plugin.scanVaultSources();
  plugin.selectedVaultPath = readOnlyCopy;
  ok((await plugin.unlock(MASTER)) === true, '只读副本可解锁');
  view.render();
  ok(plugin.isReadOnlyCopy() === true, '查看副本时进入只读态');
  ok(!findButton(view.contentEl, '编辑笔记'), '只读副本下不提供笔记编辑入口');
  ok(String(textOf(view.contentEl)).indexOf('NOTE-BODY-MARKER') >= 0, '只读副本下笔记仍可查看');
  const copyBytesBefore = fileStore.get(readOnlyCopy);
  const canonicalBytesBefore = fileStore.get(VAULT_PATH);
  await rejects(
    plugin.saveNote(plugin.notes[0].id, '只读副本写入尝试'),
    '只读',
    '负向：只读副本下笔记保存被拒'
  );
  ok(fileStore.get(readOnlyCopy) === copyBytesBefore, '只读副本文件字节未变（笔记写入）');
  ok(fileStore.get(VAULT_PATH) === canonicalBytesBefore, '正式库文件字节未变（笔记写入）');
  plugin.lock();
  await plugin.scanVaultSources();
  fileStore.delete(readOnlyCopy);
  ok(plugin.isReadOnlyCopy() === false && plugin.selectedVaultPath === '', '锁定后只读态复位');

  // 21) 0.3.0 笔记界面交互（示例表格 / 可用条目名 / 草稿清理）
  ok((await plugin.unlock(MASTER)) === true, '解锁以测试笔记界面');
  await plugin.saveNote('note-primary', '');
  view.render();
  ok(!findAll(view.contentEl, (el) => el.hasClass('xsv-mode-tab')).length, '不再渲染表格 / 笔记切换标签');
  ok(!findAll(view.contentEl, (el) => el.hasClass('xsv-mode-tab-table')).length, '表格切换入口已移除');
  ok(!findButton(view.contentEl, '表格'), '界面上没有「表格」按钮');
  ok(!findButton(view.contentEl, '新增'), '界面上没有「新增」按钮');

  // 21a) 空态引导 + 示例表格按钮（不自动保存）
  const guide = findAll(view.contentEl, (el) => el.hasClass('xsv-note-guide'))[0];
  ok(!!guide, '空笔记显示引导块');
  ok(textOf(guide).indexOf('从这里开始写账号表') >= 0, '引导块说明可见');
  const sampleButton = findButton(view.contentEl, '插入示例表格');
  ok(!!sampleButton, '空态提供插入示例表格按钮');
  sampleButton.click();
  ok(view.noteEditing === true, '点击示例后进入编辑态');
  const sampleEditor = findAll(view.contentEl, (el) => el.tagName === 'TEXTAREA')[0];
  ok(sampleEditor.value.indexOf('| 名称 | 账号 | 密码 | 网址 |') >= 0, '示例包含四列表头');
  ok(sampleEditor.value.indexOf('{{') < 0, '示例不再生成 {{...}} 引用');
  ok(sampleEditor.value.indexOf('\\|') >= 0, '示例含 \\| 转义的特殊字符密码');
  ok(
    sampleEditor.value.indexOf('[github.com](https://github.com)') >= 0 &&
      sampleEditor.value.indexOf('[aliyun.com](https://console.aliyun.com)') >= 0,
    '示例网址列使用可点链接'
  );
  ok(
    sampleEditor.value.indexOf('只有把列名加进') >= 0,
    '示例表下说明默认不遮挡、只有手动设为密文才遮挡'
  );
  ok(plugin.notes[0].body === '', '负向：示例插入不自动保存');
  findButton(view.contentEl, '保存笔记').click();
  await waitFor(() => plugin.notes[0].body.indexOf('| 名称 | 账号 | 密码 | 网址 |') >= 0, '保存示例笔记');
  view.render();
  const sampleTable = findAll(view.contentEl, (el) => el.tagName === 'TABLE')[0];
  const sampleCells = findAll(sampleTable, (el) => el.tagName === 'TD');
  ok(sampleCells.length === 8, '示例渲染两行四列共 8 个单元格');
  ok(
    findAll(sampleTable, (el) => el.hasClass('xsv-cell-secret')).length === 0,
    '示例默认全明文：密码列不遮挡'
  );
  ok(
    textOf(sampleTable).indexOf('p@ss|w0rd*_2026') >= 0,
    '示例密码的 \\| 转义在渲染时还原为 |，且 * _ 原样显示'
  );
  const samplePasswordCell = sampleCells.filter((el) => textOf(el).indexOf('p@ss|w0rd*_2026') >= 0)[0];
  clipboard = '';
  samplePasswordCell.click();
  await waitFor(() => clipboard === 'p@ss|w0rd*_2026', '示例密码点击复制');
  ok(clipboard === 'p@ss|w0rd*_2026', '示例密码复制逐字一致');
  const sampleAnchors = findAll(sampleTable, (el) => el.tagName === 'A');
  ok(
    sampleAnchors.length === 2 &&
      sampleAnchors.some((el) => el.getAttribute('href') === 'https://github.com') &&
      sampleAnchors.some((el) => el.getAttribute('href') === 'https://console.aliyun.com'),
    '示例网址列插入后即可点击跳转'
  );

  // 21b) 示例插入不重复：已有内容先选择追加/替换
  await plugin.saveNote('note-primary', '已有内容-EXISTING');
  view.render();
  findButton(view.contentEl, '编辑笔记').click();
  const dupEditor = findAll(view.contentEl, (el) => el.tagName === 'TEXTAREA')[0];
  findButton(view.contentEl, '插入示例表格').click();
  const choice = findAll(view.contentEl, (el) => el.hasClass('xsv-sample-choice'))[0];
  ok(!!choice && choice.style.display !== 'none', '已有内容时先显示追加/替换选择');
  ok(dupEditor.value.indexOf('| 名称 | 账号 | 密码 | 网址 |') < 0, '负向：未选择前不插入示例');
  ok(plugin.notes[0].body === '已有内容-EXISTING', '负向：未选择前不改内存笔记');
  findButton(view.contentEl, '追加到末尾').click();
  const headerCount = (dupEditor.value.match(/\| 名称 \| 账号 \| 密码 \| 网址 \|/g) || []).length;
  ok(headerCount === 1, '追加后示例只出现一次');
  ok(dupEditor.value.indexOf('已有内容-EXISTING') === 0, '追加保留原有内容');
  ok(choice.style.display === 'none', '选择后隐藏选择条');
  findButton(view.contentEl, '插入示例表格').click();
  ok(choice.style.display !== 'none', '再次点击示例重新出现选择');
  const headerCount2 = (dupEditor.value.match(/\| 名称 \| 账号 \| 密码 \| 网址 \|/g) || []).length;
  ok(headerCount2 === 1, '负向：第二次点击本身不造成重复');
  findButton(choice, '取消').click();
  ok(choice.style.display === 'none', '取消追加后保留原有内容');
  ok((dupEditor.value.match(/\| 名称 \| 账号 \| 密码 \| 网址 \|/g) || []).length === 1, '取消后仍只有一份示例');
  findButton(view.contentEl, '插入示例表格').click();
  findButton(view.contentEl, '替换全文').click();
  ok(dupEditor.value.indexOf('已有内容-EXISTING') < 0, '替换全文移除原内容');
  ok((dupEditor.value.match(/\| 名称 \| 账号 \| 密码 \| 网址 \|/g) || []).length === 1, '替换后只有一份示例');

  // 21e) 引用语法取消后：编辑器不再列条目名，旧文本按字面保存与渲染
  ok(
    !findAll(view.contentEl, (el) => el.hasClass('xsv-ref-names')).length,
    '编辑态不再显示可用条目名提示条'
  );
  ok(plugin.entries.length === 3, '条目数据仍完整保留在内存/密文中');
  dupEditor.value = '旧引用字面：{{GitHub.密码}} 与 {{Missing.账号}}';
  dupEditor.fire('input');
  findButton(view.contentEl, '保存笔记').click();
  await waitFor(
    () => plugin.notes[0].body.indexOf('{{GitHub.密码}}') >= 0,
    '字面引用文本保存为笔记内容'
  );
  view.render();
  ok(
    textOf(view.contentEl).indexOf('{{GitHub.密码}}') >= 0 &&
      textOf(view.contentEl).indexOf('{{Missing.账号}}') >= 0,
    '旧引用文本按字面渲染'
  );
  ok(
    !findAll(view.contentEl, (el) => el.tagName === 'BUTTON' && el.hasClass('xsv-ref')).length,
    '负向：字面引用不生成掩码按钮'
  );
  ok(textOf(view.contentEl).indexOf(SECRET_ONE) < 0, '负向：字面引用不解析出条目值');

  // 21c) 0.3.0 已移除「引用缺失 → 创建条目」与「条目保存笔记提示」
  ok(!findAll(view.contentEl, (el) => el.hasClass('xsv-ref-missing-action')).length, '引用缺失不再提供创建入口');
  ok(typeof plugin.maybeHintNoteContent === 'undefined', '条目保存的笔记提示已随条目 UI 移除');

  // 21d) 锁定后草稿与示例选择一并清空
  view.noteEditing = true;
  view.noteDraft = '示例草稿-DRAFT-MARKER';
  view.render();
  plugin.lock();
  ok(view.noteEditing === false && view.noteDraft === null, '锁定后草稿被丢弃');
  ok(String(textOf(view.contentEl)).indexOf('DRAFT-MARKER') < 0, '锁定后不残留示例草稿');
  ok(!findAll(view.contentEl, (el) => el.hasClass('xsv-sample-choice')).length, '锁定后追加/替换选择条被移除');

  // 22) crypto.subtle 不可用时明确报错
  plugin.lock();
  const savedCrypto = plugin.cryptoApi;
  plugin.cryptoApi = null;
  view.render();
  ok(String(textOf(view.contentEl)).indexOf('WebCrypto') >= 0, '无 WebCrypto 时界面明确提示');
  plugin.cryptoApi = savedCrypto;
  view.render();

  // 23) 整页视图单实例：已存在整页标签时只聚焦，不新建第二个面板
  const pageLeaves = () =>
    leaves.filter(
      (item) => item.view && typeof item.view.getViewType === 'function' && item.view.getViewType() === 'xu-secret-vault-page'
    );
  ok(pageLeaves().length === 1, '当前只有一个整页标签');
  const firstOpen = await plugin.openVaultView();
  ok(firstOpen === pageLeaves()[0], '再次打开聚焦已有整页标签');
  const secondOpen = await plugin.openVaultView();
  ok(pageLeaves().length === 1, '连续打开两次仍只有一个整页标签');
  ok(secondOpen === pageLeaves()[0], '不会新建重复面板');

  // 24) 单元格即复制单元：字面转义 / 密文列 / 特殊符号逐字一致
  ok((await plugin.unlock(MASTER)) === true, '解锁以测试表格单元格');
  const SPECIAL_VALUE = 'P|*_`{{}}<>&😀中文，。';
  const SPECIAL_SOURCE = 'P\\|*_`{{}}<>&😀中文，。';
  const BACKSLASH_VALUE = 'C:\\temp\\x';
  const BACKSLASH_SOURCE = 'C:\\\\temp\\\\x';
  const SECRET_ESCAPE_VALUE = 'S|P\\W';
  const SECRET_ESCAPE_SOURCE = 'S\\|P\\\\W';
  const TABLE_NOTE = [
    '| 名称 | 账号 | 备注 | 密码 | 链接 |',
    '| :--- | :--- | :--- | :--- | :--- |',
    '| GitHub | CELL-COPY-VALUE | ' + SPECIAL_SOURCE + ' | ' + SECRET_ESCAPE_SOURCE + ' | [官网](https://example.com) |',
    '| 裸链 | https://example.org/bare | ' + BACKSLASH_SOURCE + ' | P@ss-W0rd_*2026 |  |',
  ].join('\n');
  await plugin.saveNote('note-primary', TABLE_NOTE);
  view.render();

  let cellTable = findAll(view.contentEl, (el) => el.tagName === 'TABLE' && el.hasClass('xsv-md-table'))[0];
  ok(!!cellTable && cellTable.parent && cellTable.parent.hasClass('xsv-table-wrap'), '表格外层提供横向滚动容器');
  const heads = findAll(cellTable, (el) => el.tagName === 'TH');
  ok(heads.length === 5, '表头 5 列');
  ok(!heads.some((el) => el.hasClass('xsv-cell-copy')), '表头单元格不参与复制（无点击类）');
  let cells = findAll(cellTable, (el) => el.tagName === 'TD');
  ok(cells.length === 10, '两行各 5 个单元格');
  ok(cells.filter((el) => el.hasClass('xsv-cell-copy')).length === 9, '非空数据单元格都可点击复制');
  ok(String(textOf(cellTable)).indexOf('CELL-COPY-VALUE') >= 0, '明文列文本默认可见');
  ok(
    findAll(cellTable, (el) => el.hasClass('xsv-cell-secret')).length === 0,
    '默认全明文：名为「密码」的列也不遮挡'
  );
  ok(
    textOf(cellTable).indexOf(SECRET_ESCAPE_VALUE) >= 0,
    '密码列真实值默认直接显示'
  );
  ok(
    findAll(view.contentEl, (el) => el.hasClass('xsv-sensitive-note')).length === 0,
    '负向：默认不出现按密码处理说明行'
  );

  const cellByText = (needle) => cells.filter((el) => String(textOf(el)).indexOf(needle) >= 0)[0];
  const copyCell = cellByText('CELL-COPY-VALUE');
  clipboard = '';
  notices.length = 0;
  copyCell.click();
  await waitFor(() => clipboard === 'CELL-COPY-VALUE', '点击单元格复制');
  ok(clipboard === 'CELL-COPY-VALUE', '点击单元格复制其文本');
  await waitFor(() => notices.some((message) => message === '已复制'), '单元格复制提示');
  ok(notices.some((message) => message === '已复制'), '单元格复制给出轻量「已复制」提示');
  ok(plugin.clipboardTimer !== 0, '单元格复制沿用 30 秒自动清空定时器');

  // 特殊符号逐字一致：| * _ 反引号 {{}} <> & emoji 中文标点
  const specialCell = cellByText('P|*_');
  ok(!!specialCell && textOf(specialCell) === SPECIAL_VALUE, '特殊符号单元格渲染逐字一致');
  clipboard = '';
  specialCell.click();
  await waitFor(() => clipboard === SPECIAL_VALUE, '特殊符号复制');
  ok(clipboard === SPECIAL_VALUE, '特殊符号复制逐字一致');
  // \| 还原为 |，\\ 还原为 \，其它反斜杠保持原样
  const backslashCell = cellByText('C:\\temp');
  ok(!!backslashCell && textOf(backslashCell) === BACKSLASH_VALUE, '\\\\ 转义还原为单个反斜杠');
  clipboard = '';
  backslashCell.click();
  await waitFor(() => clipboard === BACKSLASH_VALUE, '反斜杠单元格复制');
  ok(clipboard === BACKSLASH_VALUE, '反斜杠单元格复制逐字一致');

  // 唯一触发条件：用户手动把「密码」标为密文；规则变更会重渲染，需要重新查询节点
  await plugin.saveColumnRules([{ name: '密码', mode: 'secret' }]);
  cellTable = findAll(view.contentEl, (el) => el.tagName === 'TABLE' && el.hasClass('xsv-md-table'))[0];
  cells = findAll(cellTable, (el) => el.tagName === 'TD');
  ok(
    findAll(cellTable, (el) => el.hasClass('xsv-cell-secret')).length === 2,
    '手动把「密码」标为密文后该列遮挡'
  );
  ok(
    textOf(findAll(view.contentEl, (el) => el.hasClass('xsv-sensitive-note'))[0]).indexOf('1 列') >= 0,
    '手动标记后表格下方说明 1 列按密码处理'
  );
  const secretCell = cells.filter((el) => el.hasClass('xsv-cell-secret'))[0];
  ok(String(textOf(secretCell)).trim().indexOf('••••••') === 0, '密文列默认显示掩码');
  ok(textOf(cellTable).indexOf(SECRET_ESCAPE_VALUE) < 0, '负向：密文真实值不在 DOM 文本中');
  const eyeButton = findAll(secretCell, (el) => el.tagName === 'BUTTON')[0];
  ok(!!eyeButton && String(eyeButton.textContent).indexOf('👁') >= 0, '密文列提供眼睛按钮');
  eyeButton.click();
  ok(textOf(secretCell).indexOf(SECRET_ESCAPE_VALUE) >= 0, '眼睛按钮临时显示真实值');
  eyeButton.click();
  ok(String(textOf(secretCell)).trim().indexOf('••••••') === 0, '再次点击眼睛回到掩码');
  clipboard = '';
  notices.length = 0;
  secretCell.click();
  await waitFor(() => clipboard === SECRET_ESCAPE_VALUE, '点击密文单元格复制真实值');
  ok(clipboard === SECRET_ESCAPE_VALUE, '密文单元格点击复制真实值（逐字一致）');
  await waitFor(() => notices.some((message) => message === '已复制'), '密文单元格复制提示');
  ok(notices.some((message) => message === '已复制'), '密文单元格复制给出「已复制」提示');

  // 链接单元格：交给系统浏览器，不复制
  await delay(30);
  clipboard = 'UNCHANGED-BEFORE-LINK';
  notices.length = 0;
  const openBefore = openCalls.length;
  cellByText('官网').click();
  await delay(20);
  ok(
    openCalls.length === openBefore + 1 && openCalls[openCalls.length - 1] === 'https://example.com',
    '链接单元格点击打开系统浏览器'
  );
  ok(clipboard === 'UNCHANGED-BEFORE-LINK', '负向：链接单元格不复制文本');
  ok(!notices.some((message) => message === '已复制'), '负向：链接单元格不弹复制提示');

  clipboard = 'UNCHANGED-BEFORE-BARE';
  cellByText('example.org').click();
  await delay(20);
  ok(openCalls[openCalls.length - 1] === 'https://example.org/bare', '裸 URL 单元格同样打开浏览器');
  ok(clipboard === 'UNCHANGED-BEFORE-BARE', '负向：裸 URL 单元格不复制文本');

  // 空单元格：不复制、不提示
  clipboard = 'UNCHANGED-BEFORE-EMPTY';
  notices.length = 0;
  const emptyCell = cells.filter((el) => !el.hasClass('xsv-cell-copy') && String(textOf(el)).trim() === '')[0];
  ok(!!emptyCell, '存在空单元格');
  emptyCell.click();
  await delay(20);
  ok(clipboard === 'UNCHANGED-BEFORE-EMPTY', '负向：空单元格点击不复制');
  ok(!notices.some((message) => message === '已复制'), '负向：空单元格点击不提示');

  // 遮罩/失焦：已临时显示的值立刻回到掩码态
  const liveSecretCell = findAll(view.contentEl, (el) => el.hasClass('xsv-cell-secret'))[0];
  findAll(liveSecretCell, (el) => el.tagName === 'BUTTON')[0].click();
  ok(textOf(liveSecretCell).indexOf(SECRET_ESCAPE_VALUE) >= 0, '遮罩前先临时显示（构造测试场景）');
  windowStub.fire('blur');
  ok(view.masked === true, '失焦立即遮罩');
  ok(textOf(view.contentEl).indexOf(SECRET_ESCAPE_VALUE) < 0, '负向：遮罩后 DOM 不残留已显示的密文');
  windowStub.fire('focus');
  ok(view.masked === false, '倒计时内返回解除遮罩');
  const secretCellAfter = findAll(view.contentEl, (el) => el.hasClass('xsv-cell-secret'))[0];
  ok(String(textOf(secretCellAfter)).trim().indexOf('••••••') === 0, '揭示态在遮罩时已复位为掩码');

  // 剪贴板不可用：明确提示，不静默
  const savedClipboardWrite = navigator.clipboard.writeText;
  navigator.clipboard.writeText = async () => {
    throw new Error('clipboard denied');
  };
  notices.length = 0;
  ok((await plugin.copySecret('CLIPBOARD-FAIL-PROBE')) === false, '复制失败时 copySecret 返回 false');
  await waitFor(() => notices.some((message) => message.indexOf('剪贴板') >= 0), '剪贴板失败给出明确提示');
  navigator.clipboard.writeText = savedClipboardWrite;
  clipboard = '';

  // 25) 引用语法取消后旧数据仍完整：entries 留在密文载荷，花括号按字面显示
  const cellRefs = findAll(view.contentEl, (el) => el.hasClass('xsv-ref'));
  ok(cellRefs.length === 0, '负向：笔记表格不再生成引用按钮');
  ok(plugin.entries.length === 3, 'entries 仍完整保留在内存/密文载荷');
  ok(
    textOf(view.contentEl).indexOf('{{}}') >= 0,
    '表格中的 {{}} 按字面文本显示'
  );

  // 26) 锁定后整页无明文（表格单元格文本 / 密文真实值 / 草稿 / 表格节点）
  view.noteEditing = true;
  view.noteDraft = 'CELL-DRAFT-MARKER';
  view.render();
  ok(String(textOf(view.contentEl)).indexOf('CELL-DRAFT-MARKER') >= 0, '锁定前草稿可见（构造测试场景）');
  plugin.lock();
  const lockedPageText = String(textOf(view.contentEl));
  ok(lockedPageText.indexOf('CELL-COPY-VALUE') < 0, '锁定后整页 DOM 不含表格单元格明文');
  ok(lockedPageText.indexOf(SECRET_ESCAPE_VALUE) < 0, '锁定后整页 DOM 不含密文列真实值');
  ok(lockedPageText.indexOf('P@ss-W0rd_*2026') < 0, '锁定后整页 DOM 不含特殊字符密码');
  ok(lockedPageText.indexOf('CELL-DRAFT-MARKER') < 0, '锁定后整页 DOM 不含编辑草稿');
  ok(!findAll(view.contentEl, (el) => el.tagName === 'TABLE').length, '锁定后表格节点被移除');
  view.render();
  ok(findAll(view.contentEl, (el) => el.hasClass('xsv-page-card')).length === 1, '锁定后整页回到居中的解锁卡片');

  ok((await plugin.unlock(MASTER)) === true, '重新解锁');
  view.render();
  ok(plugin.entries.length === 3, '界面下线后 entries 仍完整保存在密文载荷中');
  ok(String(textOf(view.contentEl)).indexOf('CELL-COPY-VALUE') >= 0, '重新解锁后笔记表格再次渲染');

  // 27) 列显示规则：默认空表全明文；只有手动标记才遮挡；增删改立即生效；清空需二次确认
  await plugin.saveColumnRules([]);
  view.render();
  ok(plugin.getColumnRules().length === 0, '默认规则为空（不做任何按列名推断）');
  ok(plugin.getColumnMode('密码') === 'plain', '默认全明文：名为「密码」的列也是明文');
  ok(plugin.getColumnMode('账号') === 'plain', '默认全明文：账号列按明文');
  ok(plugin.getColumnMode('token') === 'plain', '默认全明文：旧的 token 关键词不再触发遮挡');
  ok(plugin.getColumnMode('手机号') === 'plain', '未命中规则按明文');
  ok(
    findAll(view.contentEl, (el) => el.hasClass('xsv-cell-secret')).length === 0,
    '无规则时表格全部按明文渲染'
  );

  const dirtyRules = [
    '密码',
    ' token ',
    { name: '账号', mode: 'bogus' },
    { name: '密码', mode: 'plain' },
    { name: '   ', mode: 'secret' },
    null,
    { name: 'token', mode: 'secret' },
  ];
  await plugin.saveColumnRules(dirtyRules);
  const normalizedRules = plugin.getColumnRules();
  ok(normalizedRules.length === 3, '脏数据归一化：只保留 3 条合法规则');
  ok(
    normalizedRules.filter((rule) => rule.name === '密码')[0].mode === 'plain',
    '重复列名合并为一条，后出现的模式生效'
  );
  ok(
    normalizedRules.filter((rule) => rule.name === '账号')[0].mode === 'plain',
    '非法模式归一化为明文'
  );
  ok(
    normalizedRules.every((rule) => Object.keys(rule).length === 2),
    '规则只存 name 与 mode，不携带任何值'
  );

  // 自定义列名：精确匹配优先于包含匹配，改动立即重渲染
  await plugin.saveColumnRules([
    { name: '密码', mode: 'secret' },
    { name: '账号', mode: 'plain' },
  ]);
  ok((await plugin.addColumnRule('手机号', 'secret')).ok === true, '新增自定义密文列名成功');
  ok(plugin.getColumnMode('手机号') === 'secret', '自定义列名精确命中');
  const RULE_NOTE = [
    '| 名称 | 手机号 | 手机号（副） | 备注 |',
    '| --- | --- | --- | --- |',
    '| GitHub | 13800000000 | 13900000000 | 说明 |',
  ].join('\n');
  await plugin.saveNote('note-primary', RULE_NOTE);
  view.render();
  ok(
    findAll(view.contentEl, (el) => el.hasClass('xsv-cell-secret')).length === 2,
    '自定义密文列与包含匹配列都按密文渲染'
  );
  ok(plugin.getColumnMode('手机号（副）') === 'secret', '包含匹配同样按密文');
  await plugin.addColumnRule('手机号（副）', 'plain');
  ok(plugin.getColumnMode('手机号（副）') === 'plain', '精确匹配优先于包含匹配');
  ok(
    findAll(view.contentEl, (el) => el.hasClass('xsv-cell-secret')).length === 1,
    '规则改动立即重渲染当前笔记（无需重新解锁）'
  );
  const exactRuleIndex = plugin.getColumnRules().findIndex((rule) => rule.name === '手机号（副）');
  await plugin.deleteColumnRule(exactRuleIndex);
  ok(
    findAll(view.contentEl, (el) => el.hasClass('xsv-cell-secret')).length === 2,
    '删除规则后立即恢复包含匹配'
  );
  const phoneRuleIndex = plugin.getColumnRules().findIndex((rule) => rule.name === '手机号');
  await plugin.updateColumnRule(phoneRuleIndex, { mode: 'plain' });
  ok(plugin.getColumnMode('手机号') === 'plain', '切换明文/密文立即生效');
  ok(
    findAll(view.contentEl, (el) => el.hasClass('xsv-cell-secret')).length === 0,
    '手机号改为明文后，包含该规则名的列同样按明文'
  );
  await plugin.updateColumnRule(phoneRuleIndex, { mode: 'secret' });

  // 空列名拒绝、重复合并、行数上限
  notices.length = 0;
  const emptyRule = await plugin.addColumnRule('   ', 'secret');
  ok(emptyRule.ok === false, '负向：空列名不保存');
  ok(notices.some((message) => message.indexOf('不能为空') >= 0), '空列名给出提示');
  const beforeMerge = plugin.getColumnRules().length;
  ok((await plugin.addColumnRule('手机号', 'plain')).merged === true, '重复列名合并为一条');
  ok(plugin.getColumnRules().length === beforeMerge, '重复列名不新增行');
  ok(plugin.getColumnMode('手机号') === 'plain', '重复合并时采用新模式');

  const fullRules = Array.from({ length: 50 }, (unused, index) => ({
    name: '列-' + index,
    mode: 'plain',
  }));
  await plugin.saveColumnRules(fullRules);
  notices.length = 0;
  const overflowRule = await plugin.addColumnRule('溢出', 'secret');
  ok(overflowRule.ok === false && overflowRule.reason === 'limit', '负向：超过 50 行拒绝新增');
  ok(notices.some((message) => message.indexOf('最多 50 条') >= 0), '行数上限给出提示');

  // 清空全部规则：二次确认，取消不清空，确认后回到全明文（默认规则为空表）
  const restoreModal = plugin.requestRestoreDefaultColumnRules();
  ok(!!restoreModal && restoreModal.isOpen === true, '清空全部规则弹出二次确认');
  ok(
    textOf(restoreModal.contentEl).indexOf('所有列都按明文显示') >= 0,
    '二次确认说明清空后所有列按明文显示'
  );
  findButton(restoreModal.contentEl, '取消').click();
  ok(plugin.getColumnRules().length === 50, '取消清空后自定义规则保持不变');
  const confirmModal = plugin.requestRestoreDefaultColumnRules();
  findButton(confirmModal.contentEl, '清空全部规则（全明文）').click();
  await waitFor(() => plugin.getColumnRules().length === 0, '确认清空全部规则');
  ok(plugin.getColumnRules().length === 0, '确认后规则表为空（全明文）');
  ok(plugin.getColumnMode('密码') === 'plain', '清空后名为密码的列同样按明文');
  await waitFor(
    () => notices.some((message) => message.indexOf('已清空全部规则') >= 0),
    '清空规则提示'
  );
  ok(notices.some((message) => message.indexOf('已清空全部规则') >= 0), '清空规则给出提示');

  // 设置页规则表 UI：下拉控件、动态行、添加后聚焦、切换即时生效、删除、空列名提示
  const ruleHost = makeEl('div');
  plugin.settingTab.renderColumnRulesEditor({ settingEl: ruleHost });
  ok(
    findAll(ruleHost, (el) => el.hasClass('xsv-rule-row')).length === 0,
    '规则表默认渲染 0 行（全明文）'
  );
  const rowsNow = () => findAll(ruleHost, (el) => el.hasClass('xsv-rule-row'));
  const rowInput = (row) => findAll(row, (el) => el.tagName === 'INPUT')[0];
  const rowSelect = (row) => findAll(row, (el) => el.tagName === 'SELECT')[0];

  findButton(ruleHost, '添加自定义列名').click();
  let rows = rowsNow();
  ok(rows.length === 1, '添加后出现一行');
  const firstRow = rows[0];
  ok(!!rowInput(firstRow) && rowInput(firstRow).value === '', '新增行显示空列名输入框');
  const draftSelect = rowSelect(firstRow);
  ok(!!draftSelect && draftSelect.hasClass('xsv-rule-select'), '每行提供下拉选择控件');
  ok(draftSelect.value === 'plain', '下拉默认值为明文');
  ok(
    findAll(draftSelect, (el) => el.tagName === 'OPTION').length === 2,
    '下拉固定两个选项'
  );
  ok(
    findAll(draftSelect, (el) => el.tagName === 'OPTION').some((el) => el.value === 'secret') &&
      findAll(draftSelect, (el) => el.tagName === 'OPTION').some((el) => el.value === 'plain'),
    '下拉选项为明文 / 密文'
  );
  const styleSource = fs.readFileSync(path.join(__dirname, '..', 'styles.css'), 'utf8');
  ok(
    styleSource.indexOf('.xsv-rule-row .xsv-rule-select') >= 0 &&
      styleSource.indexOf('width: 96px') >= 0,
    '下拉固定窄宽（96px），窄屏下不被挤压隐藏'
  );
  draftSelect.value = 'secret';
  draftSelect.fire('change');
  ok(plugin.getColumnRules().length === 0, '草稿行切换模式不落盘');
  rowInput(firstRow).value = '手机号';
  rowInput(firstRow).fire('change');
  await waitFor(() => plugin.getColumnMode('手机号') === 'secret', '设置页新增规则保存');
  await delay(30);
  ok(plugin.getColumnMode('手机号') === 'secret', '设置页新增规则立即生效');
  rows = rowsNow();
  ok(rows.length === 1, '新增规则后行数增加');
  ok(rowSelect(rows[0]).value === 'secret', '重绘后下拉值不丢失');

  // 连续添加第二行：两行各自独立
  findButton(ruleHost, '添加自定义列名').click();
  rows = rowsNow();
  ok(rows.length === 2, '可重复添加多行');
  ok(rowSelect(rows[1]).value === 'plain', '第二行下拉默认明文，与第一行独立');
  rowInput(rows[1]).value = '邮箱';
  rowInput(rows[1]).fire('change');
  await waitFor(() => plugin.getColumnRules().length === 2, '第二行新增保存');
  await delay(30);
  rows = rowsNow();
  ok(plugin.getColumnRules().length === 2, '两行规则各自独立落盘');
  ok(
    rowInput(rows[0]).value === '手机号' && rowSelect(rows[0]).value === 'secret' &&
      rowInput(rows[1]).value === '邮箱' && rowSelect(rows[1]).value === 'plain',
    '两行的列名与模式互不影响'
  );

  // 下拉切换：立即生效并重渲染当前笔记
  rowSelect(rows[0]).value = 'plain';
  rowSelect(rows[0]).fire('change');
  await waitFor(() => plugin.getColumnMode('手机号') === 'plain', '设置页下拉切换为明文');
  await delay(30);
  rows = rowsNow();
  ok(plugin.getColumnMode('手机号') === 'plain', '下拉切换模式立即生效');
  ok(rowSelect(rows[0]).value === 'plain', '切换后下拉值更新');
  ok(
    rowInput(rows[1]).value === '邮箱' && rowSelect(rows[1]).value === 'plain',
    '切换第一行不影响第二行'
  );
  rowSelect(rows[0]).value = 'secret';
  rowSelect(rows[0]).fire('change');
  await waitFor(() => plugin.getColumnMode('手机号') === 'secret', '设置页下拉切回密文');
  await delay(30);
  ok(plugin.getColumnMode('手机号') === 'secret', '下拉可来回切换');
  ok(
    findAll(view.contentEl, (el) => el.hasClass('xsv-cell-secret')).length === 2,
    '下拉切换后当前笔记表格即时重渲染'
  );

  // 删除行后其余行值保持
  rows = rowsNow();
  findButton(rows[0], '×').click();
  await waitFor(() => plugin.getColumnRules().length === 1, '设置页删除规则');
  await delay(30);
  rows = rowsNow();
  ok(plugin.getColumnMode('手机号') === 'plain', '删除后自定义规则失效');
  ok(rows.length === 1, '删除一行后剩余一行');
  ok(
    rowInput(rows[0]).value === '邮箱' && rowSelect(rows[0]).value === 'plain',
    '删除后其余行的列名与下拉值保持'
  );
  rowSelect(rows[0]).value = 'secret';
  rowSelect(rows[0]).fire('change');
  await waitFor(() => plugin.getColumnMode('邮箱') === 'secret', '剩余行切换为密文');
  await delay(30);

  // 空列名拒绝：新增空行不输入直接提交
  findButton(ruleHost, '添加自定义列名').click();
  rows = rowsNow();
  notices.length = 0;
  rowInput(rows[rows.length - 1]).fire('change');
  ok(notices.some((message) => message.indexOf('不能为空') >= 0), '设置页空列名给出提示');
  ok(plugin.getColumnRules().length === 1, '设置页空列名不落盘');
  rows = rowsNow();
  ok(rows.length === 1, '空列名草稿被丢弃');

  // 旧 data.json 已有自定义规则：升级后保留并继续生效；未标记的列仍按明文
  const settingsBackup = JSON.parse(JSON.stringify(plugin.settings));
  const originalLoadData = plugin.loadData;
  plugin.loadData = async () => ({
    language: 'zh',
    vaultPath: VAULT_PATH,
    columnRules: [
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
    ],
  });
  await plugin.loadSettings();
  ok(plugin.getColumnRules().length === 0, '旧版 0.3.1 预置 12 条规则升级后视为未自定义并清空');
  ok(plugin.getColumnMode('密码') === 'plain', '升级后名为密码的列默认明文');
  plugin.loadData = async () => ({
    language: 'zh',
    vaultPath: VAULT_PATH,
    columnRules: [
      { name: '手机号', mode: 'secret' },
      { name: '账号', mode: 'plain' },
    ],
    obsoleteField: 'legacy',
  });
  await plugin.loadSettings();
  ok(plugin.getColumnMode('手机号') === 'secret', '旧 data.json 的自定义规则升级后仍生效');
  ok(plugin.getColumnMode('密码') === 'plain', '旧 data.json 未标记的密码列仍按明文');
  ok(plugin.getColumnRules().length === 2, '旧 data.json 的规则表归一化后保留 2 条');
  plugin.loadData = originalLoadData;
  plugin.settings = settingsBackup;

  // data.json 只存 name/mode，不含任何密码或笔记内容
  await plugin.saveSettings();
  const rulesDump = JSON.stringify(plugin.__savedData);
  ok(
    rulesDump.indexOf('columnRules') >= 0 &&
      rulesDump.indexOf('"name":"邮箱"') >= 0 &&
      rulesDump.indexOf('"mode":"secret"') >= 0,
    'data.json 只持久化 name/mode 形式的列显示规则'
  );
  ok(
    rulesDump.indexOf(SECRET_ONE) < 0 &&
      rulesDump.indexOf(SECRET_TWO) < 0 &&
      rulesDump.indexOf(MASTER) < 0 &&
      rulesDump.indexOf('CELL-COPY-VALUE') < 0,
    '负向：data.json 不含密码、主密码或笔记内容'
  );

  // 28) i18n 占位符：下拉文案、全量词条扫描与调用点审计
  const flattenDefs = (defs) => {
    const out = [];
    for (const def of defs) {
      if (Array.isArray(def.items)) out.push(...flattenDefs(def.items));
      else out.push(def);
    }
    return out;
  };
  const readBgLockOptions = () => {
    const defs = flattenDefs(plugin.settingTab.getSettingDefinitions());
    const def = defs.filter((item) => item.name === plugin.t('setting_bg_lock'))[0];
    ok(!!def && typeof def.render === 'function', '找到「失焦锁定倒计时」设置项');
    const options = [];
    let selected = null;
    let onChange = null;
    const dropdown = {
      addOption(value, label) {
        options.push({ value, label });
        return this;
      },
      setValue(value) {
        selected = value;
        return this;
      },
      onChange(fn) {
        onChange = fn;
        return this;
      },
    };
    def.render({ addDropdown: (callback) => callback(dropdown) });
    return { options, selected, onChange };
  };

  plugin.settings.language = 'zh';
  let bgOptions = readBgLockOptions();
  ok(
    bgOptions.options.map((item) => item.label).join('|') ===
      '立即（严格）|5 秒|10 秒|30 秒|60 秒|120 秒',
    '失焦倒计时下拉文案精确匹配（中文）'
  );
  ok(bgOptions.selected === '30', '失焦倒计时下拉默认选中 30 秒');
  ok(
    bgOptions.options.every((item) => !/[{}]/.test(item.label)),
    '中文下拉 6 项均无未替换的 { 占位符'
  );
  bgOptions.onChange('10');
  await waitFor(() => plugin.settings.backgroundLockSeconds === 10, '切换倒计时为 10 秒');
  bgOptions = readBgLockOptions();
  ok(bgOptions.selected === '10', '切换后下拉仍显示 10 秒');
  ok(
    bgOptions.options.map((item) => item.label).indexOf('10 秒') >= 0 &&
      bgOptions.options.map((item) => item.label).indexOf('10 seconds') < 0,
    '切换后文案仍正确'
  );

  plugin.settings.language = 'en';
  bgOptions = readBgLockOptions();
  ok(
    bgOptions.options.map((item) => item.label).join('|') ===
      'Immediate (strict)|5 seconds|10 seconds|30 seconds|60 seconds|120 seconds',
    '失焦倒计时下拉文案精确匹配（英文）'
  );
  ok(
    bgOptions.options.every((item) => !/[{}]/.test(item.label)),
    '英文下拉 6 项均无未替换的 { 占位符'
  );
  plugin.settings.language = 'zh';
  plugin.settings.backgroundLockSeconds = 10;
  await plugin.saveSettings();
  plugin.settings.backgroundLockSeconds = 30;
  await plugin.saveSettings();

  // 全量词条：自动为每个占位符提供参数，确保两语言下都不残留 {xxx}
  const allKeys = plugin.listI18nKeys();
  ok(allKeys.length >= 120, 'i18n 词条覆盖中英两语言');
  for (const lang of ['zh', 'en']) {
    plugin.settings.language = lang;
    const leftovers = [];
    for (const key of allKeys) {
      const template = plugin.t(key);
      const vars = {};
      for (const token of template.match(/\{([A-Za-z][A-Za-z0-9_]*)\}/g) || []) {
        vars[token.slice(1, -1)] = '填充值';
      }
      const filled = plugin.t(key, vars);
      if (/[{}]/.test(filled)) leftovers.push(key + '=' + filled);
    }
    ok(leftovers.length === 0, `${lang} 语言下全部 i18n 占位符均已替换` + (leftovers.length ? '：' + leftovers.join(' | ') : ''));
  }

  // 调用点审计：含占位符的词条不允许以 t('key') 无参形式调用
  plugin.settings.language = 'zh';
  const placeholderKeys = new Set(
    allKeys.filter((key) => /\{[A-Za-z][A-Za-z0-9_]*\}/.test(plugin.t(key)))
  );
  ok(placeholderKeys.size >= 5, '识别出多个含占位符的词条');
  const callSiteSource = fs.readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8');
  const noArgCall = /(?:this\.plugin\.t|this\.t|plugin\.t|\bt)\(\s*'([A-Za-z0-9_]+)'\s*\)/g;
  const missingVars = new Set();
  let callMatch;
  while ((callMatch = noArgCall.exec(callSiteSource))) {
    if (placeholderKeys.has(callMatch[1])) missingVars.add(callMatch[1]);
  }
  ok(
    missingVars.size === 0,
    '所有含占位符的 t() 调用都传入参数' + (missingVars.size ? '：' + Array.from(missingVars).join(',') : '')
  );

  // 逐条精确校验常见占位符文案（中文）
  plugin.settings.language = 'zh';
  const zhCases = [
    ['setting_bg_lock_seconds', { n: 5 }, '5 秒'],
    ['notice_copied', { seconds: 30 }, '已复制，30 秒后自动清空剪贴板。'],
    ['mask_countdown', { seconds: 10 }, '将在 10 秒后锁定'],
    ['err_unlock_backoff', { seconds: 15 }, '尝试次数过多，请在 15 秒后重试。'],
    ['readonly_copy_path', { path: '/vault.json' }, '当前文件：/vault.json'],
    ['conflict_banner', { path: '/copy.json' }, '/copy.json'],
  ];
  for (const [key, vars, expected] of zhCases) {
    const text = plugin.t(key, vars);
    ok(text.indexOf(expected) >= 0 && !/[{}]/.test(text), '占位符替换正确：' + key);
  }
  const sensitiveText = plugin.t('notice_sensitive_columns', { count: 2 });
  ok(
    sensitiveText.indexOf('本表 2 列') >= 0 && !/[{}]/.test(sensitiveText),
    '占位符替换正确：notice_sensitive_columns'
  );
  plugin.settings.language = 'en';
  ok(
    plugin.t('setting_bg_lock_seconds', { n: 5 }).indexOf('5 seconds') === 0 &&
      !/[{}]/.test(plugin.t('setting_bg_lock_seconds', { n: 5 })),
    '英文占位符替换正确：setting_bg_lock_seconds'
  );
  plugin.settings.backgroundLockSeconds = 30;
  plugin.settings.language = 'zh';
  await plugin.saveSettings();

  plugin.lock();
  console.log('CREATE_MS=' + createMs + '  UNLOCK_MS=' + unlockMs);
  console.log('ASSERTIONS=' + assertions + '  FAILURES=' + failures.length);
  if (failures.length) {
    console.error('FAILED:');
    for (const failure of failures) console.error(' - ' + failure);
    process.exit(1);
  }
  console.log('E2E_ALL_PASS');
  process.exit(0);
})().catch((error) => {
  console.error('E2E_FATAL', error);
  process.exit(1);
});
