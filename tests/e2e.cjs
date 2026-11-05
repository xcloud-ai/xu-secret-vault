/* XU Secret Vault — e2e / 安全负向测试（Node 原生 WebCrypto + Obsidian 桩） */
'use strict';

const fs = require('fs');
const path = require('path');
const Module = require('module');
const { webcrypto } = require('crypto');

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
let writeTransform = null;
let activePlugin = null;

const app = {
  vault: {
    adapter: {
      exists: async (filePath) => fileStore.has(filePath) || createdDirs.has(filePath),
      read: async (filePath) => {
        if (!fileStore.has(filePath)) throw new Error('file not found: ' + filePath);
        return fileStore.get(filePath);
      },
      write: async (filePath, text) => {
        const finalText = writeTransform ? writeTransform(text) : text;
        fileStore.set(filePath, finalText);
      },
      mkdir: async (dirPath) => {
        createdDirs.add(dirPath);
      },
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
      readText: async () => clipboard,
    },
  },
  configurable: true,
  writable: true,
});

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
    version: '0.1.0',
    minAppVersion: '1.13.0',
  });
  activePlugin = plugin;
  plugin.settings.vaultPath = VAULT_PATH;
  await plugin.onload();

  ok(plugin.cryptoApi !== null, 'WebCrypto 探测可用');

  // 1) 首次使用 UI：创建保险库
  const leaf = await plugin.openVaultView();
  const view = leaf.view;
  await view.onOpen();
  await waitFor(() => view.plugin.vaultExists !== null, '检测保险库状态');
  ok(
    String(textOf(view.contentEl)).indexOf('创建主密码') >= 0,
    '首次使用显示创建主密码界面'
  );

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
  await waitFor(() => plugin.isUnlocked(), '创建保险库完成');
  const createMs = Date.now() - createStart;

  ok(fileStore.has(VAULT_PATH), '创建后生成密文文件 ' + VAULT_PATH);
  ok(plugin.isUnlocked(), '创建后自动解锁');
  ok(plugin.sessionKey.extractable === false, '会话密钥 non-extractable');
  ok(plugin.sessionSalt.length === 16, '盐为 16 字节');
  ok(plugin.entries.length === 0, '新保险库条目为空');

  const env0 = JSON.parse(fileStore.get(VAULT_PATH));
  ok(env0.formatVersion === 1, '信封 formatVersion=1');
  ok(env0.kdf.algo === 'PBKDF2-SHA512', 'KDF 算法记录为 PBKDF2-SHA512');
  ok(Number(env0.kdf.iterations) === 600000, 'KDF 迭代数记录为 600000');
  ok(Buffer.from(env0.kdf.salt, 'base64').length === 16, '信封盐为 16 字节');
  ok(Buffer.from(env0.cipher.iv, 'base64').length === 12, '信封 IV 为 12 字节');
  ok(env0.cipher.algo === 'AES-256-GCM', '加密算法记录为 AES-256-GCM');
  ok(!('entries' in env0), '信封中不存在明文 entries 字段');

  // 2) 通过 UI 新增条目
  const addButton = findButton(view.contentEl, '新增');
  ok(!!addButton, '找到新增按钮');
  addButton.click();
  const addModal = Array.from(plugin.openModals)[0];
  ok(!!addModal, '新增弹窗已打开');
  const modalInputs = findAll(addModal.contentEl, (el) => el.tagName === 'INPUT' && el.type === 'text');
  const modalTextareas = findAll(addModal.contentEl, (el) => el.tagName === 'TEXTAREA');
  ok(modalInputs.length === 2 && modalTextareas.length === 2, '弹窗字段齐全（名称/标签/内容/备注）');
  modalInputs[0].value = 'Alpha';
  modalInputs[1].value = 'work, cloud';
  modalTextareas[0].value = SECRET_ONE;
  modalTextareas[1].value = 'primary credential';
  const saveButton = findButton(addModal.contentEl, '保存');
  saveButton.click();
  await waitFor(() => !addModal.isOpen && plugin.entries.length === 1, '新增条目落盘');

  ok(plugin.entries[0].name === 'Alpha', '条目名称已保存');
  ok(plugin.entries[0].content === SECRET_ONE, '条目内容已保存在内存');
  ok(plugin.entries[0].tags.join(',') === 'work,cloud', '标签去重并保存');
  const env1 = JSON.parse(fileStore.get(VAULT_PATH));
  ok(env1.cipher.iv !== env0.cipher.iv, '新增写盘生成了新的 IV');
  ok(env1.kdf.salt === env0.kdf.salt, '同一保险库盐保持不变');

  // 3) 列表中默认不显示明文，点击「显示」后才出现
  ok(String(textOf(view.contentEl)).indexOf(SECRET_ONE) < 0, '列表中默认隐藏明文');
  const revealButton = findButton(view.contentEl, '显示');
  ok(!!revealButton, '找到显示按钮');
  revealButton.click();
  ok(String(textOf(view.contentEl)).indexOf(SECRET_ONE) >= 0, '点击显示后明文出现在界面');

  // 4) 复制到剪贴板
  const copyButton = findButton(view.contentEl, '复制');
  copyButton.click();
  await waitFor(() => clipboard === SECRET_ONE, '复制到剪贴板');
  ok(clipboard === SECRET_ONE, '复制动作写入剪贴板');

  // 5) UI 编辑（内容变化）
  const editButton = findButton(view.contentEl, '编辑');
  editButton.click();
  const editModal = Array.from(plugin.openModals)[0];
  ok(!!editModal && String(textOf(editModal.contentEl)).indexOf(SECRET_ONE) >= 0, '编辑弹窗载入原明文');
  const editTextareas = findAll(editModal.contentEl, (el) => el.tagName === 'TEXTAREA');
  editTextareas[0].value = SECRET_TWO;
  findButton(editModal.contentEl, '保存').click();
  await waitFor(() => !editModal.isOpen, '编辑保存完成');
  ok(plugin.entries[0].content === SECRET_TWO, '编辑后的内容已更新');
  const env2 = JSON.parse(fileStore.get(VAULT_PATH));
  ok(env2.cipher.iv !== env1.cipher.iv, '编辑写盘生成了新的 IV');
  ok(String(fileStore.get(VAULT_PATH)).indexOf(SECRET_TWO) < 0, '负向：密文 blob 不含条目明文（编辑后）');
  ok(String(fileStore.get(VAULT_PATH)).indexOf(SECRET_ONE) < 0, '负向：密文 blob 不含旧明文');

  // 6) 锁定：同步清屏、关闭 Modal、清剪贴板、丢弃密钥
  if (String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0) {
    findButton(view.contentEl, '显示').click();
  }
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) >= 0, '锁定前明文可见（构造测试场景）');

  findButton(view.contentEl, '编辑').click();
  const openModal = Array.from(plugin.openModals)[0];
  ok(!!openModal && String(textOf(openModal.contentEl)).indexOf(SECRET_TWO) >= 0, '锁定前编辑弹窗含明文');

  plugin.lock();
  ok(plugin.sessionKey === null, '锁定后 CryptoKey 已丢弃');
  ok(plugin.entries.length === 0, '锁定后内存条目集合已清空');
  ok(plugin.openModals.size === 0 && openModal.isOpen === false, '锁定关闭所有编辑弹窗');
  ok(String(textOf(openModal.contentEl)).indexOf(SECRET_TWO) < 0, '锁定后弹窗 DOM 不含明文');
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0, '负向：锁定后面板 DOM 不含明文');
  await waitFor(() => clipboard === '', '锁定后清空剪贴板');
  ok(clipboard === '', '锁定后剪贴板已清空');

  // 7) 信封头降级攻击
  const goodEnvelopeText = fileStore.get(VAULT_PATH);
  const tampered = JSON.parse(goodEnvelopeText);
  tampered.kdf.iterations = 1;
  fileStore.set(VAULT_PATH, JSON.stringify(tampered, null, 2));
  await rejects(plugin.unlock(MASTER), '格式无效', '负向：篡改迭代数被拒绝');
  fileStore.set(VAULT_PATH, goodEnvelopeText);

  const saltTampered = JSON.parse(goodEnvelopeText);
  saltTampered.kdf.salt = Buffer.from(
    webcrypto.getRandomValues(new Uint8Array(16))
  ).toString('base64');
  fileStore.set(VAULT_PATH, JSON.stringify(saltTampered, null, 2));
  const saltUnlock = await plugin.unlock(MASTER);
  ok(saltUnlock === false, '负向：替换盐后无法解密');
  fileStore.set(VAULT_PATH, goodEnvelopeText);

  // 8) 错误主密码 / 正确解锁
  const wrongUnlock = await plugin.unlock('wrong-master-password');
  ok(wrongUnlock === false, '负向：错误主密码无法解锁');
  ok(!plugin.isUnlocked(), '错误主密码后仍处于锁定态');

  const unlockStart = Date.now();
  const unlocked = await plugin.unlock(MASTER);
  const unlockMs = Date.now() - unlockStart;
  ok(unlocked === true, '正确主密码重新解锁成功');
  ok(plugin.entries.length === 1, '重新解锁恢复条目数量');
  ok(plugin.entries[0].content === SECRET_TWO, '重新解锁后内容仍正确');
  ok(plugin.sessionKey.extractable === false, '重新解锁的密钥仍 non-extractable');

  // 9) 自动锁定同样清屏
  view.render();
  findButton(view.contentEl, '显示').click();
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) >= 0, '自动锁定前明文可见');
  plugin.idleDeadline = Date.now() - 1;
  plugin.checkAutoLock();
  ok(plugin.sessionKey === null, '自动锁定丢弃 CryptoKey');
  ok(plugin.entries.length === 0, '自动锁定清空内存条目');
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0, '负向：自动锁定后面板 DOM 不含明文');
  ok(notices.some((message) => message.indexOf('自动锁定') >= 0), '自动锁定给出用户提示');

  // 10) 删除（UI 二次确认），再次解锁确认已删除
  await plugin.unlock(MASTER);
  view.render();
  findButton(view.contentEl, '删除').click();
  const deleteModal = Array.from(plugin.openModals)[0];
  ok(!!deleteModal, '删除确认弹窗已打开');
  findButton(deleteModal.contentEl, '确认删除').click();
  await waitFor(() => plugin.entries.length === 0, '删除条目完成');
  ok(plugin.entries.length === 0, '条目已删除');
  const env3Text = fileStore.get(VAULT_PATH);
  const env3 = JSON.parse(env3Text);
  ok(String(env3Text).indexOf(SECRET_TWO) < 0, '负向：删除后密文 blob 不含明文');

  plugin.lock();
  const unlockEmpty = await plugin.unlock(MASTER);
  ok(unlockEmpty === true && plugin.entries.length === 0, '重新解锁后确认条目已删除');

  // 11) 明文不进入任何信封历史
  for (const [label, text] of [
    ['创建', JSON.stringify(env0)],
    ['新增', JSON.stringify(env1)],
    ['编辑', JSON.stringify(env2)],
    ['删除', env3Text],
  ]) {
    ok(
      text.indexOf(SECRET_ONE) < 0 &&
        text.indexOf(SECRET_TWO) < 0 &&
        text.indexOf(SECRET_THREE) < 0 &&
        text.indexOf(MASTER) < 0,
      '负向：' + label + '后的密文不含任何明文或主密码'
    );
  }

  // 12) 写盘读回校验：磁盘不一致时拒绝并保持旧数据
  const beforeFailure = fileStore.get(VAULT_PATH);
  writeTransform = (text) => text.slice(0, Math.max(0, text.length - 32));
  await rejects(
    plugin.addEntry({ name: 'Gamma', type: 'note', content: SECRET_THREE }),
    '写入校验失败',
    '负向：写盘读回不一致时拒绝提交'
  );
  ok(plugin.entries.length === 0, '写盘失败后内存数据未更新');
  writeTransform = null;
  fileStore.set(VAULT_PATH, beforeFailure);

  // 13) 主密码与明文不进入设置持久化
  await plugin.saveSettings();
  const settingsText = JSON.stringify(plugin.settings);
  ok(settingsText.indexOf(MASTER) < 0, '设置对象不含主密码');
  ok(settingsText.indexOf(SECRET_ONE) < 0 && settingsText.indexOf(SECRET_TWO) < 0, '设置对象不含条目明文');
  const savedText = JSON.stringify(plugin.__savedData);
  ok(savedText.indexOf(MASTER) < 0 && savedText.indexOf(SECRET_TWO) < 0, 'data.json 写入记录不含主密码或明文');

  // 14) crypto.subtle 不可用时明确报错
  plugin.lock();
  const savedCrypto = plugin.cryptoApi;
  plugin.cryptoApi = null;
  view.render();
  ok(String(textOf(view.contentEl)).indexOf('WebCrypto') >= 0, '无 WebCrypto 时界面明确提示');
  plugin.cryptoApi = savedCrypto;
  view.render();

  // 收尾断言：命令与视图存在
  ok(plugin.__commands.length === 3, '注册了 3 条命令');
  ok(plugin.__viewFactories['xu-secret-vault-view'] !== undefined, '注册了侧边栏视图');
  ok(plugin.__settingTab !== null, '注册了设置页');

  console.log('');
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
