import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

await import("../starPromptPolicy.js");

const policyApi = globalThis.AISGStarPromptPolicy;
const [ipcxHtml, appSource, ipcxAppSource] = await Promise.all([
  readFile(new URL("../index-ipcx.html", import.meta.url), "utf8"),
  readFile(new URL("../app.js", import.meta.url), "utf8"),
  readFile(new URL("../ipcxApp.js", import.meta.url), "utf8"),
]);

function createStorage(initial = {}) {
  const values = new Map(Object.entries(initial));
  return {
    getItem(key) {
      return values.has(key) ? values.get(key) : null;
    },
    removeItem(key) {
      values.delete(key);
    },
    setItem(key, value) {
      values.set(key, String(value));
    },
  };
}

function createScope({ cookie = "", protocol = "https:", storage = {} } = {}) {
  let cookieValue = cookie;
  const cookieWrites = [];
  const document = {};
  Object.defineProperty(document, "cookie", {
    get() {
      return cookieValue;
    },
    set(value) {
      cookieWrites.push(value);
      const pair = value.split(";", 1)[0];
      const [name] = pair.split("=", 1);
      const remaining = cookieValue
        .split(/;\s*/)
        .filter(Boolean)
        .filter((entry) => !entry.startsWith(`${name}=`));
      cookieValue = [pair, ...remaining].join("; ");
    },
  });
  return {
    scope: {
      document,
      localStorage: createStorage(storage),
      location: { protocol },
    },
    cookieWrites,
  };
}

test("Star 提示策略固定为 12 小时，并把截止时间同时写入 Cookie 与本地存储", () => {
  assert.ok(policyApi, "应暴露 AISGStarPromptPolicy");
  assert.equal(policyApi.TTL_MS, 12 * 60 * 60 * 1000);
  const now = 1_800_000_000_000;
  const { scope, cookieWrites } = createScope();
  const policy = policyApi.create({ scope, now: () => now });

  const until = policy.remember();

  assert.equal(until, now + policyApi.TTL_MS);
  assert.equal(scope.localStorage.getItem(policyApi.STORAGE_KEY), String(until));
  assert.match(cookieWrites.at(-1), /Max-Age=43200/);
  assert.match(cookieWrites.at(-1), /SameSite=Lax/);
  assert.match(cookieWrites.at(-1), /Secure/);
  assert.equal(policy.shouldPrompt(), false);
});

test("Star 提示在截止时间到达后恢复，并接受 file 协议的本地存储兜底", () => {
  let now = 1_800_000_000_000;
  const until = now + policyApi.TTL_MS;
  const { scope, cookieWrites } = createScope({
    protocol: "file:",
    storage: { [policyApi.STORAGE_KEY]: String(until) },
  });
  const policy = policyApi.create({ scope, now: () => now });

  assert.equal(policy.shouldPrompt(), false);
  now = until + 1;
  assert.equal(policy.shouldPrompt(), true);
  policy.remember();
  assert.doesNotMatch(cookieWrites.at(-1), /Secure/);
});

test("Star 提示优先采用仍有效的较晚截止时间，并忽略无效值", () => {
  const now = 1_800_000_000_000;
  const cookieUntil = now + 10_000;
  const storageUntil = now + 20_000;
  const { scope } = createScope({
    cookie: `unrelated=1; ${policyApi.COOKIE_NAME}=${encodeURIComponent(String(cookieUntil))}`,
    storage: { [policyApi.STORAGE_KEY]: String(storageUntil) },
  });
  const policy = policyApi.create({ scope, now: () => now });

  assert.equal(policy.suppressedUntil(), storageUntil);
  assert.equal(policyApi.normalizeUntil("not-a-number", now), 0);
  assert.equal(policyApi.normalizeUntil(String(now), now), 0);
  assert.equal(policyApi.normalizeUntil(String(cookieUntil), now), cookieUntil);
});

test("存储不可用时策略安全降级为提示，不阻断检测", () => {
  const now = 1_800_000_000_000;
  const scope = { location: { protocol: "http:" } };
  Object.defineProperty(scope, "document", {
    get() {
      throw new Error("cookie blocked");
    },
  });
  Object.defineProperty(scope, "localStorage", {
    get() {
      throw new Error("storage blocked");
    },
  });
  const policy = policyApi.create({ scope, now: () => now });

  assert.equal(policy.shouldPrompt(), true);
  assert.equal(policy.remember(), now + policyApi.TTL_MS);
  assert.equal(policyApi.create({ scope: {} }).shouldPrompt(), true);
});

test("IPCX 摘要与页面统一使用准确的不一致措辞和 AI 排查提示", () => {
  assert.match(ipcxAppSource, /"AI Signal Guard · 通用数字环境检测",\s*PROJECT_URL/);
  assert.match(ipcxAppSource, /https:\/\/betaer\.github\.io\/AiSignalGuard\//);
  assert.match(ipcxAppSource, /时区不一致/);
  assert.match(ipcxAppSource, /语言不一致/);
  assert.doesNotMatch(ipcxHtml + ipcxAppSource, /时区待核对|语言待核对/);
  assert.match(ipcxAppSource, /已复制，请发给AI协助排查解决问题 👨‍🔧/);
});

test("正式页与 IPCX 都把 Star 主按钮接入待处理检测，并让重测进入 Loading", () => {
  assert.match(appSource, /import "\.\/starPromptPolicy\.js"/);
  assert.match(appSource, /starSupportGithub\.addEventListener\("click", continueStarSupport\)/);
  assert.match(appSource, /function requestRetest\(\)/);
  assert.match(appSource, /setAppStage\("running"\)/);
  assert.match(ipcxHtml, /id="star-support-dialog"/);
  assert.match(ipcxHtml, /id="star-support-github"/);
  assert.match(ipcxHtml, /id="recheck-loading"/);
  assert.match(ipcxAppSource, /function requestRecheck\(\)/);
  assert.match(ipcxAppSource, /\$\("#star-support-github"\)\.addEventListener\("click", continueStarSupport\)/);
  assert.match(ipcxAppSource, /function continueStarSupport\(\)[\s\S]*?if \(shouldContinue\) runRecheck\(\)/);
  assert.match(ipcxHtml, /读取浏览器与时区信号/);
  assert.match(ipcxHtml, /交叉核对 DNS、WebRTC 与多源数据/);
  assert.match(ipcxHtml, /生成检测结论/);
});
