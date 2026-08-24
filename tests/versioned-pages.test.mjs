import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const projectRoot = new URL("../", import.meta.url);
const publicRoot = "https://betaer.github.io/AiSignalGuard/";
const files = {
  latest: new URL("index.html", projectRoot),
  v1: new URL("v1/index.html", projectRoot),
  v2: new URL("v2/index.html", projectRoot),
};

const [latestHtml, v1Html, v2Html] = await Promise.all(
  Object.values(files).map((file) => readFile(file, "utf8")),
);
const packageJson = JSON.parse(await readFile(new URL("package.json", projectRoot), "utf8"));

function normalizeRelativeReferences(html, pathname) {
  const base = new URL(pathname, "https://version.test");
  return html.replace(/\b(src|href)="([^"]+)"/g, (match, attribute, value) => {
    if (/^(?:[a-z]+:|\/\/|#|data:)/i.test(value)) {
      return match;
    }
    const normalized = new URL(value, base);
    return `${attribute}="${normalized.pathname}${normalized.search}${normalized.hash}"`;
  });
}

test("根入口、v1 与 v2 固定入口完整且不保留冗余平铺归档", async () => {
  await Promise.all(Object.values(files).map((file) => access(file)));
  for (const alias of ["index-v1.0.html", "index-v2.0.html", "index-ipcx-v2.0.html"]) {
    await assert.rejects(access(new URL(alias, projectRoot)), { code: "ENOENT" }, alias);
  }
});

test("根入口直接呈现 v2，且与 v2 固定入口保持同一份页面能力", () => {
  assert.equal(packageJson.version, "2.0.0");
  assert.match(latestHtml, /<html[^>]+data-version="2\.0\.0"/);
  assert.match(v2Html, /<html[^>]+data-version="2\.0\.0"/);
  assert.equal(
    normalizeRelativeReferences(latestHtml, "/"),
    normalizeRelativeReferences(v2Html, "/v2/"),
  );
  assert.doesNotMatch(latestHtml, /http-equiv="refresh"|location\.(?:assign|replace)\s*\(/i);
});

test("v1 固定入口保留旧版并从子目录正确引用根资源", () => {
  assert.match(v1Html, /<html[^>]+data-version="1\.0\.0"/);
  assert.match(v1Html, /href="\.\.\/styles\.min\.css\?v=/);
  assert.match(v1Html, /src="\.\.\/app\.min\.js\?v=/);
  assert.match(v1Html, /src="\.\.\/assets\/merged_ai_logo\.svg\?v=/);
});

test("三个入口的规范地址和分享预览都统一指向唯一公开根地址", () => {
  for (const [name, html] of [["latest", latestHtml], ["v1", v1Html], ["v2", v2Html]]) {
    assert.ok(html.includes(`<link rel="canonical" href="${publicRoot}">`), name);
    assert.ok(html.includes(`<meta property="og:url" content="${publicRoot}">`), name);
  }
  assert.ok(latestHtml.includes(`PROJECT_URL = "${publicRoot}"`));
  assert.ok(v2Html.includes(`PROJECT_URL = "${publicRoot}"`));
});

test("最新版去除旧品牌词和多余截图分享文案", () => {
  const forbidden = /本站|ip\.cx|ipcx|适合手机截图分享/i;
  assert.doesNotMatch(latestHtml, forbidden);
  assert.doesNotMatch(v2Html, forbidden);
});

test("最新版 GitHub Star 徽标固定显示 999+ 且不再请求真实计数", () => {
  for (const [name, html] of [["latest", latestHtml], ["v2", v2Html]]) {
    assert.match(html, /id="github-shortcut"[^>]+data-star-state="fixed"/);
    assert.match(html, /id="github-shortcut"[^>]+aria-label="打开 GitHub 仓库，999\+ Star"/);
    assert.match(html, /id="star-count"[^>]*>999\+<\/span>/);
    assert.match(html, /id="github-label"[^>]*>GitHub · 999\+<\/span>/);
    assert.doesNotMatch(
      html,
      /api\.github\.com\/repos\/|GITHUB_REPO|STAR_CACHE_KEY|STAR_CACHE_TTL_MS|normalizeStarCount|renderStarCount|loadStars\s*\(|stargazers_count/,
      name,
    );
  }
});

test("最新版页脚不再自返，JA3 / JA4 统一为第 5 条边界说明", () => {
  for (const [name, html] of [["latest", latestHtml], ["v2", v2Html]]) {
    assert.doesNotMatch(html, /返回正式首页|\.site-footer a|\.fingerprint-tls-card/);
    assert.match(html, /data-fingerprint-primary="boundaries"[\s\S]*?fingerprint-primary-count">5 项</);
    assert.match(
      html,
      /<li><strong>JA3 \/ JA4 不可直接读取<\/strong>普通网页脚本无法访问 TLS ClientHello，因此本页不会生成或伪造 JA3 \/ JA4 值。<\/li>/,
      name,
    );
    assert.doesNotMatch(html, /<article[^>]+data-fingerprint-card="tls"/);
  }
});

test("最新版首次检测与重测共用 12 小时 Star 闸门", () => {
  for (const html of [latestHtml, v2Html]) {
    assert.match(html, /pendingDetection:\s*null/);
    assert.match(html, /function requestDetection\(kind\)/);
    assert.match(html, /requestDetection\("initial"\)/);
    assert.match(html, /requestDetection\("recheck"\)/);
    assert.match(html, /if \(kind === "initial"\)[\s\S]*runInitialDetection\(\)/);
    assert.match(html, /if \(kind === "recheck"\)[\s\S]*runRecheck\(\)/);
    assert.doesNotMatch(html, /pendingRecheck/);
  }
});

test("最新版标题、首屏说明与社交搜索元数据统一使用正式品牌表达", () => {
  for (const [name, html] of [["latest", latestHtml], ["v2", v2Html]]) {
    assert.match(html, /<title>AI Signal Guard · 实时网络与浏览器隐私检测<\/title>/, name);
    assert.doesNotMatch(html, /<title>[^<]*v2\.0|(?:og:title|twitter:title)" content="[^"]*v2\.0/, name);
    assert.match(html, /<span class="brand-note">实时网络检测<\/span>/, name);
    assert.match(html, /<section class="intro"[\s\S]*?<p>浏览器端AI网络与身份信号检测<\/p>/, name);
    assert.match(html, /<meta name="robots" content="index,follow,max-image-preview:large,max-snippet:-1,max-video-preview:-1">/, name);
    assert.match(html, /<meta property="og:image" content="https:\/\/betaer\.github\.io\/AiSignalGuard\/assets\/og\.png\?v=20260824">/, name);
    assert.match(html, /<meta name="twitter:card" content="summary_large_image">/, name);
    assert.match(html, /<meta name="twitter:image" content="https:\/\/betaer\.github\.io\/AiSignalGuard\/assets\/og\.png\?v=20260824">/, name);
    assert.match(html, /<script type="application\/ld\+json">[\s\S]*?"@type": "WebApplication"[\s\S]*?"featureList": \[/, name);
  }
});
