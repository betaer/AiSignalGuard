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
const socialPreview = new URL("tuiguang/social-preview.png", projectRoot);
const xiaohongshuCover = new URL("tuiguang/xiaohongshu-cover.png", projectRoot);

const [latestHtml, v1Html, v2Html] = await Promise.all(
  Object.values(files).map((file) => readFile(file, "utf8")),
);
const packageJson = JSON.parse(await readFile(new URL("package.json", projectRoot), "utf8"));
const latestRuntime = await readFile(new URL("v2/app.js", projectRoot), "utf8");

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

async function readPngDimensions(file) {
  const png = await readFile(file);
  assert.equal(png.subarray(1, 4).toString("ascii"), "PNG");
  return {
    width: png.readUInt32BE(16),
    height: png.readUInt32BE(20),
  };
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
  assert.ok(latestRuntime.includes(`PROJECT_URL = "${publicRoot}"`));
  for (const html of [latestHtml, v2Html]) assert.match(html, /src="(?:v2\/)?app\.js\?v=/);
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

test("最新版 X 入口默认只显示图标并在悬停时说明作者账号", () => {
  for (const [name, html] of [["latest", latestHtml], ["v2", v2Html]]) {
    assert.match(
      html,
      /id="github-shortcut"[\s\S]*?<a class="floating-tool-button floating-x-button" id="x-shortcut" href="https:\/\/x\.com\/intent\/user\?screen_name=betaer" target="_blank" rel="noopener noreferrer"/,
      name,
    );
    assert.match(html, /id="x-shortcut"[^>]+aria-label="在新窗口打开作者 X @Betaer 主页"[^>]+title="作者 X @Betaer"/, name);
    assert.match(html, /class="floating-tool-icon floating-x-icon"[\s\S]*?<span class="floating-tool-label">作者 X @Betaer<\/span>/, name);
    assert.match(html, /\.floating-x-icon\s*\{[^}]*fill:\s*currentColor;[^}]*stroke:\s*none;/, name);
    assert.doesNotMatch(html, /\.floating-x-button \.floating-tool-label\s*\{[^}]*opacity:\s*1;/, name);
    assert.match(html, /\.floating-tool-label\s*\{[^}]*opacity:\s*0;/, name);
    assert.match(html, /\.floating-tool-button:hover \.floating-tool-label,[^{}]+\{[^}]*opacity:\s*1;/, name);
    assert.match(html, /@media \(max-width:\s*680px\)[\s\S]*?\.floating-tool-label\s*\{\s*display:\s*none;\s*\}/, name);
    assert.match(
      html,
      /@media \(max-width:\s*360px\)[\s\S]*?\.floating-tool-button\s*\{[^}]*flex-basis:\s*38px;[^}]*width:\s*38px;[^}]*height:\s*38px;/,
      name,
    );
  }
  assert.doesNotMatch(v1Html, /id="x-shortcut"/);
});

test("最新版页脚链接密码生成器且不再自返，JA3 / JA4 统一为第 5 条边界说明", () => {
  for (const [name, html] of [["latest", latestHtml], ["v2", v2Html]]) {
    assert.doesNotMatch(html, /返回正式首页|\.fingerprint-tls-card/);
    assert.match(
      html,
      /href="https:\/\/betaer\.github\.io\/password-generator\/" title="Password Generator"[^>]*>密码生成器<\/a>/,
      name,
    );
    assert.doesNotMatch(html, /<footer class="site-footer">[\s\S]*?href="https:\/\/betaer\.github\.io\/AiSignalGuard\/"/);
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
  for (const html of [latestRuntime]) {
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
    assert.match(html, /<title>AI Signal Guard · 浏览器端 AI 网络与环境信号检测<\/title>/, name);
    assert.doesNotMatch(html, /<title>[^<]*v2\.0|(?:og:title|twitter:title)" content="[^"]*v2\.0/, name);
    assert.match(html, /<span class="brand-note">实时网络检测<\/span>/, name);
    assert.match(html, /<h1 id="demo-title">浏览器端 AI 网络与<span>环境信号检测<\/span><\/h1>/, name);
    assert.match(html, /<p class="intro-value">核对出口 IP、DNS、WebRTC、时区、语言、浏览器环境与 AI 服务路径，快速发现泄漏、冲突和异常信号。<\/p>/, name);
    assert.match(html, /<p class="intro-scenario">适用于 Claude、ChatGPT、Gemini 等 AI 服务的网络排障、环境一致性核对与访问前预检。<\/p>/, name);
    assert.match(html, /<span class="signal-group-title">环境信号<\/span>/, name);
    assert.match(html, /网络参考分基于本轮可观察信号生成，不代表平台账号状态、封号概率或平台内部风控结论。/, name);
    assert.match(html, /<meta name="robots" content="index,follow,max-image-preview:large,max-snippet:-1,max-video-preview:-1">/, name);
    assert.match(html, /<meta property="og:image" content="https:\/\/betaer\.github\.io\/AiSignalGuard\/tuiguang\/social-preview\.png\?v=20260825-environment">/, name);
    assert.match(html, /<meta property="og:image:width" content="1774">/, name);
    assert.match(html, /<meta property="og:image:height" content="887">/, name);
    assert.match(html, /<meta name="twitter:card" content="summary_large_image">/, name);
    assert.match(html, /<meta name="twitter:image" content="https:\/\/betaer\.github\.io\/AiSignalGuard\/tuiguang\/social-preview\.png\?v=20260825-environment">/, name);
    assert.match(html, /"image": "https:\/\/betaer\.github\.io\/AiSignalGuard\/tuiguang\/social-preview\.png\?v=20260825-environment"/, name);
    assert.match(html, /<script type="application\/ld\+json">[\s\S]*?"@type": "WebSite"[\s\S]*?"@type": "SoftwareApplication"[\s\S]*?"featureList": \[[\s\S]*?"@type": "BreadcrumbList"/, name);
    assert.match(html, /<link rel="sitemap" type="application\/xml" href="https:\/\/betaer\.github\.io\/sitemap\.xml">/, name);
    assert.doesNotMatch(html, /Trust Score|8-source IP|浏览器端AI网络与身份信号检测/, name);
  }
});

test("最新版结构化数据可解析并复用根站 WebSite 实体", () => {
  for (const [name, html] of [["latest", latestHtml], ["v2", v2Html]]) {
    const payload = html.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/)?.[1];
    assert.ok(payload, `${name}: 缺少 JSON-LD`);
    const data = JSON.parse(payload);
    const graph = data["@graph"];
    assert.ok(Array.isArray(graph), `${name}: JSON-LD 应使用 @graph`);
    const website = graph.find((entry) => entry["@type"] === "WebSite");
    const application = graph.find((entry) => entry["@type"] === "SoftwareApplication");
    const breadcrumb = graph.find((entry) => entry["@type"] === "BreadcrumbList");
    assert.equal(website.url, "https://betaer.github.io/", name);
    assert.equal(application.url, publicRoot, name);
    assert.equal(application.isPartOf["@id"], "https://betaer.github.io/#website", name);
    assert.equal(breadcrumb.itemListElement.length, 2, name);
  }
});

test("推广图片存在且尺寸符合社交平台使用比例", async () => {
  const [previewSize, xiaohongshuSize] = await Promise.all([
    readPngDimensions(socialPreview),
    readPngDimensions(xiaohongshuCover),
  ]);
  assert.deepEqual(previewSize, { width: 1774, height: 887 });
  assert.equal(previewSize.width / previewSize.height, 2, "X/Twitter 封面应为 2:1");
  assert.ok(xiaohongshuSize.width >= 1080, "小红书封面宽度应至少为 1080px");
  assert.ok(xiaohongshuSize.height >= 1440, "小红书封面高度应至少为 1440px");
  assert.ok(
    Math.abs(xiaohongshuSize.width / xiaohongshuSize.height - 3 / 4) < 0.003,
    "小红书封面应接近 3:4 竖版比例",
  );
});
