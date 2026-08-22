import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const projectRoot = new URL("../", import.meta.url);

const RESULT_ROUTES = Object.freeze([
  ["overview", "总览", "总览"],
  ["network", "网络身份", "出口"],
  ["leaks", "泄漏与解析", "泄漏"],
  ["paths", "路径与节点", "路径"],
  ["browser", "浏览器环境", "设备"],
]);
const TOOL_ROUTES = Object.freeze([
  "ip",
  "dns",
  "stun",
  "cdn",
  "split",
  "multi",
  "latency",
]);
const CORE_ROW_IDS = Object.freeze([
  "position-consistency",
  "asn-organization",
  "geo-cross-check",
  "exit-ip-quality",
  "network-type",
  "risk-proxy-labels",
  "system-timezone",
  "browser-language",
  "emoji-rendering",
  "chinese-fonts",
  "dns-leak",
  "dns-region-consistency",
  "webrtc-leak",
  "stun-nodes",
  "majority-region",
  "conflict-check",
  "network-label-consensus",
  "ip-intel-sources",
  "route-registry-sources",
]);
const EXPECTED_VIEWS = Object.freeze([
  ...RESULT_ROUTES.map(([route]) => route),
  "tools",
  ...TOOL_ROUTES.map((route) => `tool-${route}`),
]);

async function readProjectFile(name) {
  try {
    return { name, source: await readFile(new URL(name, projectRoot), "utf8") };
  } catch (error) {
    if (error?.code === "ENOENT") return { name, source: "", error };
    throw error;
  }
}

const [htmlFile, appFile, buildFile, packageFile] = await Promise.all([
  readProjectFile("index-ipcx-remix-v1.2.0.html"),
  readProjectFile("ipcx-remix-v1.2.0.js"),
  readProjectFile("build/sites-vite-plugin.js"),
  readProjectFile("package.json"),
]);

function requiredSource(file) {
  assert.equal(
    file.error,
    undefined,
    `${file.name} 必须存在，且必须使用设计稿规定的版本化文件名`,
  );
  return file.source;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function attribute(tag, name) {
  const escapedName = escapeRegExp(name);
  const match = tag.match(
    new RegExp(
      `(?:^|\\s)${escapedName}(?:\\s*=\\s*(["'])(.*?)\\1)?(?=\\s|\\/?>)`,
      "i",
    ),
  );
  return match ? (match[2] ?? "") : null;
}

function openingTags(source) {
  return [...source.matchAll(/<[a-z][^<>]*>/gi)].map((match) => ({
    index: match.index,
    source: match[0],
    name: match[0].match(/^<([a-z][\w-]*)/i)?.[1].toLowerCase(),
  }));
}

function classTokens(tag) {
  return (attribute(tag, "class") || "").split(/\s+/).filter(Boolean);
}

function hasClass(tag, className) {
  return classTokens(tag).includes(className);
}

function elementBlocks(source, tagName) {
  const escapedName = escapeRegExp(tagName);
  return [...source.matchAll(
    new RegExp(`<${escapedName}\\b[^<>]*>[\\s\\S]*?<\\/${escapedName}>`, "gi"),
  )].map((match) => ({
    index: match.index,
    source: match[0],
    opening: match[0].match(new RegExp(`^<${escapedName}\\b[^<>]*>`, "i"))?.[0] || "",
  }));
}

function plainText(source) {
  return source
    .replace(/<script\b[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&(?:nbsp|ensp|emsp);/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function sorted(values) {
  return [...values].sort((left, right) => left.localeCompare(right, "en"));
}

function cssHexVariable(source, name) {
  const match = source.match(new RegExp(`${escapeRegExp(name)}\\s*:\\s*(#[0-9a-f]{6})\\s*;`, "i"));
  assert.ok(match, `缺少可审计的颜色变量 ${name}`);
  return match[1];
}

function relativeLuminance(hex) {
  const channels = hex.slice(1).match(/.{2}/g).map((value) => Number.parseInt(value, 16) / 255);
  const [red, green, blue] = channels.map((value) =>
    value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4,
  );
  return 0.2126 * red + 0.7152 * green + 0.0722 * blue;
}

function contrastRatio(foreground, background) {
  const lighter = Math.max(relativeLuminance(foreground), relativeLuminance(background));
  const darker = Math.min(relativeLuminance(foreground), relativeLuminance(background));
  return (lighter + 0.05) / (darker + 0.05);
}

function compositeHex(foreground, background, opacity) {
  const foregroundChannels = foreground.slice(1).match(/.{2}/g).map((value) => Number.parseInt(value, 16));
  const backgroundChannels = background.slice(1).match(/.{2}/g).map((value) => Number.parseInt(value, 16));
  return `#${foregroundChannels.map((value, index) =>
    Math.round(value * opacity + backgroundChannels[index] * (1 - opacity))
      .toString(16)
      .padStart(2, "0"),
  ).join("")}`;
}

function viewRecords(source) {
  const records = openingTags(source)
    .filter(({ source: tag }) => attribute(tag, "data-remix-view") !== null)
    .map((record) => ({
      ...record,
      view: attribute(record.source, "data-remix-view"),
    }));

  return records.map((record, index) => ({
    ...record,
    body: source.slice(record.index, records[index + 1]?.index ?? source.length),
  }));
}

function declaredStringArray(source, variableName) {
  const match = source.match(
    new RegExp(
      `(?:var|let|const)\\s+${escapeRegExp(variableName)}\\s*=\\s*(?:Object\\.freeze\\(\\s*)?\\[([\\s\\S]*?)\\]\\s*\\)?\\s*;`,
    ),
  );
  assert.ok(match, `${variableName} 必须以可审计的静态数组声明`);
  return [...match[1].matchAll(/["']([^"']+)["']/g)].map((item) => item[1]);
}

test("版本化 HTML 与控制器文件均已创建", () => {
  requiredSource(htmlFile);
  requiredSource(appFile);
});

test("页面标题、根版本属性和可见版本号均锁定为 v1.2.0", () => {
  const html = requiredSource(htmlFile);
  const htmlTag = openingTags(html).find(({ name }) => name === "html")?.source;
  assert.ok(htmlTag, "页面必须有 html 根元素");
  assert.equal(attribute(htmlTag, "lang"), "zh-CN");
  assert.equal(attribute(htmlTag, "data-remix-version"), "1.2.0");
  assert.match(
    html,
    /<title>\s*IPCX Remix v1\.2\.0\s*·\s*AI Signal Guard\s*<\/title>/i,
  );

  const description = openingTags(html).find(
    ({ name, source }) => name === "meta" && attribute(source, "name") === "description",
  )?.source;
  assert.ok(description, "页面必须提供 meta description");
  assert.match(attribute(description, "content") || "", /IPCX Remix v1\.2\.0/);

  const body = html.match(/<body\b[^>]*>([\s\S]*?)<\/body>/i)?.[1] || "";
  assert.match(plainText(body), /\bv1\.2\.0\b/, "正文中必须能看见版本号");
});

test("五个结果入口使用普通 Hash 链接，并同时提供桌面与手机名称", () => {
  const html = requiredSource(htmlFile);
  const routeLinks = elementBlocks(html, "a").filter(
    ({ opening }) => hasClass(opening, "module-tab") && attribute(opening, "data-route") !== null,
  );

  assert.equal(routeLinks.length, RESULT_ROUTES.length, "一级结果导航必须恰好五项");
  assert.deepEqual(
    routeLinks.map(({ opening }) => attribute(opening, "data-route")),
    RESULT_ROUTES.map(([route]) => route),
    "五个结果入口应保持设计稿顺序",
  );

  for (const [route, desktopLabel, mobileLabel] of RESULT_ROUTES) {
    const matches = routeLinks.filter(
      ({ opening }) => attribute(opening, "data-route") === route,
    );
    assert.equal(matches.length, 1, `${route} 结果入口必须唯一`);
    assert.equal(attribute(matches[0].opening, "href"), `#/${route}`);
    assert.equal(attribute(matches[0].opening, "role"), null, "Hash 导航不得伪装成 ARIA Tab");
    assert.match(plainText(matches[0].source), new RegExp(escapeRegExp(desktopLabel)));
    assert.match(plainText(matches[0].source), new RegExp(escapeRegExp(mobileLabel)));

    if (route === "overview") {
      assert.equal(attribute(matches[0].opening, "aria-current"), "page");
    } else {
      assert.equal(attribute(matches[0].opening, "aria-current"), null);
    }
  }
});

test("五结果、工具中心和七个工具详情拥有 13 个唯一视图", () => {
  const html = requiredSource(htmlFile);
  const views = viewRecords(html);
  const names = views.map(({ view }) => view);

  assert.equal(views.length, EXPECTED_VIEWS.length);
  assert.equal(new Set(names).size, names.length, "data-remix-view 不得重复");
  assert.deepEqual(sorted(names), sorted(EXPECTED_VIEWS));

  for (const view of views) {
    const isOverview = view.view === "overview";
    assert.equal(
      attribute(view.source, "hidden") !== null,
      !isOverview,
      `${view.view} 的中性首帧显隐状态不正确`,
    );

    const heading = elementBlocks(view.body, "h2")[0];
    assert.ok(heading, `${view.view} 必须有 h2 视图标题`);
    assert.equal(
      attribute(heading.opening, "tabindex"),
      "-1",
      `${view.view} 标题必须能接收编程式焦点`,
    );
    assert.ok(plainText(heading.source), `${view.view} 标题必须有可访问名称`);
  }
});

test("工具中心入口与七张工具卡使用唯一的规范 Hash", () => {
  const html = requiredSource(htmlFile);
  const anchors = elementBlocks(html, "a");
  assert.ok(
    anchors.some(({ opening }) => attribute(opening, "href") === "#/tools"),
    "结果中心必须能进入 #/tools",
  );

  const cards = anchors.filter(({ opening }) => hasClass(opening, "advanced-tool-card"));
  assert.equal(cards.length, TOOL_ROUTES.length, "工具中心必须恰好七张工具卡");

  const hashes = [];
  for (const tool of TOOL_ROUTES) {
    const matches = cards.filter(({ opening }) => attribute(opening, "data-tool") === tool);
    assert.equal(matches.length, 1, `${tool} 工具卡必须唯一`);
    assert.equal(attribute(matches[0].opening, "href"), `#/tools/${tool}`);
    hashes.push(attribute(matches[0].opening, "href"));
  }
  assert.equal(new Set(hashes).size, TOOL_ROUTES.length, "七个工具 Hash 不得重复");
});

test("每张高级工具卡完整披露用途、成本、隐私、确认和实现状态", () => {
  const html = requiredSource(htmlFile);
  const cards = elementBlocks(html, "a").filter(({ opening }) =>
    hasClass(opening, "advanced-tool-card"),
  );

  for (const card of cards) {
    const tool = attribute(card.opening, "data-tool");
    const text = plainText(card.source);
    assert.match(text, /用途/, `${tool} 工具卡缺少用途说明`);
    assert.match(text, /预计/, `${tool} 工具卡缺少预计探针规模`);
    assert.match(text, /网络成本/, `${tool} 工具卡缺少网络成本`);
    assert.match(text, /隐私/, `${tool} 工具卡缺少隐私等级`);
    assert.match(text, /(?:需|无需)主动确认/, `${tool} 工具卡缺少主动确认要求`);
    assert.match(text, /未启用|规划中|本版边界/, `${tool} 工具卡缺少中性实现状态`);
    assert.match(text, /查看检测边界/, `${tool} 未接入工具不能伪装成可运行操作`);
    assert.doesNotMatch(text, /开始检测|立即检测|运行工具/);
  }
});

test("七个工具详情均为中性能力边界，并可返回工具中心", () => {
  const html = requiredSource(htmlFile);
  const views = viewRecords(html);

  for (const tool of TOOL_ROUTES) {
    const view = views.find(({ view: name }) => name === `tool-${tool}`);
    assert.ok(view, `缺少 tool-${tool} 详情视图`);
    const text = plainText(view.body);
    assert.match(text, /未启用|规划中|本版边界/, `${tool} 详情必须标明未接入边界`);
    assert.match(view.body, /<a\b[^>]*href=["']#\/tools["'][^>]*>/i, `${tool} 详情缺少返回链接`);
    assert.doesNotMatch(
      text,
      /开始检测|检测成功|运行成功|成功率|已完成\s*\d+|已探测\s*\d+|延迟\s*[:：]\s*\d+\s*ms|风险结论\s*[:：]\s*(?:低|中|高)/,
      `${tool} 详情不得呈现伪造运行结果`,
    );
    assert.match(text, /不计入.*(?:分数|覆盖率|风险判断)|(?:分数|覆盖率|风险判断).*不计入/);
  }
});

test("19 个核心 data-row-id 完整、唯一，且仍使用原生 details", () => {
  const html = requiredSource(htmlFile);
  const tags = openingTags(html);
  const rowTags = tags.filter(({ source }) => attribute(source, "data-row-id") !== null);
  const rowIds = rowTags.map(({ source }) => attribute(source, "data-row-id"));
  const signalRows = tags.filter(({ source }) => hasClass(source, "signal-row"));

  assert.equal(rowTags.length, 19);
  assert.equal(signalRows.length, 19, "高级工具不得被计入 19 条核心详情");
  assert.equal(new Set(rowIds).size, 19, "data-row-id 不得重复");
  assert.deepEqual(sorted(rowIds), sorted(CORE_ROW_IDS));

  for (const row of rowTags) {
    assert.equal(row.name, "details", `${attribute(row.source, "data-row-id")} 必须使用原生 details`);
    assert.ok(hasClass(row.source, "signal-row"));
  }
});

test("高级工具中心和详情不复用 signal-row 或核心行标识", () => {
  const html = requiredSource(htmlFile);
  const toolViews = viewRecords(html).filter(({ view }) =>
    view === "tools" || view.startsWith("tool-"),
  );

  for (const view of toolViews) {
    const tags = openingTags(view.body);
    assert.equal(
      tags.some(({ source }) => hasClass(source, "signal-row")),
      false,
      `${view.view} 不得复用 .signal-row`,
    );
    assert.equal(
      tags.some(({ source }) => attribute(source, "data-row-id") !== null),
      false,
      `${view.view} 不得声明 data-row-id`,
    );
  }
});

test("页面内所有 id 唯一，控制器所需的关键节点齐全", () => {
  const html = requiredSource(htmlFile);
  const ids = openingTags(html)
    .map(({ source }) => attribute(source, "id"))
    .filter((value) => value !== null);
  assert.equal(new Set(ids).size, ids.length, "HTML id 必须全局唯一");

  for (const id of [
    "main",
    "result-title",
    "summary-exit-ip",
    "summary-location",
    "snapshot-exit-ip",
    "snapshot-location",
    "snapshot-asn",
    "snapshot-organization",
    "webrtc-http-ip",
    "webrtc-public-ip",
    "fingerprint-evidence",
    "network-source-status",
    "privacy-toggle",
    "floating-recheck",
    "floating-copy",
    "floating-action-status",
    "route-announcer",
    "recheck-loading",
    "toast",
  ]) {
    assert.ok(ids.includes(id), `缺少实时控制器所需的 #${id}`);
  }
});

test("中性首帧不内置地址、设备指纹或绿色风险结论", () => {
  const html = requiredSource(htmlFile);
  const text = plainText(html);

  assert.doesNotMatch(
    html,
    /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/,
    "初始 HTML 不得包含固定 IPv4",
  );
  assert.doesNotMatch(
    html,
    /\b(?:[0-9a-f]{1,4}:){2,}[0-9a-f:]{1,39}\b/i,
    "初始 HTML 不得包含固定 IPv6",
  );
  assert.doesNotMatch(html, /\b[0-9a-f]{16,64}\b/i, "初始 HTML 不得内置指纹摘要");
  assert.doesNotMatch(html, /\bAS\d{3,10}\b/i, "初始 HTML 不得内置 ASN");
  assert.doesNotMatch(
    text,
    /美国\s*[·/]\s*洛杉矶|洛杉矶出口|住宅\s*[/·]\s*移动网络|多源结果一致|未发现明显泄漏|0\s*项明确冲突|状态稳定|检测通过|风险较低|低风险结论/,
  );
  assert.match(text, /读取中|检测中|未确认|未知|证据不足/);

  const score = html.match(
    /<([a-z][\w-]*)\b[^>]*class=["'][^"']*\bscore-number\b[^"']*["'][^>]*>([\s\S]*?)<\/\1>/i,
  );
  assert.ok(score, "首帧必须保留网络参考分节点");
  assert.match(plainText(score[2]), /^(?:—|读取中…?|检测中…?|未确认)$/);
});

test("所有敏感首帧节点使用中性占位，并覆盖完整隐私范围", () => {
  const html = requiredSource(htmlFile);
  const sensitiveTags = openingTags(html).filter(
    ({ source }) => attribute(source, "data-sensitive") !== null,
  );
  const sensitiveKinds = sensitiveTags.map(({ source }) => attribute(source, "data-sensitive"));

  assert.ok(sensitiveTags.length >= 7, "隐私遮罩必须覆盖多类敏感值，而不只是 IPv4");
  for (const kind of ["ip", "ipv6", "mdns", "city", "asn", "organization", "fingerprint"]) {
    assert.ok(sensitiveKinds.includes(kind), `data-sensitive 缺少 ${kind} 类型`);
  }

  for (const { source: tag, index, name } of sensitiveTags) {
    const closing = `</${name}>`;
    const end = html.indexOf(closing, index);
    assert.notEqual(end, -1, `${attribute(tag, "data-sensitive")} 敏感节点缺少闭合标签`);
    const value = plainText(html.slice(index + tag.length, end));
    assert.match(
      value,
      /读取中|检测中|未确认|未知|等待|未取得|不可读取|—/,
      `${attribute(tag, "data-sensitive")} 敏感节点首帧必须中性`,
    );
  }
});

test("页面与控制器不包含示例结果、真实用户资料或嵌入式凭据", () => {
  const html = requiredSource(htmlFile);
  const app = requiredSource(appFile);
  const source = `${html}\n${app}`;

  assert.doesNotMatch(source, /38\.92\.27\.182|198\.51\.100\.|203\.0\.113\.|192\.0\.2\./);
  assert.doesNotMatch(source, /本地演示数据|本地模拟结果|固定测试用户|真实用户地址/);
  assert.doesNotMatch(source, /\bsk-(?:live|test|proj)?[-_a-z0-9]{16,}\b/i);
  assert.doesNotMatch(source, /\bAIza[0-9A-Za-z_-]{20,}\b/);
  assert.doesNotMatch(source, /\bgh[pousr]_[0-9A-Za-z]{20,}\b/);
  assert.doesNotMatch(source, /\bBearer\s+[0-9A-Za-z._~-]{16,}\b/i);
  assert.doesNotMatch(
    source,
    /(?:api[_-]?key|secret|access[_-]?token)\s*[:=]\s*["'][^"']{8,}["']/i,
  );
});

test("失败和来源缺失保持未知语义，评分必须满足跨域证据门槛，且未接入工具不参与评分", () => {
  const html = requiredSource(htmlFile);
  const app = requiredSource(appFile);

  assert.match(app, /MIN_SCORE_(?:COVERAGE|EVIDENCE)/, "评分门槛必须使用具名常量，不能任意一条来源就出分");
  assert.match(app, /intelSummary\.usable\s*>=/);
  assert.match(app, /routeSummary\.usable\s*>=/);
  assert.match(app, /stunSummary\.usable\s*>=/);
  assert.match(app, /dnsComparable/, "数字分必须纳入可比较的 DNS 证据");
  assert.match(app, /scoreAvailable\s*\?\s*String\(score\)\s*:\s*["']—["']/);
  assert.match(app, /泄漏证据不足/);
  assert.match(app, /dnsCountryMissing|dnsEvidenceIncomplete/);
  const scoreCautionInputs = app.match(
    /var\s+scoreCaution\s*=\s*Boolean\(([\s\S]*?)\n\s*\);/,
  )?.[1] || "";
  assert.match(
    scoreCautionInputs,
    /dnsCountryMissing/,
    "部分 DNS 地区字段缺失时，分数环也必须进入核对态而不是保持绿色",
  );
  assert.match(app, /未知|未确认/);
  assert.match(
    plainText(html),
    /未接入[^。；]*(?:不参与|不计入)[^。；]*(?:分数|覆盖率|风险判断)|(?:分数|覆盖率|风险判断)[^。；]*(?:不参与|不计入)[^。；]*未接入/,
  );
});

test("控制器定义确定性的五结果与七工具 Hash 路由", () => {
  const app = requiredSource(appFile);

  assert.match(app, /(?:var|let|const)\s+REMIX_DEFAULT_ROUTE\s*=\s*["']#\/overview["']/);
  assert.deepEqual(
    declaredStringArray(app, "REMIX_RESULT_ROUTES"),
    RESULT_ROUTES.map(([route]) => route),
  );
  assert.deepEqual(declaredStringArray(app, "REMIX_TOOL_ROUTES"), TOOL_ROUTES);
  assert.match(app, /function\s+normalizeRemixRoute\s*\(/);
  assert.match(app, /function\s+renderRemixRoute\s*\(/);
  assert.match(app, /history\.replaceState\s*\(/);
  assert.match(app, /location\.hash/);
  assert.match(app, /["']hashchange["']/);
  assert.equal(
    (app.match(/addEventListener\(\s*["'](?:hashchange|popstate)["']/g) || []).length,
    1,
    "纯 Hash SPA 只应注册一个历史变化监听，避免同一次切换重复渲染",
  );
  assert.match(app, /aria-current/);
  assert.match(app, /route-announcer/);
  assert.match(app, /\.focus\s*\(\s*\{\s*preventScroll:\s*true\s*\}/);
});

test("实时证据脚本按策略、证据、Remix 控制器的顺序加载", () => {
  const html = requiredSource(htmlFile);
  const scripts = openingTags(html)
    .filter(({ name }) => name === "script")
    .map(({ source }) => attribute(source, "src"))
    .filter(Boolean);
  const requiredScripts = [
    "starPromptPolicy.js",
    "ipcxEvidence.js",
    "ipcx-remix-v1.2.0.js",
  ];

  for (const script of requiredScripts) {
    assert.equal(scripts.filter((entry) => entry === script).length, 1, `${script} 必须且只能加载一次`);
  }
  assert.ok(
    requiredScripts.every((script, index) =>
      index === 0 || scripts.indexOf(requiredScripts[index - 1]) < scripts.indexOf(script)),
    "脚本顺序必须是 starPromptPolicy → ipcxEvidence → Remix 控制器",
  );
  assert.equal(scripts.includes("ipcxApp.js"), false, "Remix 不得回退加载旧控制器");
});

test("隐私说明区分自有服务器与浏览器第三方请求，复制内容服从遮罩", () => {
  const html = requiredSource(htmlFile);
  const app = requiredSource(appFile);
  const text = plainText(html);

  assert.match(text, /结果[^。；]*(?:不上传|不会上传)[^。；]*自有服务器/);
  assert.match(text, /浏览器[^。；]*(?:直接)?请求[^。；]*第三方(?:检测)?服务/);
  assert.match(app, /\[data-sensitive\]/);
  assert.match(app, /state\.privacy/);

  for (const functionName of ["summaryText", "aiDiagnosticReportText"]) {
    const block = app.match(
      new RegExp(`function\\s+${functionName}\\s*\\([\\s\\S]*?(?=\\n\\s*function\\s+|$)`),
    )?.[0];
    assert.ok(block, `缺少 ${functionName}`);
    assert.match(block, /state\.privacy/, `${functionName} 必须根据隐私状态生成文本`);
    assert.match(block, /mask|隐藏|遮罩/, `${functionName} 必须输出遮罩值而非敏感原值`);
  }
});

test("移动端固定栏恰好保留重测、分享、隐私三项操作", () => {
  const html = requiredSource(htmlFile);
  const actions = openingTags(html).filter(
    ({ source }) => attribute(source, "data-mobile-action") !== null,
  );
  const mapping = Object.fromEntries(
    actions.map(({ source }) => [attribute(source, "data-mobile-action"), attribute(source, "id")]),
  );

  assert.equal(actions.length, 3);
  assert.deepEqual(sorted(Object.keys(mapping)), ["privacy", "recheck", "share"]);
  assert.deepEqual(mapping, {
    recheck: "floating-recheck",
    share: "floating-copy",
    privacy: "privacy-toggle",
  });
  for (const { source } of actions) {
    assert.equal(attribute(source, "name"), null);
    assert.equal(attribute(source, "type"), "button");
    assert.ok(attribute(source, "aria-label"), "移动操作必须有 aria-label");
  }
});

test("跳过链接、礼貌播报、焦点样式与非阻断 Star 入口齐全", () => {
  const html = requiredSource(htmlFile);
  const app = requiredSource(appFile);
  const tags = openingTags(html);
  const anchors = elementBlocks(html, "a");
  const ids = new Map(
    tags
      .filter(({ source }) => attribute(source, "id") !== null)
      .map(({ source }) => [attribute(source, "id"), source]),
  );

  assert.ok(
    anchors.some(({ opening, source }) =>
      attribute(opening, "href") === "#main" && /跳到|跳过/.test(plainText(source))),
    "页面必须提供跳过链接",
  );
  assert.equal(attribute(ids.get("main") || "", "tabindex"), "-1", "主要内容必须可接收跳过链接焦点");
  assert.equal(attribute(ids.get("recheck-loading") || "", "tabindex"), "-1", "重测遮罩必须可接收程序化焦点");
  assert.equal(attribute(ids.get("recheck-loading") || "", "role"), "dialog", "阻断式重测遮罩必须使用对话框语义");
  assert.equal(attribute(ids.get("recheck-loading") || "", "aria-modal"), "true", "阻断式重测遮罩必须声明 aria-modal");
  assert.equal(attribute(ids.get("route-announcer") || "", "role"), "status");
  assert.equal(attribute(ids.get("route-announcer") || "", "aria-live"), "polite");
  assert.equal(attribute(ids.get("floating-action-status") || "", "role"), "status");
  assert.equal(attribute(ids.get("floating-action-status") || "", "aria-live"), "polite");
  assert.match(html, /:focus-visible\b/);
  assert.match(app, /\.inert\s*=/, "重测期间必须让遮罩后的交互区域 inert");
  assert.match(app, /focusOrigin|keyboard/i, "键盘触发路由后必须保留可见焦点来源");
  assert.doesNotMatch(html, /<dialog\b[^>]*id=["']star-support-dialog["']/i);
  assert.doesNotMatch(html, /\.star-support-(?:dialog|close|primary|secondary)\b/);
  assert.doesNotMatch(app, /star-support-dialog|\.showModal\s*\(/);
  assert.match(plainText(html), /GitHub|Star/, "Star 支持入口应保留在页脚或更多菜单中");
});

test("总览五域摘要和四个结果域状态条均有可更新的真实节点", () => {
  const html = requiredSource(htmlFile);
  const ids = openingTags(html)
    .map(({ source }) => attribute(source, "id"))
    .filter(Boolean);

  for (const id of [
    "overview-network-state",
    "overview-leaks-state",
    "overview-paths-state",
    "overview-browser-state",
    "overview-sources-state",
    "network-compact-state",
    "leaks-compact-state",
    "paths-compact-state",
    "browser-compact-state",
  ]) {
    assert.ok(ids.includes(id), `缺少动态结果节点 #${id}`);
  }

  const overviewSlot = elementBlocks(html, "div").find(({ opening }) =>
    attribute(opening, "id") === "overview-core-slot",
  );
  assert.ok(overviewSlot, "总览核心插槽必须存在");
  assert.equal(
    openingTags(overviewSlot.source).filter(({ source }) => hasClass(source, "overview-domain-card")).length,
    5,
    "总览必须直接呈现五个可深入的域摘要，不能留下空插槽",
  );
});

test("来源进行中不冒充失败，风险与冲突只统计 voteEligible 来源", () => {
  const app = requiredSource(appFile);

  assert.match(app, /function\s+summarizeSourceProgress\s*\(/);
  assert.match(app, /pending|loading/);
  assert.match(app, /进行中/);
  assert.match(
    app,
    /riskFlags\s*=\s*state\.ipIntel\.filter\([\s\S]*?record\.voteEligible/,
    "path_mismatch 等不可投票来源不得进入风险计数",
  );
  assert.match(app, /dnsCountryMissing|dnsEvidenceIncomplete/);
  assert.match(app, /state\.completedAt[\s\S]*autoDisclosure/, "自动展开必须等首轮真实检测结算后再执行");
});

test("重测会重新采集本地浏览器环境，并用 runId 阻止旧指纹迟到覆盖", () => {
  const app = requiredSource(appFile);

  assert.match(app, /function\s+refreshLocalEnvironment\s*\(/);
  assert.match(app, /state\.localSignals\s*=\s*collectLocalSignals\s*\(\s*\)/);
  assert.match(app, /state\.observations\.timezone\s*=/);
  assert.match(app, /state\.observations\.languages\s*=/);
  assert.match(app, /computeFingerprints\s*\(\s*runId\s*\)/);
  assert.match(
    app,
    /runId[^\n]*(?:!==|===)[^\n]*state\.runId|state\.runId[^\n]*(?:!==|===)[^\n]*runId/,
    "异步指纹计算提交结果前必须核对当前检测轮次",
  );
});

test("小字号次要文字与琥珀状态色在实际浅色背景上达到 WCAG AA", () => {
  const html = requiredSource(htmlFile);
  const muted = cssHexVariable(html, "--muted");
  const amber = cssHexVariable(html, "--amber");
  const backgrounds = [
    ["页面底色", cssHexVariable(html, "--bg")],
    ["卡片底色", cssHexVariable(html, "--surface")],
    ["柔和卡片底色", cssHexVariable(html, "--surface-soft")],
  ];

  for (const [label, background] of backgrounds) {
    assert.ok(
      contrastRatio(muted, background) >= 4.5,
      `--muted 在${label}上的对比度必须至少为 4.5:1`,
    );
  }
  assert.ok(
    contrastRatio(amber, cssHexVariable(html, "--amber-soft")) >= 4.5,
    "--amber 在 --amber-soft 上的对比度必须至少为 4.5:1",
  );
  assert.ok(
    contrastRatio("#ffffff", cssHexVariable(html, "--green-deep")) >= 4.5,
    "一级导航选中态的白字与绿色底必须至少达到 4.5:1",
  );
  assert.match(
    html,
    /\.module-tab\[aria-current="page"\]\s*\{[^}]*background:\s*var\(--green-deep\)/s,
    "一级导航实际选中态必须使用通过对比度合同的深绿色",
  );
  const tabSmallRule = html.match(/\.module-tab\s+small\s*\{([^}]*)\}/s)?.[1] || "";
  assert.ok(tabSmallRule, "缺少一级导航副标签样式");
  const tabSmallOpacity = Number(tabSmallRule.match(/opacity:\s*([\d.]+)/)?.[1] ?? 1);
  assert.ok(
    contrastRatio(
      compositeHex(muted, cssHexVariable(html, "--surface-soft"), tabSmallOpacity),
      cssHexVariable(html, "--surface-soft"),
    ) >= 4.5,
    "未选中导航副标签按实际透明度合成后必须达到 4.5:1",
  );
  assert.ok(
    contrastRatio(
      compositeHex("#ffffff", cssHexVariable(html, "--green-deep"), tabSmallOpacity),
      cssHexVariable(html, "--green-deep"),
    ) >= 4.5,
    "选中导航副标签按实际透明度合成后必须达到 4.5:1",
  );
});

test("四类可见焦点指示器使用不透明专用颜色并达到 3:1", () => {
  const html = requiredSource(htmlFile);
  const focus = cssHexVariable(html, "--focus");
  for (const [label, background] of [
    ["页面底色", cssHexVariable(html, "--bg")],
    ["卡片底色", cssHexVariable(html, "--surface")],
    ["柔和卡片底色", cssHexVariable(html, "--surface-soft")],
  ]) {
    assert.ok(
      contrastRatio(focus, background) >= 3,
      `焦点指示器在${label}上的对比度必须至少为 3:1`,
    );
  }
  assert.equal(
    (html.match(/outline:\s*3px\s+solid\s+var\(--focus\)/g) || []).length,
    4,
    "全局控件、说明气泡、浮动按钮和键盘路由标题必须统一使用专用焦点色",
  );
});

test("响应式样式覆盖窄屏、安全区、触控尺寸和减少动画偏好", () => {
  const html = requiredSource(htmlFile);

  assert.match(
    html,
    /<meta\b[^>]*name=["']viewport["'][^>]*content=["'][^"']*viewport-fit=cover[^"']*["'][^>]*>/i,
  );
  assert.match(html, /@media\s*\([^)]*max-width:\s*(?:960|900|844|768)px[^)]*\)/i);
  assert.match(html, /@media\s*\([^)]*max-width:\s*(?:480|440|390)px[^)]*\)/i);
  assert.match(html, /@media\s*\(prefers-reduced-motion:\s*reduce\)/i);
  assert.match(html, /env\(safe-area-inset-bottom/i);
  assert.match(html, /env\(safe-area-inset-left/i);
  assert.match(html, /env\(safe-area-inset-right/i);
  assert.match(html, /overflow-wrap:\s*anywhere/i);
  assert.match(html, /min-height:\s*(?:44px|var\(--[^)]*(?:tap|touch|target)[^)]*\))/i);
  assert.match(
    html,
    /padding-bottom:\s*(?:calc\([^;]*(?:safe|toolbar|dock)[^;]*\)|var\(--[^)]*(?:safe|toolbar|dock)[^)]*\))/i,
    "页面底部必须为安全区和固定工具栏预留空间",
  );
  assert.match(html, /(?:result-route-nav|module-tabs)[^{}]*\{[^}]*position:\s*sticky/si);
  assert.doesNotMatch(html, /fonts\.googleapis\.com|use\.typekit\.net|@import\s+url/i);
});

test("构建静态清单发布版本化 HTML 与控制器且不重复", () => {
  const build = requiredSource(buildFile);
  const manifest = build.match(/const\s+STATIC_FILES\s*=\s*\[([\s\S]*?)\]\s*;/)?.[1];
  assert.ok(manifest, "build/sites-vite-plugin.js 必须保留可审计的 STATIC_FILES 清单");
  const entries = [...manifest.matchAll(/["']([^"']+)["']/g)].map((match) => match[1]);

  for (const file of ["index-ipcx-remix-v1.2.0.html", "ipcx-remix-v1.2.0.js"]) {
    assert.equal(entries.filter((entry) => entry === file).length, 1, `${file} 必须在构建清单中且不重复`);
  }
  for (const legacyFile of ["index-ipcx.html", "ipcxApp.js", "ipcxEvidence.js"]) {
    assert.ok(entries.includes(legacyFile), `构建注册不得删除原有 ${legacyFile}`);
  }
});

test("package.json 注册 Remix 定向测试、完整回归和语法检查", () => {
  const packageSource = requiredSource(packageFile);
  const packageJson = JSON.parse(packageSource);
  const scripts = packageJson.scripts || {};

  assert.equal(packageJson.version, "1.1.0", "Remix 页面版本不得修改项目包版本");
  assert.equal(
    scripts["test:ipcx-remix"],
    "node --test tests/ipcx-remix-v1.2.0-contract.test.mjs",
  );
  assert.equal(
    scripts["test:ipcx-remix-ui"],
    "node tests/ipcx-remix-v1.2.0-ui.e2e.mjs",
  );
  assert.equal(
    scripts["test:ipcx-remix-semantics"],
    "node tests/ipcx-remix-v1.2.0-semantics.e2e.mjs",
  );
  assert.match(scripts.test || "", /npm run test:ipcx-remix/);
  assert.match(scripts["test:e2e"] || "", /npm run test:ipcx-remix-ui/);
  assert.match(scripts["test:e2e"] || "", /npm run test:ipcx-remix-semantics/);
  assert.match(scripts.check || "", /node --check ipcx-remix-v1\.2\.0\.js/);
});
