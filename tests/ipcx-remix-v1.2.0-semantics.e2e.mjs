// IPCX Remix v1.2.0 语义回归：隐私、缺失证据、低覆盖率、路径错配与检测生命周期。
// 运行：node tests/ipcx-remix-v1.2.0-semantics.e2e.mjs
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const PAGE_FILE = "index-ipcx-remix-v1.2.0.html";
const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const rootPrefix = `${projectRoot.replace(/\/$/, "")}${sep}`;
const mimeTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
};

const server = createServer(async (request, response) => {
  if (request.method !== "GET" && request.method !== "HEAD") {
    response.writeHead(405, { Allow: "GET, HEAD" }).end();
    return;
  }
  let pathname;
  try {
    pathname = decodeURIComponent(new URL(request.url, "http://127.0.0.1/").pathname);
  } catch {
    response.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" }).end("Bad Request");
    return;
  }
  const relativePath = pathname === "/" ? PAGE_FILE : pathname.replace(/^\/+/, "");
  const file = resolve(projectRoot, relativePath);
  if (!file.startsWith(rootPrefix)) {
    response.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" }).end("Forbidden");
    return;
  }
  try {
    const body = await readFile(file);
    response.writeHead(200, {
      "Cache-Control": "no-store",
      "Content-Type": mimeTypes[extname(file).toLowerCase()] || "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
    });
    response.end(request.method === "HEAD" ? undefined : body);
  } catch {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" }).end("Not Found");
  }
});

function json(route, body, status = 200) {
  return route.fulfill({
    status,
    contentType: "application/json; charset=utf-8",
    headers: { "Access-Control-Allow-Origin": "*" },
    body: JSON.stringify(body),
  });
}

function text(route, body, status = 200) {
  return route.fulfill({
    status,
    contentType: "text/plain; charset=utf-8",
    headers: { "Access-Control-Allow-Origin": "*" },
    body: String(body),
  });
}

function fiveUsIntelFixtures(ip) {
  return {
    "ipwho.is": {
      ip,
      country_code: "US",
      country: "United States",
      region: "California",
      city: "Mountain View",
      connection: { asn: 15169, org: "Google LLC", type: "business" },
      security: { proxy: false, vpn: false, tor: false, hosting: false },
    },
    "api.ip.sb": {
      ip,
      country_code: "US",
      country: "United States",
      region: "California",
      city: "Mountain View",
      asn: "AS15169",
      asn_organization: "Google LLC",
      type: "business",
    },
    "get.geojs.io": {
      ip,
      country_code: "US",
      country: "United States",
      region: "California",
      city: "Mountain View",
      asn: "AS15169",
      organization_name: "Google LLC",
    },
    "api.db-ip.com": {
      ipAddress: ip,
      countryCode: "US",
      countryName: "United States",
      stateProv: "California",
      city: "Mountain View",
    },
    "api.ipapi.is": {
      ip,
      location: { country_code: "US", country: "United States", state: "California", city: "Mountain View" },
      asn: { asn: 15169, org: "Google LLC", type: "business" },
      is_proxy: false,
      is_vpn: false,
      is_tor: false,
      is_datacenter: false,
    },
  };
}

async function respondToExternal(route, scenario) {
  if (scenario.httpGate) await scenario.httpGate.promise;
  const url = new URL(route.request().url());

  if (url.hostname === "api64.ipify.org") {
    await json(route, { ip: scenario.publicIp });
    return;
  }
  if (url.hostname === "api.github.com") {
    await json(route, { stargazers_count: 0 });
    return;
  }
  if (url.hostname === "bash.ws" && url.pathname === "/id") {
    await text(route, "fixture123");
    return;
  }
  if (url.hostname === "bash.ws" && url.pathname.startsWith("/dnsleak/test/")) {
    await json(route, scenario.dnsRecords || []);
    return;
  }
  if (/\.bash\.ws$/.test(url.hostname) && url.pathname.endsWith("/logo.png")) {
    await route.fulfill({ status: 200, contentType: "image/png", body: "" });
    return;
  }
  if (scenario.routeEvidence && url.hostname === "data.iana.org" && url.pathname === "/rdap/ipv4.json") {
    await json(route, { services: [[['0.0.0.0/0'], ['https://rdap.arin.net/registry/']]] });
    return;
  }
  if (scenario.routeEvidence && url.hostname === "rdap.org" && url.pathname.startsWith("/ip/")) {
    await json(route, {
      startAddress: "8.8.8.0",
      endAddress: "8.8.8.255",
      name: "GOOGLE",
      port43: "whois.arin.net",
      type: "DIRECT ALLOCATION",
    });
    return;
  }
  if (scenario.routeEvidence && url.hostname === "stat.ripe.net" && url.pathname === "/data/network-info/data.json") {
    await json(route, { data: { asns: [15169], prefix: "8.8.8.0/24" } });
    return;
  }
  if (scenario.intelFixtures?.[url.hostname]) {
    await json(route, scenario.intelFixtures[url.hostname]);
    return;
  }
  await route.abort("blockedbyclient");
}

function installBrowserFixtures(config) {
  const clipboardWrites = [];
  const clipboard = Object.freeze({
    writeText(value) {
      clipboardWrites.push(String(value));
      return Promise.resolve();
    },
    readText() {
      return Promise.resolve(clipboardWrites.at(-1) || "");
    },
  });
  Object.defineProperty(globalThis, "__semanticClipboardWrites", { configurable: true, value: clipboardWrites });
  try {
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: clipboard });
  } catch {
    Object.defineProperty(Navigator.prototype, "clipboard", { configurable: true, get: () => clipboard });
  }

  const pendingOffers = [];
  class FixtureRTCPeerConnection extends EventTarget {
    constructor(configuration = {}) {
      super();
      this.configuration = configuration;
      this.connectionState = "new";
      this.iceConnectionState = "new";
      this.localDescription = null;
    }

    createDataChannel(label) {
      return { label: String(label), close() {} };
    }

    createOffer() {
      if (config.rtcMode === "pending") {
        return new Promise((resolve, reject) => pendingOffers.push({ resolve, reject }));
      }
      if (config.rtcMode === "fail") {
        return Promise.reject(new DOMException("确定性 STUN 失败夹具", "NetworkError"));
      }
      return Promise.resolve({ type: "offer", sdp: "v=0" });
    }

    setLocalDescription(description) {
      this.localDescription = description;
      queueMicrotask(() => {
        const event = new Event("icecandidate");
        Object.defineProperty(event, "candidate", {
          value: {
            address: config.rtcIp,
            type: "srflx",
            candidate: `candidate:1 1 udp 2122260223 ${config.rtcIp} 54321 typ srflx`,
          },
        });
        this.dispatchEvent(event);
      });
      return Promise.resolve();
    }

    close() {
      this.connectionState = "closed";
      this.iceConnectionState = "closed";
    }
  }

  Object.defineProperty(globalThis, "__releaseSemanticRtc", {
    configurable: true,
    value() {
      pendingOffers.splice(0).forEach(({ reject }) => reject(new DOMException("夹具已释放", "NetworkError")));
    },
  });
  for (const name of ["RTCPeerConnection", "webkitRTCPeerConnection", "mozRTCPeerConnection"]) {
    Object.defineProperty(globalThis, name, { configurable: true, value: FixtureRTCPeerConnection });
  }
  try {
    localStorage.setItem("aisg-star-prompt-until", String(Date.now() + 24 * 60 * 60 * 1000));
  } catch {}
}

function deferred() {
  let resolvePromise;
  const promise = new Promise((resolve) => { resolvePromise = resolve; });
  return { promise, resolve: resolvePromise };
}

async function waitForDetectionIdle(page) {
  await page.waitForFunction(() => {
    const button = document.querySelector("#floating-recheck");
    return Boolean(button && !button.disabled && button.getAttribute("aria-busy") !== "true");
  }, undefined, { timeout: 15_000 });
}

async function groupState(page, title) {
  return page.evaluate((expectedTitle) => {
    const group = Array.from(document.querySelectorAll(".signal-group")).find(
      (item) => item.querySelector(".signal-group-title")?.textContent.trim() === expectedTitle,
    );
    const result = group?.querySelector(".signal-group-result");
    return {
      text: result?.textContent.trim() || "",
      fullText: group?.textContent.replace(/\s+/g, " ").trim() || "",
      tone: result?.classList.contains("bad")
        ? "bad"
        : result?.classList.contains("warn")
          ? "warn"
          : result?.classList.contains("good")
            ? "good"
            : "neutral",
    };
  }, title);
}

async function rowState(page, id) {
  return page.evaluate((rowId) => {
    const row = document.querySelector(`.signal-row[data-row-id="${rowId}"]`);
    const value = row?.querySelector(".signal-row-value");
    const evidence = row?.querySelectorAll(".row-detail-item")?.[1]?.querySelector("p");
    return {
      text: value?.textContent.trim() || "",
      evidence: evidence?.textContent.trim() || "",
      caption: row?.querySelector(".metric-evidence-caption")?.textContent.trim() || "",
      tone: value?.classList.contains("bad")
        ? "bad"
        : value?.classList.contains("warn")
          ? "warn"
          : value?.classList.contains("good")
            ? "good"
            : "neutral",
    };
  }, id);
}

let browser;
let localOrigin;

async function withScenario(scenario, callback) {
  const context = await browser.newContext({
    locale: scenario.locale || "zh-CN",
    serviceWorkers: "block",
    timezoneId: scenario.timezoneId || "Asia/Taipei",
    viewport: { width: 1200, height: 800 },
  });
  const externalRequests = [];
  try {
    await context.route("**/*", async (route) => {
      const url = new URL(route.request().url());
      if (url.origin === localOrigin) {
        await route.continue();
        return;
      }
      externalRequests.push(url.href);
      await respondToExternal(route, scenario);
    });
    await context.addInitScript(installBrowserFixtures, {
      rtcMode: scenario.rtcMode || "fail",
      rtcIp: scenario.rtcIp || "8.8.8.8",
    });
    const page = await context.newPage();
    const response = await page.goto(`${localOrigin}/${PAGE_FILE}#/overview`, { waitUntil: "domcontentloaded" });
    assert.equal(response?.status(), 200, "语义回归页面必须由本地 HTTP Server 返回 200");
    await callback(page, externalRequests);
  } finally {
    await context.close();
  }
}

async function privacyMasksCompressedIpv6() {
  const rawIpv6 = "2600::";
  await withScenario({ publicIp: rawIpv6, rtcMode: "fail", dnsRecords: [] }, async (page) => {
    await waitForDetectionIdle(page);
    assert.equal(
      (await page.locator("#summary-exit-ip").innerText()).trim(),
      rawIpv6,
      "隐私测试必须先确认页面真实接收到了压缩 IPv6 夹具",
    );
    await page.locator("#privacy-toggle").click();
    const visible = (await page.locator("#summary-exit-ip").innerText()).trim();
    assert.ok(visible, "隐私开启后仍应显示经过处理的出口地址状态");
    assert.doesNotMatch(visible, new RegExp(rawIpv6.replace(/:/g, "\\:")), "压缩 IPv6 不得在页面摘要中泄漏原值");

    await page.locator("#floating-copy").click();
    await page.waitForFunction(() => globalThis.__semanticClipboardWrites.length >= 1);
    const summary = await page.evaluate(() => globalThis.__semanticClipboardWrites.at(-1));
    assert.doesNotMatch(summary, /2600::/, "隐私开启后复制摘要不得包含压缩 IPv6 原值");

    await page.locator("#floating-ai-report").click();
    await page.waitForFunction(() => globalThis.__semanticClipboardWrites.length >= 2);
    const report = await page.evaluate(() => globalThis.__semanticClipboardWrites.at(-1));
    assert.doesNotMatch(report, /2600::/, "隐私开启后 AI 诊断报告不得包含压缩 IPv6 原值");
  });
}

async function missingDnsCountryCannotTurnGreen() {
  const publicIp = "8.8.8.8";
  await withScenario({
    publicIp,
    rtcMode: "success",
    rtcIp: publicIp,
    locale: "en-US",
    timezoneId: "America/Los_Angeles",
    intelFixtures: fiveUsIntelFixtures(publicIp),
    dnsRecords: [{ type: "dns", ip: "9.9.9.9", asn: "AS19281" }],
  }, async (page) => {
    await waitForDetectionIdle(page);
    assert.equal((await page.locator("#summary-coverage").innerText()).trim(), "50%", "5 家 IP 情报与 10 个 STUN 夹具必须形成 50% 覆盖率");
    assert.match((await rowState(page, "majority-region")).text, /US\s*·\s*5\s*\/\s*10/, "五家 US 情报夹具必须真实进入地区投票");
    assert.match((await rowState(page, "stun-nodes")).text, /10\s*\/\s*10/, "十个 STUN 夹具必须全部返回 8.8.8.8");
    const dns = await rowState(page, "dns-leak");
    const dnsRegion = await rowState(page, "dns-region-consistency");
    assert.equal(dns.tone, "warn", "DNS 缺少国家字段时，DNS 行必须保持警告态");
    assert.equal(dnsRegion.tone, "warn", "DNS 国家不可比较时，地区一致性行必须保持警告态");
    assert.match(dns.caption, /有效\s*1\s*\/\s*1/, "DNS 泄漏行可把真实解析器地址计为有效");
    assert.match(dnsRegion.caption, /有效\s*0\s*\/\s*1/, "DNS 地区行不得把缺失国家字段的解析器计为有效");

    const leak = await groupState(page, "网络泄漏");
    assert.notEqual(leak.tone, "good", "DNS 地址不同且地区缺失时，泄漏组不得判绿");
    assert.equal(
      await page.evaluate(() => Array.from(document.querySelectorAll(".signal-group")).find(
        (item) => item.querySelector(".signal-group-title")?.textContent.trim() === "身份信号",
      )?.open),
      false,
      "自动披露必须等待真实检测结算，并在终态收起无异常分组",
    );
    assert.doesNotMatch(
      (await page.locator(".status-badge").innerText()).trim(),
      /^状态稳定$/,
      "DNS 证据不可比较时，总览不得显示状态稳定",
    );
  });
}

async function threePercentCoverageCannotCreateScore() {
  const publicIp = "8.8.8.8";
  const ipwho = fiveUsIntelFixtures(publicIp)["ipwho.is"];
  await withScenario({
    publicIp,
    rtcMode: "fail",
    intelFixtures: { "ipwho.is": ipwho },
    dnsRecords: [],
  }, async (page) => {
    await waitForDetectionIdle(page);
    assert.equal((await page.locator("#summary-coverage").innerText()).trim(), "3%", "仅 1 / 30 成功时覆盖率必须是 3%");
    const score = (await page.locator(".score-number").innerText()).trim();
    assert.doesNotMatch(score, /^\d+$/, "仅 3% 覆盖率不得生成数字参考分");
    const ringStyle = await page.locator(".score-ring").getAttribute("style") || "";
    assert.doesNotMatch(ringStyle, /var\(--green\)|#159868|rgb\(21,\s*152,\s*104\)/i, "低覆盖率不得绘制绿色分数环");
    const multi = await groupState(page, "多源互证");
    assert.notEqual(multi.tone, "good", "仅一家情报成功时，多源互证不得判绿");
  });
}

async function mixedDnsEvidenceKeepsNumericScoreCautious() {
  const publicIp = "8.8.8.8";
  await withScenario({
    publicIp,
    rtcMode: "success",
    rtcIp: publicIp,
    locale: "en-US",
    timezoneId: "America/Los_Angeles",
    intelFixtures: fiveUsIntelFixtures(publicIp),
    routeEvidence: true,
    dnsRecords: [
      { type: "dns", ip: "8.8.4.4", country_code: "US", country_name: "United States", asn: "AS15169" },
      { type: "dns", ip: "9.9.9.9", asn: "AS19281" },
    ],
  }, async (page) => {
    await waitForDetectionIdle(page);
    assert.match((await page.locator(".score-number").innerText()).trim(), /^\d+$/, "跨域门槛满足后应保留数字网络参考分");
    assert.match(
      await page.locator(".score-ring").getAttribute("style") || "",
      /var\(--amber\)|#925a12|rgb\(146,\s*90,\s*18\)/i,
      "一条 DNS 地区完整、一条缺失时，即使已有数字分，分数环仍必须为琥珀核对态",
    );
    assert.match(
      (await page.locator(".status-badge").innerText()).trim(),
      /证据不足|需要核对|需留意/,
      "混合 DNS 地区证据必须在总览明确披露核对状态",
    );
    const region = await rowState(page, "dns-region-consistency");
    assert.match(region.caption, /有效\s*1\s*\/\s*2/, "混合 DNS 地区证据只能把字段完整的一条计为有效");
  });
}

async function dnsCountryWithoutAddressIsNotComparable() {
  const publicIp = "8.8.8.8";
  await withScenario({
    publicIp,
    rtcMode: "success",
    rtcIp: publicIp,
    locale: "en-US",
    timezoneId: "America/Los_Angeles",
    intelFixtures: fiveUsIntelFixtures(publicIp),
    routeEvidence: true,
    dnsRecords: [
      { type: "dns", country_code: "US", country_name: "United States", asn: "AS15169" },
    ],
  }, async (page) => {
    await waitForDetectionIdle(page);
    const dns = await rowState(page, "dns-leak");
    const region = await rowState(page, "dns-region-consistency");
    assert.equal(dns.tone, "warn", "DNS 记录没有地址时，泄漏行不得判绿");
    assert.equal(region.tone, "warn", "DNS 记录没有地址时，地区行不得判绿");
    assert.match(region.caption, /有效\s*0\s*\/\s*1/, "无地址记录不得计入地区有效证据");
    assert.doesNotMatch(region.text, /1\s*\/\s*1\s*与出口同国/, "只有国家标签、没有地址时不得声称同国一致");
    assert.doesNotMatch(region.evidence, /同国\s*1\s*个/, "地区证据说明不得把无地址记录算作同国");
    assert.doesNotMatch((await page.locator(".score-number").innerText()).trim(), /^\d+$/, "无可比较 DNS 地址时不得生成数字分");
    assert.doesNotMatch(
      await page.locator(".score-ring").getAttribute("style") || "",
      /var\(--green\)|#159868|rgb\(21,\s*152,\s*104\)/i,
      "无可比较 DNS 地址时分数环不得为绿色",
    );
    assert.notEqual((await groupState(page, "网络泄漏")).tone, "good", "无地址 DNS 证据不得让泄漏组判绿");
    assert.doesNotMatch((await page.locator(".status-badge").innerText()).trim(), /^状态稳定$/, "无地址 DNS 证据不得显示状态稳定");
  });
}

async function pathMismatchRiskFlagIsIneligible() {
  await withScenario({
    publicIp: "8.8.8.8",
    rtcMode: "fail",
    dnsRecords: [],
    intelFixtures: {
      "ipwho.is": {
        ip: "1.1.1.1",
        country_code: "US",
        country: "United States",
        connection: { asn: 13335, org: "Cloudflare, Inc." },
        security: { proxy: true, vpn: false, tor: false, hosting: false },
      },
    },
  }, async (page) => {
    await waitForDetectionIdle(page);
    assert.match(
      await page.locator('[data-evidence-set="ipIntelSources"]').innerText(),
      /ipwho\.is[\s\S]*路径不同/,
      "风险排除测试必须先确认 ipwho 路径错配夹具已被归类为 path_mismatch",
    );
    const risk = await rowState(page, "risk-proxy-labels");
    assert.notEqual(risk.tone, "bad", "path_mismatch 来源的风险字段不得触发红色风险结论");
    assert.doesNotMatch(risk.text, /1\s*家/, "path_mismatch 来源不得计入风险来源数量");
    assert.doesNotMatch(risk.evidence, /本轮\s*1\s*\/\s*10\s*家/, "path_mismatch 来源不得计入风险字段覆盖数");
    assert.match(risk.caption, /有效\s*0\s*\/\s*10/, "path_mismatch 风险字段不得虚增逐指标有效来源数");
  });
}

async function recheckRefreshesLocalEnvironment() {
  const publicIp = "8.8.8.8";
  await withScenario({
    publicIp,
    rtcMode: "success",
    rtcIp: publicIp,
    intelFixtures: fiveUsIntelFixtures(publicIp),
    dnsRecords: [{ type: "dns", ip: "9.9.9.9", country_code: "US", country_name: "United States" }],
  }, async (page) => {
    await waitForDetectionIdle(page);
    await page.emulateMedia({ reducedMotion: "reduce" });
    const beforeHash = (await page.locator('[data-fingerprint-value="v2"]').innerText()).trim();
    await page.evaluate(() => {
      Object.defineProperty(navigator, "hardwareConcurrency", { configurable: true, value: 99 });
    });
    assert.equal(await page.evaluate(() => navigator.hardwareConcurrency), 99, "测试夹具必须成功改变浏览器线程信号");

    await page.locator("#floating-recheck").click();
    await page.waitForFunction(() => document.querySelector("#floating-recheck")?.disabled === true);
    await waitForDetectionIdle(page);

    const evidence = (await page.locator("#fingerprint-evidence").innerText()).replace(/\s+/g, " ");
    const afterHash = (await page.locator('[data-fingerprint-value="v2"]').innerText()).trim();
    assert.match(evidence, /99\s*线程/, "重新检测后必须展示重新采集的 hardwareConcurrency");
    assert.notEqual(afterHash, beforeHash, "本地宽指纹摘要必须随重新采集的浏览器信号更新");
  });
}

async function pendingLifecycleRemainsPendingThenSettles() {
  const httpGate = deferred();
  await withScenario({
    publicIp: "8.8.8.8",
    rtcMode: "pending",
    dnsRecords: [],
    httpGate,
  }, async (page, externalRequests) => {
    await page.waitForTimeout(150);
    assert.equal(await page.locator("#floating-recheck").isDisabled(), true, "HTTP 与 RTC gate 未释放时检测必须仍处于运行态");
    assert.ok(externalRequests.some((url) => url.startsWith("https://api64.ipify.org/")), "HTTP gate 必须真实拦住 ipify 请求");
    assert.ok(externalRequests.some((url) => url === "https://bash.ws/id"), "HTTP gate 必须真实拦住 DNS ID 请求");
    for (const title of ["出口 IP", "网络泄漏", "多源互证"]) {
      const group = await groupState(page, title);
      assert.doesNotMatch(group.fullText, /失败\s*10|没有节点/, `${title} 在请求尚未结算时不得伪报“失败 10”或“没有节点”`);
    }
    assert.match(
      (await groupState(page, "多源互证")).fullText,
      /进行中\s*10/,
      "请求未结算时必须明确显示进行中的来源数量",
    );

    await page.evaluate(() => globalThis.__releaseSemanticRtc());
    httpGate.resolve();
    await waitForDetectionIdle(page);
    const lifecycle = await page.evaluate(() => ({
      title: document.querySelector("#result-title")?.textContent.trim() || "",
      compact: Object.fromEntries(["network", "leaks", "paths", "browser"].map((domain) => [
        domain,
        document.querySelector(`#${domain}-compact-state`)?.textContent.trim() || "",
      ])),
    }));
    assert.doesNotMatch(lifecycle.title, /等待证据结论|检测中|读取中/, "结算后总览标题必须脱离首帧占位");
    assert.doesNotMatch(lifecycle.compact.network, /^检测中$/, "结算后网络状态条必须脱离占位");
    assert.doesNotMatch(lifecycle.compact.leaks, /^未确认$/, "结算后泄漏状态条必须脱离占位");
    assert.doesNotMatch(lifecycle.compact.paths, /^读取中$/, "结算后路径状态条必须脱离占位");
    assert.doesNotMatch(lifecycle.compact.browser, /^读取中$/, "结算后浏览器状态条必须脱离占位");
  });
}

const cases = [
  ["压缩 IPv6 隐私遮罩", privacyMasksCompressedIpv6],
  ["DNS 国家字段缺失不得判绿", missingDnsCountryCannotTurnGreen],
  ["3% 覆盖率不得生成绿色分数", threePercentCoverageCannotCreateScore],
  ["混合 DNS 地区证据保持数字分核对态", mixedDnsEvidenceKeepsNumericScoreCautious],
  ["DNS 只有国家没有地址时不可比较", dnsCountryWithoutAddressIsNotComparable],
  ["路径错配来源不得贡献风险", pathMismatchRiskFlagIsIneligible],
  ["重新检测会刷新本地浏览器与指纹信号", recheckRefreshesLocalEnvironment],
  ["请求未结算与结算后的生命周期", pendingLifecycleRemainsPendingThenSettles],
];

await new Promise((resolveListen, rejectListen) => {
  server.once("error", rejectListen);
  server.listen(0, "127.0.0.1", resolveListen);
});
const address = server.address();
assert.ok(address && typeof address !== "string", "本地 HTTP Server 必须监听随机端口");
localOrigin = `http://127.0.0.1:${address.port}`;

const failures = [];
try {
  browser = await chromium.launch({ headless: true });
  for (const [name, testCase] of cases) {
    try {
      await testCase();
      console.log(`通过：${name}`);
    } catch (error) {
      failures.push({ name, error });
      console.error(`失败：${name}\n${error.stack || error}`);
    }
  }
} finally {
  await browser?.close();
  await new Promise((resolveClose) => server.close(resolveClose));
}

if (failures.length) {
  throw new AggregateError(
    failures.map(({ error }) => error),
    `IPCX Remix v1.2.0 语义回归失败 ${failures.length} / ${cases.length} 项：${failures.map(({ name }) => name).join("、")}`,
  );
}
console.log(`IPCX Remix v1.2.0 语义回归通过：${cases.length} / ${cases.length}`);
