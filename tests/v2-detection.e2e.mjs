import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile, mkdir } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const root = fileURLToPath(new URL("../", import.meta.url));
const ipv4 = "203.0.113.42";
const ipv6 = "2001:db8::1";
const expandedIpv6 = "2001:0db8:0000:0000:0000:0000:0000:0001";
const mime = { ".html": "text/html", ".js": "text/javascript", ".svg": "image/svg+xml" };
const server = createServer(async (request, response) => {
  const pathname = new URL(request.url, "http://localhost").pathname;
  const file = resolve(root, "." + (pathname.endsWith("/") ? pathname + "index.html" : pathname));
  if (!file.startsWith(root.replace(/\/$/, "") + sep)) return response.writeHead(403).end();
  try { response.writeHead(200, { "Content-Type": mime[extname(file)] || "application/octet-stream" }).end(await readFile(file)); }
  catch { response.writeHead(404).end(); }
});
await new Promise(resolveListen => server.listen(0, "127.0.0.1", resolveListen));
const base = `http://127.0.0.1:${server.address().port}`;
let browser;
const runtimeCoverage = new Map();

async function collectCoverage(run) {
  for (const entry of await run.page.coverage.stopJSCoverage()) {
    if (!/\/v2\/(?:app|core|evidence)\.js\?/.test(entry.url)) continue;
    const name = new URL(entry.url).pathname.split("/").pop();
    assert.ok(entry.source, `缺少 ${name} 的覆盖率源码`);
    const result = runtimeCoverage.get(name) || { text: entry.source, hits: new Uint8Array(entry.source.length) };
    const snapshot = new Uint8Array(entry.source.length);
    const ranges = entry.functions.flatMap(fn => fn.ranges).sort((left, right) => (right.endOffset - right.startOffset) - (left.endOffset - left.startOffset));
    for (const range of ranges) snapshot.fill(range.count > 0 ? 1 : 0, range.startOffset, range.endOffset);
    for (let index = 0; index < snapshot.length; index++) result.hits[index] ||= snapshot[index];
    runtimeCoverage.set(name, result);
  }
}

async function createScenario(options = {}) {
  const scenario = { dnsCountry: "CA", noHttp: false, proxy: false, ipv6Conflict: false, aiOpaque: false, ...options };
  const context = await browser.newContext({ locale: "en-CA", timezoneId: "America/Toronto", permissions: ["clipboard-read", "clipboard-write"] });
  await context.addInitScript(({ ipv4, ipv6, conflict }) => {
    window.__testPeerStats = { created: 0, closed: 0 };
    window.RTCPeerConnection = class extends EventTarget {
      constructor() { super(); this.closed = false; this.iceGatheringState = "new"; window.__testPeerStats.created++; }
      createDataChannel() {}
      async createOffer() { return {}; }
      async setLocalDescription() {
        this.iceGatheringState = "gathering";
        for (const address of [ipv4, conflict ? "2001:db8::99" : ipv6, ipv6]) {
          await new Promise(resolve => setTimeout(resolve, 5));
          if (this.closed) return;
          const event = new Event("icecandidate");
          Object.defineProperty(event, "candidate", { value: { type: "srflx", address } });
          this.dispatchEvent(event);
        }
        this.iceGatheringState = "complete";
        this.dispatchEvent(new Event("icegatheringstatechange"));
      }
      close() { if (!this.closed) window.__testPeerStats.closed++; this.closed = true; }
    };
  }, { ipv4, ipv6, conflict: scenario.ipv6Conflict });
  const requests = [];
  await context.route("**/*", async route => {
    const url = new URL(route.request().url());
    if (url.hostname === "127.0.0.1") return route.continue();
    requests.push(url.href);
    const json = body => route.fulfill({ contentType: "application/json", headers: { "Access-Control-Allow-Origin": "*" }, body: JSON.stringify(body) });
    const text = body => route.fulfill({ contentType: "text/plain", headers: { "Access-Control-Allow-Origin": "*" }, body });
    if (["api.ipify.org", "api6.ipify.org", "4.ident.me", "6.ident.me"].includes(url.hostname)) {
      if (scenario.noHttp) return route.abort();
      return json({ ip: ["api6.ipify.org", "6.ident.me"].includes(url.hostname) ? ipv6 : ipv4 });
    }
    if (url.hostname === "bash.ws") {
      if (url.pathname === "/id") return text("review0001");
      if (scenario.dnsCountry === "failed") return route.abort();
      return json([{ type: "dns", ip: "198.51.100.7", country_code: scenario.dnsCountry }]);
    }
    if (url.hostname.endsWith(".bash.ws")) return route.fulfill({ status: 204, body: "" });
    if (["chatgpt.com", "claude.ai", "gemini.google.com"].includes(url.hostname)) {
      if (scenario.aiOpaque) return route.fulfill({ contentType: "text/plain", headers: { "Access-Control-Allow-Origin": "https://different-origin.example" }, body: "User-agent: *\nDisallow: /private/\n" });
      return text(url.pathname.endsWith("trace") ? `ip=${expandedIpv6}\nloc=CA\ncolo=YYZ\n` : "resource");
    }
    const target = decodeURIComponent(url.href).includes(ipv6) ? expandedIpv6 : ipv4;
    const asn = 64501, org = "Example Inc", country = "CA";
    if (url.hostname === "ipwho.is") return json({ ip: target, country_code: country, connection: { asn, org }, security: { proxy: scenario.proxy, hosting: false } });
    if (url.hostname === "api.ip.sb") return json({ ip: target, country_code: country, asn, asn_organization: "Example, Inc." });
    if (url.hostname === "get.geojs.io") return json({ ip: target, country_code: country, asn, organization_name: org });
    if (url.hostname === "api.db-ip.com") return json({ ipAddress: ipv4, countryCode: country });
    if (url.hostname === "api.country.is") return json({ ip: ipv4, country });
    if (url.hostname === "api.ipapi.is") return json({ ip: target, location: { country_code: country }, asn: { asn, org, type: "isp" }, is_proxy: scenario.proxy, is_datacenter: false });
    if (url.hostname === "ipinfo.io") return json({ ip: target, country, org: `AS${asn} ${org}` });
    if (url.hostname === "api.iplocation.net") return json({ ip: target, country_code2: country, asn, isp: org });
    if (url.hostname === "free.freeipapi.com") return json({ ipAddress: target, countryCode: country, asNumber: asn, asOrganization: org, isProxy: false });
    if (url.hostname === "ip.guide") return json({ ip: target, location: { country_code: country }, network: { cidr: target.includes(":") ? "2001:db8::/32" : "203.0.113.0/24", autonomous_system: { asn, organization: org } } });
    if (url.hostname === "data.iana.org") return json({ services: [[url.pathname.includes("ipv6") ? ["2001:db8::/32"] : ["203.0.113.0/24"], ["https://rdap.example/"]]] });
    if (url.hostname === "rdap.org") return json({ name: org, startAddress: target, endAddress: target, handle: "TEST" });
    if (url.hostname === "stat.ripe.net") return json({ data: { asns: [asn], prefix: "203.0.113.0/24", records: [[{ key: "origin", value: `AS${asn}` }, { key: "descr", value: org }]], prefixes: [{ prefix: "203.0.113.0/24" }] } });
    if (url.hostname === "dns.google") return json({ Answer: [{ data: `"${asn} | 203.0.113.0/24 | CA | arin"` }] });
    if (url.hostname === "www.peeringdb.com") return json({ data: [{ asn, name: org }] });
    if (url.hostname === "api.hackertarget.com") return text(`"${target}","${asn}","203.0.113.0/24","${org}"`);
    if (url.hostname === "api.asrank.caida.org") return json({ data: { asn: { asn, asnName: org } } });
    throw new Error(`测试未声明的外部请求：${url.href}`);
  });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.coverage.startJSCoverage();
  return { scenario, context, page, requests, errors };
}

async function complete(page) {
  await page.waitForFunction(() => !document.querySelector("#floating-recheck").disabled && document.querySelector("#result-run-state").textContent === "本次检测完成", null, { timeout: 20000 });
}

async function start(run, pathname) {
  await run.page.goto(base + pathname, { waitUntil: "load" });
  assert.equal(run.requests.length, 0, "首次确认前不得发起外部检测");
  assert.equal(await run.page.locator("#result-run-state").textContent(), "尚未开始检测");
  assert.equal(await run.page.locator('[data-evidence-set="positionConsistency"] [data-raw-state="success"]').count(), 0, "确认前本地明细不得宣称已读取");
  await run.page.locator("#star-support-continue").click();
  await complete(run.page);
}

try {
  browser = await chromium.launch({ headless: true });
  const normal = await createScenario();
  try {
    await start(normal, "/");
    assert.equal(await normal.page.locator(".status-badge").textContent(), "状态稳定", await normal.page.evaluate(() => JSON.stringify({
      score: document.querySelector(".score-number").textContent,
      webRtc: document.querySelector("#webrtc-panel-note").textContent,
      intel: document.querySelector('[data-evidence-set="ipIntelSources"]').textContent,
      routes: document.querySelector('[data-evidence-set="routeSources"]').textContent,
      ai: document.querySelector("#ai-services-section").textContent,
      dns: document.querySelector('[data-evidence-set="dnsResolvers"]').textContent,
    })));
    assert.equal(await normal.page.locator("#webrtc-public-ipv6").textContent(), ipv6);
    assert.equal(await normal.page.locator('[data-row-id="system-timezone"]').getAttribute("data-tone"), "good");
    assert.ok(!(await normal.page.locator('[data-row-id="system-timezone"] [data-help-kind="advice"] .row-help-bubble').textContent()).includes("请等待本轮检测完成"));
    assert.equal(await normal.page.locator('#ai-services-section [data-raw-state="path_available"]').count(), 2);
    assert.equal(await normal.page.locator('#ai-services-section [data-raw-state="reachable"]').count(), 1);
    const peerStats = await normal.page.evaluate(() => window.__testPeerStats);
    assert.deepEqual(peerStats, { created: 20, closed: 20 });
    await normal.page.locator("#privacy-toggle").click();
    const sensitive = await normal.page.locator('[data-sensitive="ip"]').allTextContents();
    assert.ok(sensitive.every(value => !value.includes(ipv4) && !value.includes(ipv6)), "所有 IP 明细均应脱敏");
    const allEvidence = await normal.page.locator("[data-evidence-set]").allTextContents();
    assert.ok(allEvidence.every(value => !value.includes(ipv4) && !value.includes(ipv6) && !value.includes(expandedIpv6)), "包括路由范围在内的所有来源明细都应脱敏");
    await normal.page.locator('[data-fingerprint-primary="webaudio"] > summary').click();
    const digest = await normal.page.locator("#audio-fingerprint-runs code").first().textContent();
    assert.match(digest, /••••/);
    await normal.page.locator(".audio-fingerprint-copy").first().click();
    assert.equal(await normal.page.evaluate(() => navigator.clipboard.readText()), digest);
    await normal.page.locator("#floating-ai-report").click();
    const report = await normal.page.evaluate(() => navigator.clipboard.readText());
    assert.ok(report.includes("【AI 服务路径】"));
    assert.ok(!report.includes(ipv4) && !report.includes(ipv6) && !report.includes(expandedIpv6));
    normal.scenario.dnsCountry = "CN";
    normal.scenario.proxy = true;
    await normal.page.locator("#floating-recheck").click();
    await complete(normal.page);
    assert.equal(await normal.page.locator(".status-badge").textContent(), "需要核对");
    assert.match(await normal.page.locator(".result-copy").textContent(), /DNS.*代理/);
    await normal.page.locator("#recheck-loading").waitFor({ state: "hidden" });
    await normal.page.locator("#ai-services-section > summary").click();
    await normal.page.setViewportSize({ width: 390, height: 844 });
    assert.ok(await normal.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), "移动端不能横向溢出");
    await mkdir(resolve(root, "output/playwright"), { recursive: true });
    await normal.page.locator("#ai-services-section").screenshot({ path: resolve(root, "output/playwright/v2-ai-services-mobile.png") });
    assert.deepEqual(normal.errors, []);
  } finally { await collectCoverage(normal); await normal.context.close(); }

  for (const options of [{ dnsCountry: "failed" }, { noHttp: true }, { ipv6Conflict: true }, { aiOpaque: true }]) {
    const run = await createScenario(options);
    try {
      await start(run, "/v2/");
      assert.notEqual(await run.page.locator(".status-badge").textContent(), "状态稳定", JSON.stringify(options));
      if (options.dnsCountry === "failed" || options.noHttp) assert.equal(await run.page.locator(".score-number").textContent(), "—");
      if (options.noHttp) assert.ok(Number((await run.page.locator("#summary-coverage").textContent()).replace("%", "")) < 100);
      if (options.ipv6Conflict) assert.match(await run.page.locator("#webrtc-panel-note").textContent(), /同地址族分歧 20 个/);
      if (options.aiOpaque) assert.equal(await run.page.locator('#ai-services-section [data-raw-state="unverified"]').count(), 3, await run.page.locator("#ai-services-section").textContent());
      assert.deepEqual(run.errors, []);
    } finally { await collectCoverage(run); await run.context.close(); }
  }
  for (const [name, result] of runtimeCoverage) {
    const covered = result.hits.reduce((sum, hit) => sum + hit, 0);
    console.log(`新版浏览器执行字节覆盖率 ${name}：${(covered / result.text.length * 100).toFixed(2)}%`);
    assert.ok(covered / result.text.length >= 0.8, `${name} 浏览器执行字节覆盖率低于 80%`);
  }
  console.log("新版真实页面回归通过：双栈、隐私显示与复制、动态提示、DNS/风险总结、无基准抑制评分、后到 IPv6、AI 不透明响应、重测和移动端布局。");
} finally {
  await browser?.close();
  server.closeAllConnections();
  await new Promise(resolveClose => server.close(resolveClose));
}
