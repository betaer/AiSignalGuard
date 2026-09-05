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
const progressOnly = process.argv.includes("--progress-only");

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
  await context.addInitScript(({ ipv4, ipv6, conflict, publicHost, ipv4Only }) => {
    window.__testPeerStats = { created: 0, closed: 0 };
    window.RTCPeerConnection = class extends EventTarget {
      constructor() { super(); this.closed = false; this.iceGatheringState = "new"; window.__testPeerStats.created++; }
      createDataChannel() {}
      async createOffer() { return {}; }
      async setLocalDescription() {
        this.iceGatheringState = "gathering";
        const addresses = ipv4Only ? [ipv4] : publicHost ? [ipv4, "2606:4700:4700::1111", "192.168.1.2", "private.local"] : [ipv4, conflict ? "2001:db8::99" : ipv6, ipv6];
        for (const address of addresses) {
          await new Promise(resolve => setTimeout(resolve, 5));
          if (this.closed) return;
          const event = new Event("icecandidate");
          Object.defineProperty(event, "candidate", { value: { type: publicHost && address !== ipv4 ? "host" : "srflx", address } });
          this.dispatchEvent(event);
        }
        this.iceGatheringState = "complete";
        this.dispatchEvent(new Event("icegatheringstatechange"));
      }
      close() { if (!this.closed) window.__testPeerStats.closed++; this.closed = true; }
    };
  }, { ipv4, ipv6, conflict: scenario.ipv6Conflict, publicHost: scenario.publicHost, ipv4Only: scenario.ipv4Only });
  const requests = [];
  await context.route("**/*", async route => {
    const url = new URL(route.request().url());
    if (url.hostname === "127.0.0.1") return route.continue();
    if (scenario.networkGate) await scenario.networkGate;
    requests.push(url.href);
    const json = body => route.fulfill({ contentType: "application/json", headers: { "Access-Control-Allow-Origin": "*" }, body: JSON.stringify(body) });
    const text = body => route.fulfill({ contentType: "text/plain", headers: { "Access-Control-Allow-Origin": "*" }, body });
    if (["api.ipify.org", "api6.ipify.org", "4.ident.me", "6.ident.me"].includes(url.hostname)) {
      if (scenario.noHttp || (scenario.publicHost && ["api6.ipify.org", "6.ident.me"].includes(url.hostname))) return route.abort();
      return json({ ip: ["api6.ipify.org", "6.ident.me"].includes(url.hostname) ? ipv6 : ipv4 });
    }
    if (url.hostname === "bash.ws") {
      if (url.pathname === "/id") return text("review0001");
      if (scenario.dnsCountry === "failed") return route.abort();
      return json([{ type: "dns", ip: "198.51.100.7", country_code: scenario.dnsCountry }]);
    }
    if (url.hostname.endsWith(".bash.ws")) return route.fulfill({ status: 204, body: "" });
    if (["chatgpt.com", "claude.ai", "gemini.google.com"].includes(url.hostname)) {
      if (scenario.aiRestricted && url.hostname === "chatgpt.com") return route.fulfill({ status: 403, headers: { "Access-Control-Allow-Origin": "*" }, body: "denied" });
      if (scenario.aiOpaque) return route.fulfill({ contentType: "text/plain", headers: { "Access-Control-Allow-Origin": "https://different-origin.example" }, body: "User-agent: *\nDisallow: /private/\n" });
      return text(url.pathname.endsWith("trace") ? `ip=${expandedIpv6}\nloc=CA\ncolo=YYZ\n` : "resource");
    }
    const target = decodeURIComponent(url.href).includes(ipv6) ? expandedIpv6 : ipv4;
    const asn = 64501, country = scenario.dualRegion && target.includes(":") ? "US" : "CA";
    const org = scenario.organizationAliases ? ({ "ipwho.is": "Linode", "get.geojs.io": "Akamai Connected Cloud", "ipinfo.io": "Akamai Connected Cloud", "api.iplocation.net": "Linode LLC", "ip.guide": "Akamai (Linode)" }[url.hostname] || "Akamai Technologies Inc.") : "Example Inc";
    const prefix = target.includes(":") || url.search.includes("origin6") ? "2001:db8::/32" : "203.0.113.0/24";
    const routeAsn = scenario.badRoutes ? 64599 : asn;
    if (scenario.onlyIpv6Intel && target === ipv4 && ["ipwho.is", "api.ip.sb", "get.geojs.io", "api.db-ip.com", "api.country.is", "api.ipapi.is", "ipinfo.io", "api.iplocation.net", "free.freeipapi.com", "ip.guide"].includes(url.hostname)) return route.abort();
    if (scenario.failGeo && url.hostname === "get.geojs.io") return route.abort();
    if (scenario.weakGeo && ["get.geojs.io", "api.db-ip.com", "api.country.is", "api.ipapi.is", "ipinfo.io", "api.iplocation.net", "free.freeipapi.com", "ip.guide"].includes(url.hostname)) return route.abort();
    if (url.hostname === "ipwho.is") return json({ ip: target, country_code: country, connection: { asn, org }, security: { proxy: scenario.proxy, hosting: false } });
    if (url.hostname === "api.ip.sb") return json({ ip: target, country_code: country, asn, asn_organization: scenario.organizationAliases ? "Akamai Connected Cloud" : "Example, Inc." });
    if (url.hostname === "get.geojs.io") return json({ ip: target, country_code: country, asn, organization_name: org });
    if (url.hostname === "api.db-ip.com") return json({ ipAddress: ipv4, countryCode: country });
    if (url.hostname === "api.country.is") return json({ ip: ipv4, country });
    if (url.hostname === "api.ipapi.is") return json({ ip: target, location: { country_code: country }, asn: { asn, org, type: "isp" }, is_proxy: scenario.proxy, is_vpn: scenario.partialRisk ? undefined : false, is_tor: scenario.partialRisk ? undefined : false, is_datacenter: false });
    if (url.hostname === "ipinfo.io") return json({ ip: target, country, org: `AS${asn} ${org}` });
    if (url.hostname === "api.iplocation.net") return json({ ip: target, country_code2: country, asn, isp: org });
    if (url.hostname === "free.freeipapi.com") return json({ ipAddress: target, countryCode: country, asNumber: asn, asOrganization: org, isProxy: false });
    if (url.hostname === "ip.guide") return json({ ip: target, location: { country_code: country }, network: { cidr: target.includes(":") ? "2001:db8::/32" : "203.0.113.0/24", autonomous_system: { asn, organization: org } } });
    if (url.hostname === "data.iana.org") return json({ services: [[url.pathname.includes("ipv6") ? ["2001:db8::/32"] : ["203.0.113.0/24"], ["https://rdap.example/"]]] });
    if (url.hostname === "rdap.org") return json({ name: org, startAddress: target, endAddress: target, handle: "TEST" });
    if (url.hostname === "stat.ripe.net") return json({ data: { resource: url.searchParams.get("resource"), asns: [routeAsn], prefix, records: [[{ key: "origin", value: `AS${asn}` }, { key: "route", value: prefix }, { key: "descr", value: org }]], prefixes: [{ prefix: "203.0.113.0/24" }, { prefix: "2001:db8::/32" }] } });
    if (url.hostname === "dns.google") return json({ Answer: [{ data: `"${routeAsn} | ${prefix} | CA | arin"` }] });
    if (url.hostname === "www.peeringdb.com") return json({ data: [{ asn: routeAsn, name: org }] });
    if (url.hostname === "api.hackertarget.com") return text(`"${target}","${routeAsn}","${prefix}","${org}"`);
    if (url.hostname === "api.asrank.caida.org") return json({ data: { asn: { asn: routeAsn, asnName: org } } });
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

async function verifyProgressRing() {
  for (const pathname of ["/", "/v2/"]) {
    let release;
    const run = await createScenario({ ipv4Only: pathname === "/v2/", networkGate: new Promise(resolve => { release = resolve; }) });
    try {
      await run.page.goto(base + pathname, { waitUntil: "load" });
      await run.page.evaluate(() => {
        window.__ringSamples = [];
        new MutationObserver(() => {
          const ring = document.querySelector(".score-ring");
          window.__ringSamples.push({
            running: document.querySelector("#result-run-state").textContent === "正在实时检测",
            number: document.querySelector(".score-number").textContent,
            label: document.querySelector(".score-label").textContent,
            coverage: Number(document.querySelector("#summary-coverage").textContent.replace("%", "")),
            background: ring.style.background,
            role: ring.getAttribute("role"), now: ring.getAttribute("aria-valuenow"),
          });
        }).observe(document.querySelector("#result-summary-card"), { subtree: true, childList: true, attributes: true });
      });
      assert.equal(await run.page.locator(".score-number").textContent(), "—");
      await run.page.locator("#star-support-continue").click();
      await run.page.waitForFunction(() => window.__ringSamples.some(item => item.running));
      const first = await run.page.evaluate(() => window.__ringSamples.find(item => item.running));
      assert.equal(first.number, "0%", "检测开始时显示 0% 而不是空评分圆环");
      assert.equal(first.role, "progressbar");
      release();
      await complete(run.page);
      const samples = await run.page.evaluate(() => window.__ringSamples.filter(item => item.running));
      assert.ok(new Set(samples.map(item => item.coverage)).size >= 3, "环形进度应随多批证据更新，而非只在完成时变化");
      for (const sample of samples) {
        assert.equal(sample.number, sample.coverage + "%");
        assert.equal(sample.label, "检测中 · 证据覆盖");
        assert.equal(sample.now, String(sample.coverage));
        assert.ok(sample.background.includes("var(--blue)") && sample.background.includes(sample.coverage + "%"), sample.background);
      }
      const ring = run.page.locator(".score-ring");
      assert.equal(await ring.getAttribute("role"), "img");
      assert.equal(await ring.getAttribute("aria-valuenow"), null);
      assert.match(await run.page.locator(".score-number").textContent(), /^\d+$/);
      assert.equal(await run.page.locator(".score-label").textContent(), pathname === "/v2/" ? "参考分 · 部分证据" : "网络参考分");
      assert.ok(!(await ring.getAttribute("style")).includes("var(--blue)"), "完成后切换为评分颜色");
      await run.page.setViewportSize({ width: 390, height: 844 });
      assert.ok(await run.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), "手机上百分比和标签不能造成溢出");
      run.scenario.networkGate = new Promise(resolve => { release = resolve; });
      run.scenario.noHttp = true;
      await run.page.evaluate(() => { window.__ringSamples = []; });
      await run.page.locator("#floating-recheck").click();
      await run.page.waitForFunction(() => window.__ringSamples.some(item => item.running));
      assert.equal(await run.page.evaluate(() => window.__ringSamples.find(item => item.running).number), "0%", "重测进度归零，不沿用上轮分数");
      release();
      await complete(run.page);
      assert.equal(await run.page.locator(".score-number").textContent(), "—");
      assert.equal(await ring.getAttribute("aria-valuenow"), null);
      assert.ok(!(await ring.getAttribute("style")).includes("conic-gradient"), "无评分终态不把覆盖率冒充评分");
      assert.deepEqual(run.errors, []);
      console.log(`通过 ${pathname} 环形进度：归零、多阶段百分比与填充同步、完成切分数、手机布局、重测及无评分终态`);
    } finally { release(); await collectCoverage(run); await run.context.close(); }
  }
}

try {
  browser = await chromium.launch({ headless: true });
  await verifyProgressRing();
  if (!progressOnly) {
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
    assert.match(await normal.page.locator('[data-row-id="route-registry-sources"] .signal-row-value').textContent(), /可用 \d+ \/ 20/);
    assert.equal(await normal.page.locator('[aria-label*="undefined"], [aria-label*="null"]').count(), 0);
    const timingRows = await normal.page.locator('[data-v2-evidence-set="webrtcLeakNodes"] .metric-evidence-source small, [data-v2-evidence-set="stunNodes"] .metric-evidence-source small').allTextContents();
    assert.equal(timingRows.length, 20);
    assert.ok(timingRows.every(text => (text.match(/\d+ms/g) || []).length === 1), timingRows.join("\n"));
    assert.match(await normal.page.locator('[data-row-id="conflict-check"]').textContent(), /0 家明确冲突/, "自回显路径不同不属于字段冲突");
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
    await normal.page.evaluate(() => {
      const original = OfflineAudioContext.prototype.startRendering;
      OfflineAudioContext.prototype.startRendering = function () { return original.call(this).then(buffer => new Promise(resolve => setTimeout(() => resolve(buffer), 2000))); };
    });
    await normal.page.locator("#audio-fingerprint-run").click();
    await normal.page.locator("#floating-recheck").click();
    await complete(normal.page);
    assert.equal(await normal.page.locator("#audio-fingerprint-runs > li").count(), 3, "全局完成必须等待正在运行的三轮音频任务");
    assert.equal(await normal.page.locator("#audio-fingerprint-run").getAttribute("aria-busy"), "false");
    await normal.page.locator("#recheck-loading").waitFor({ state: "hidden" });
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

  for (const options of [{ dnsCountry: "failed" }, { noHttp: true }, { ipv6Conflict: true }, { aiOpaque: true }, { dnsCountry: null }, { weakGeo: true }, { failGeo: true }, { badRoutes: true }, { publicHost: true }, { ipv4Only: true, organizationAliases: true }, { dualRegion: true }, { partialRisk: true }, { aiRestricted: true }, { onlyIpv6Intel: true, ipv4Only: true, organizationAliases: true, aiOpaque: true, partialRisk: true }]) {
    const run = await createScenario(options);
    try {
      await start(run, "/v2/");
      if (!options.failGeo) assert.notEqual(await run.page.locator(".status-badge").textContent(), "状态稳定", JSON.stringify(options));
      if (options.noHttp || options.weakGeo) {
        assert.equal(await run.page.locator(".score-number").textContent(), "—");
        assert.match(await run.page.locator("#score-explanation").textContent(), /未评分原因/);
        assert.ok(!(await run.page.locator(".score-ring").getAttribute("style")).includes("conic-gradient"), "未评分不能拿覆盖率冒充评分圆环");
      } else assert.match(await run.page.locator(".score-number").textContent(), /^\d+$/);
      if (options.noHttp) assert.ok(Number((await run.page.locator("#summary-coverage").textContent()).replace("%", "")) < 100);
      if (options.ipv6Conflict) assert.match(await run.page.locator("#webrtc-panel-note").textContent(), /同地址族分歧 20 个/);
      if (options.aiOpaque) assert.equal(await run.page.locator('#ai-services-section [data-raw-state="unverified"]').count(), 3, await run.page.locator("#ai-services-section").textContent());
      if (options.dnsCountry === null) {
        assert.match(await run.page.locator("#score-missing").textContent(), /DNS/);
        assert.match(await run.page.locator('.signal-subsection[aria-label="DNS"] .signal-subsection-status').textContent(), /证据不足/);
        const leakGroup = run.page.locator(".signal-group").filter({ has: run.page.locator(".signal-group-title", { hasText: "网络泄漏" }) });
        assert.match(await leakGroup.locator(".signal-group-result").textContent(), /证据不足/);
      }
      if (options.failGeo || options.weakGeo) assert.match(await run.page.locator('[data-row-id="conflict-check"]').textContent(), /0 家明确冲突/);
      if (options.weakGeo) {
        const votes = await run.page.locator('[data-evidence-set="geoVotes"]').allTextContents();
        assert.ok(votes.every(text => !text.includes("地区分歧")), votes.join("\n"));
        assert.ok(votes.some(text => text.includes("共识不足")));
      }
      if (options.badRoutes) {
        assert.match(await run.page.locator(".result-copy").textContent(), /路由/);
        assert.ok(await run.page.locator('[data-evidence-set="routeSources"] [data-raw-state="path_mismatch"]').count() >= 4);
      }
      if (options.publicHost) {
        assert.equal(await run.page.locator("#webrtc-public-ipv6").textContent(), "2606:4700:4700::1111");
        assert.match(await run.page.locator("#webrtc-http-ipv6-status").textContent(), /失败|未取得|不可用|网络错误/);
        assert.equal(await run.page.locator("#webrtc-public-ipv6-status").textContent(), "缺少 HTTP 基准");
      }
      if (options.ipv4Only) {
        assert.equal(await run.page.locator("#webrtc-public-ipv6").textContent(), "未取得");
        assert.match(await run.page.locator("#score-explanation").textContent(), /部分证据/);
        assert.match(await run.page.locator("#score-missing").textContent(), /IPv6.*WebRTC/);
        assert.ok(!(await run.page.locator(".result-copy").textContent()).includes("IP 情报来源存在字段分歧"));
        assert.match(await run.page.locator("#score-notes").textContent(), /组织名称/);
        assert.match(await run.page.locator('[data-row-id="conflict-check"] .signal-row-value').textContent(), /名称差异/);
        assert.ok(!(await run.page.locator('.signal-group').filter({ has: run.page.locator('.signal-group-title', { hasText: '多源互证' }) }).textContent()).includes("各地址族已独立核对"));
        await run.page.locator("#floating-copy").click();
        const report = await run.page.evaluate(() => navigator.clipboard.readText());
        assert.match(report, /部分证据/);
        assert.match(report, /IPv6.*WebRTC/);
        await run.page.locator("#score-details > summary").click();
        assert.equal(await run.page.locator("#score-dimensions > li").count(), 8);
        await run.page.setViewportSize({ width: 390, height: 844 });
        assert.ok(await run.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), "评分解释在手机上不能溢出");
      }
      if (options.dualRegion) {
        assert.equal(await run.page.locator('[data-row-id="system-timezone"]').getAttribute("data-tone"), "warn");
        assert.equal(await run.page.locator('[data-row-id="browser-language"]').getAttribute("data-tone"), "warn");
        assert.match(await run.page.locator('[data-row-id="system-timezone"] [data-detail-kind="result"]').textContent(), /IPv6/);
        assert.match(await run.page.locator("#score-dimensions").textContent(), /时区一致性需核对/);
      }
      if (options.partialRisk) {
        assert.match(await run.page.locator("#score-missing").textContent(), /VPN.*Tor/);
        assert.match(await run.page.locator('[data-row-id="risk-proxy-labels"] .signal-row-value').textContent(), /部分标签未知/);
      }
      if (options.aiRestricted) {
        assert.equal(await run.page.locator("#ai-service-summary").textContent(), "存在受限或路径分歧");
        assert.ok(!(await run.page.locator("#score-missing").textContent()).includes("ChatGPT"));
      }
      if (options.onlyIpv6Intel) {
        assert.match(await run.page.locator("#score-dimensions").textContent(), /DNS 地区部分核对 · 权重 5 \/ 10/);
        assert.match(await run.page.locator("#score-missing").textContent(), /IPv4 国家/);
      }
      assert.deepEqual(run.errors, []);
    } finally { await collectCoverage(run); await run.context.close(); }
  }
  for (const [name, result] of runtimeCoverage) {
    const covered = result.hits.reduce((sum, hit) => sum + hit, 0);
    console.log(`新版浏览器执行字节覆盖率 ${name}：${(covered / result.text.length * 100).toFixed(2)}%`);
    assert.ok(covered / result.text.length >= 0.8, `${name} 浏览器执行字节覆盖率低于 80%`);
  }
  console.log("新版真实页面回归通过：双栈、隐私显示与复制、动态提示、DNS/风险总结、无基准抑制评分、后到 IPv6、AI 不透明响应、重测和移动端布局。");
  }
} finally {
  await browser?.close();
  server.closeAllConnections();
  await new Promise(resolveClose => server.close(resolveClose));
}
