import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import "../signalSemantics.js";
import "../v2/timezones.js";
import "../v2/core.js";
import "../v2/evidence.js";

const core = globalThis.AISGV2Core;
const evidence = globalThis.AISGIpEvidence;
const ip = "203.0.113.42";
const ipv6 = "2001:db8::1";
const good = (id = "test") => ({ id, name: id, state: "success", attempted: true, voteEligible: true, countryCode: "US", asn: "AS64501", organization: "Example Inc", proxy: false, vpn: false, hosting: false, tor: false, observedIp: ip, observedIps: [ip], gatheringComplete: true });

function overviewInput() {
  const intel = Array.from({ length: 10 }, (_, i) => good(`intel-${i}`));
  const routes = Array.from({ length: 10 }, (_, i) => good(`route-${i}`));
  return {
    families: [{ family: "ipv4", ip, addresses: [ip], intel, routes, country: evidence.computeCountryConsensus(intel) }],
    webrtc: core.assessWebrtc(Array.from({ length: 20 }, (_, i) => good(`node-${i}`)), { ipv4: [ip], ipv6: [] }),
    dns: { state: "success", records: [{ observedIp: "198.51.100.1", countryCode: "US" }] },
    aiServices: core.AI_SERVICES.map(service => ({ ...service, state: "reachable" })),
  };
}

test("新版将等价 IPv6、混合 IPv4 写法统一，并拒绝伪地址", () => {
  assert.equal(core.normalizeIp("2001:0db8:0000:0000:0000:0000:0000:0001"), ipv6);
  assert.equal(core.normalizeIp("[2001:DB8::1]"), ipv6);
  assert.equal(core.normalizeIp("::ffff:192.0.2.1"), "::ffff:c000:201");
  for (const invalid of [":::1", "12345::1", "1:2:3", "256.0.0.1", "2001:db8::1::2"]) assert.equal(core.normalizeIp(invalid), null, invalid);
  const record = evidence.normalizeIntelPayload("ipwho", { ip: "2001:0db8:0:0:0:0:0:1", country_code: "US", connection: { asn: 64501, org: "Example" } }, { targetIp: ipv6 });
  assert.equal(record.voteEligible, true);
  assert.notEqual(record.state, "path_mismatch");
});

test("隐私遮罩覆盖文本内、多地址及混合 IPv6；摘要复制可复用相同策略", () => {
  const text = `字段：国家 / ASN · 观察地址：${ip} / ${ipv6}；另一个 198.51.100.2`;
  const masked = core.maskSensitiveText(text);
  assert.ok(masked.includes("字段：国家 / ASN"));
  for (const value of [ip, ipv6, "198.51.100.2"]) assert.ok(!masked.includes(value), value);
  assert.equal(core.maskSensitiveText(ip), "203.0.x.x");
  assert.equal(core.maskDigest("a".repeat(64), true), "aaaaaaaa••••••••");
  assert.equal(core.maskDigest("a".repeat(64), false), "a".repeat(64));
  assert.equal(core.maskSensitiveText(`IP:${ipv6}`), "IP:2001:db8:0:…");
  assert.equal(core.maskSensitiveText(`IP: ${ipv6}.`), "IP: 2001:db8:0:….");
});

test("时区数据保留共享地区，识别加拿大、巴西及历史别名", () => {
  assert.ok(core.timezoneCountries("America/Toronto").includes("CA"));
  assert.ok(!core.timezoneCountries("America/Toronto").includes("US"));
  assert.ok(core.timezoneCountries("America/Vancouver").includes("CA"));
  assert.deepEqual(core.timezoneCountries("America/Sao_Paulo"), ["BR"]);
  assert.ok(core.timezoneCountries("US/Eastern").includes("US"));
  assert.ok(core.timezoneCountries("Asia/Calcutta").includes("IN"));
  assert.deepEqual(core.timezoneCountries("Etc/UTC"), []);
  assert.deepEqual(core.timezoneCountries("Unknown/Zone"), []);
  assert.equal(core.languageRegion("zh-Hant-TW"), "TW");
});

test("组织投票先合并标点和大小写差异；平票和单票不能生成共识", () => {
  const records = [...Array(3).fill("Example, Inc."), ...Array(3).fill("EXAMPLE INC"), ...Array(4).fill("Other Ltd")].map(organization => ({ voteEligible: true, organization }));
  const result = evidence.computeOrganizationConsensus(records);
  assert.equal(result.votes, 6);
  assert.equal(result.conflicts, 4);
  assert.equal(result.strong, true);
  for (const countries of [["US"], ["US", "CA"], ["US", "US", "CA"]]) {
    assert.equal(evidence.computeCountryConsensus(countries.map(countryCode => ({ voteEligible: true, countryCode }))).value, null);
  }
});

test("待调度来源不冒充失败", () => {
  const result = evidence.summarizeSources([{ state: "pending", attempted: false }, { state: "loading", attempted: true }, { state: "timeout", attempted: true }]);
  assert.equal(result.failed, 1);
});

test("总览纳入 DNS 异常、代理标记与无法判定的 AI 响应", () => {
  const baseline = overviewInput();
  const initial = core.assessOverview(baseline);
  assert.equal(initial.score, 100);
  assert.equal(initial.evidenceMissing, false);
  assert.equal(initial.needsReview, false);
  baseline.dns.records[0].countryCode = "CN";
  const mismatch = core.assessOverview(baseline);
  assert.ok(mismatch.needsReview);
  assert.ok(mismatch.score < initial.score);
  baseline.dns = { state: "network_error", records: [] };
  assert.equal(core.assessOverview(baseline).score, null);
  assert.equal(core.assessOverview(baseline).evidenceMissing, true);
  const risk = overviewInput();
  risk.families[0].intel[0].proxy = true;
  assert.ok(core.assessOverview(risk).needsReview);
  risk.families[0].intel[0].voteEligible = false;
  assert.equal(core.assessOverview(risk).riskRecords.length, 0);
  const unreadable = overviewInput();
  unreadable.aiServices[0].state = "unverified";
  assert.equal(core.assessOverview(unreadable).evidenceMissing, true);
});

test("缺少 HTTP 基准或仅有 STUN 不能显示满覆盖率和正式分数", () => {
  const input = overviewInput();
  input.families = [];
  input.dns = { state: "network_error", records: [] };
  input.aiServices = [];
  input.webrtc = core.assessWebrtc(Array.from({ length: 20 }, () => good()), { ipv4: [], ipv6: [] });
  const result = core.assessOverview(input);
  assert.equal(result.score, null);
  assert.equal(result.coverage, 20);
  assert.ok(result.needsReview);
});

test("IPv6 后到达的分歧参与判断，缺失地址族和不完整收集保持未知", () => {
  const record = { ...good(), observedIps: [ip, "2001:0db8:0:0:0:0:0:2"] };
  const result = core.assessWebrtc([record], { ipv4: [ip], ipv6: [ipv6] });
  assert.equal(result.successes.length, 1);
  assert.equal(result.byFamily.ipv6.length, 1);
  assert.equal(result.conflicts.length, 1);
  assert.equal(result.tone, "bad");
  assert.equal(core.assessWebrtc([good()], { ipv4: [ip], ipv6: [ipv6] }).tone, "warn");
  assert.equal(core.assessWebrtc([{ ...good(), state: "partial", gatheringComplete: false }], { ipv4: [ip], ipv6: [] }).tone, "warn");
});

function fakePeer({ complete = true, addresses = [ip, ipv6], onClose = () => {} } = {}) {
  const handlers = new Map();
  let closed = false;
  return {
    addEventListener(name, fn) { handlers.set(name, fn); },
    createDataChannel() {},
    async createOffer() { return {}; },
    async setLocalDescription() {
      for (const address of addresses) {
        await Promise.resolve();
        if (!closed) handlers.get("icecandidate")({ candidate: { type: "srflx", address } });
      }
      if (complete && !closed) handlers.get("icecandidate")({ candidate: null });
    },
    close() { closed = true; onClose(); },
  };
}

test("单个 STUN 节点等待收集结束，保留并去重全部候选", async () => {
  let closeCount = 0;
  const result = await evidence.probeStunNode(evidence.STUN_NODES[0], { createPeerConnection: () => fakePeer({ addresses: [ip, ipv6, "2001:0db8::1"], onClose: () => closeCount++ }) });
  assert.deepEqual(result.observedIps, [ip, ipv6]);
  assert.equal(result.state, "success");
  assert.equal(result.gatheringComplete, true);
  assert.equal(closeCount, 1);
});

test("STUN 超时保留部分证据，取消不留下连接", async () => {
  const result = await evidence.probeStunNode(evidence.STUN_NODES[0], { timeoutMs: 15, createPeerConnection: () => fakePeer({ complete: false }) });
  assert.equal(result.state, "partial");
  assert.equal(result.gatheringComplete, false);
  assert.deepEqual(result.observedIps, [ip, ipv6]);
  const controller = new AbortController();
  let closed = false;
  const pending = evidence.probeStunNode(evidence.STUN_NODES[0], { signal: controller.signal, createPeerConnection: () => fakePeer({ complete: false, onClose: () => { closed = true; } }) });
  controller.abort();
  assert.equal((await pending).state, "aborted");
  assert.equal(closed, true);
});

test("真实 HTTP 的慢响应体仍受超时和外部取消保护", async () => {
  const timers = new Set();
  const server = createServer((request, response) => {
    response.writeHead(200, { "Content-Type": "application/json" });
    response.flushHeaders();
    const timer = setTimeout(() => { timers.delete(timer); response.end('{"ip":"203.0.113.42"}'); }, 300);
    timers.add(timer);
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}/`;
  try {
    await assert.rejects(core.request(fetch, url, { timeoutMs: 60 }), { name: "TimeoutError" });
    const controller = new AbortController();
    const request = core.request(fetch, url, { timeoutMs: 2000, signal: controller.signal });
    const cancellation = setTimeout(() => controller.abort(), 60);
    try { await assert.rejects(request, { name: "AbortError" }); }
    finally { clearTimeout(cancellation); }
    const probes = await evidence.discoverPublicIps({ timeoutMs: 60, fetchImpl: (_, options) => fetch(url, options) });
    assert.ok(probes.probes.every(probe => probe.state === "timeout"));
  } finally {
    timers.forEach(clearTimeout);
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});

test("AI 探针区分路径、资源可达、HTTP 受限和不透明响应", async () => {
  const calls = [];
  const trace = await core.probeAiService(core.AI_SERVICES[0], { fetchImpl: async (url, options) => { calls.push({url, options}); return new Response(`ip=${ipv6}\nloc=US\ncolo=LAX\n`); } });
  assert.equal(trace.state, "path_available");
  assert.equal(trace.observedIp, ipv6);
  assert.equal(calls[0].options.credentials, "omit");
  const blocked = await core.probeAiService(core.AI_SERVICES[1], { fetchImpl: async () => new Response("denied", { status: 403 }) });
  assert.equal(blocked.state, "restricted");
  const fallback = await core.probeAiService(core.AI_SERVICES[1], { fetchImpl: async (_, options) => {
    if (options.mode === "cors") throw new TypeError("Failed to fetch");
    return { type: "opaque", status: 0 };
  } });
  assert.equal(fallback.state, "unverified");
  assert.equal(fallback.observedIp, null);
  const gemini = await core.probeAiService(core.AI_SERVICES[2], { fetchImpl: async () => new Response("image") });
  assert.equal(gemini.state, "reachable");
  assert.equal(gemini.observedIp, null);
});

test("地址、弱共识与缺失字段的边界保持中性", () => {
  assert.equal(core.normalizeIp(null), null);
  assert.equal(core.ipFamily("invalid"), null);
  assert.deepEqual(core.uniqueIps(), []);
  assert.equal(core.maskSensitiveText(null), "");
  assert.equal(core.maskSensitiveText(":::1"), ":::1");
  assert.match(core.maskSensitiveText("::ffff:192.0.2.1"), /…/);
  assert.equal(core.languageRegion("und"), null);
  assert.equal(core.languageRegion("not a valid locale"), null);
  assert.equal(core.consensus([{ voteEligible: false, organization: "X" }, { voteEligible: true, organization: " " }, { voteEligible: true }], "organization").value, null);
  assert.deepEqual(core.candidateIps({ observedIp: ip }), [ip]);
  assert.equal(core.assessWebrtc([], { ipv4: [], ipv6: [] }).tone, "warn");
  assert.equal(core.assessWebrtc([good()], { ipv4: [ip, "203.0.113.43"], ipv6: [] }).httpDisagreements.length, 1);
  const sparse = overviewInput();
  sparse.dns.records[0].countryCode = null;
  assert.equal(core.assessOverview(sparse).score, null);
  const mismatch = overviewInput();
  mismatch.aiServices[0] = { state: "path_available", observedIp: ipv6, countryCode: "CA" };
  assert.equal(core.assessOverview(mismatch).needsReview, true);
  mismatch.aiServices[0].observedIp = ip;
  assert.equal(core.assessOverview(mismatch).needsReview, true);
  mismatch.aiServices[0].countryCode = "US";
  assert.equal(core.assessOverview(mismatch).needsReview, false);
});

test("AI 异常、取消、空回显与调度器都保留真实终态", async () => {
  const service = core.AI_SERVICES[0];
  const controller = new AbortController();
  controller.abort();
  let called = false;
  const aborted = await core.probeAiService(service, { signal: controller.signal, fetchImpl: async () => { called = true; } });
  assert.equal(aborted.state, "aborted");
  assert.equal(called, false);
  const timeout = await core.probeAiService(service, { timeoutMs: 5, fetchImpl: () => new Promise(() => {}) });
  assert.equal(timeout.state, "timeout");
  const failed = await core.probeAiService(service, { fetchImpl: async () => { throw new Error("network stopped"); } });
  assert.equal(failed.state, "network_error");
  const errorResponse = await core.probeAiService(service, { fetchImpl: async () => new Response(null, { status: 500 }) });
  assert.equal(errorResponse.state, "http_error");
  const empty = await core.probeAiService(service, { schedule: task => task(), fetchImpl: async () => new Response("no trace fields") });
  assert.equal(empty.state, "unverified");
  const ipOnly = await core.probeAiService(service, { fetchImpl: async () => new Response(`ip=${ip}\nloc=not-country`) });
  assert.equal(ipOnly.state, "path_available");
  assert.equal(ipOnly.countryCode, null);
  const opaque = await core.probeAiService(core.AI_SERVICES[2], { fetchImpl: async () => ({ type: "opaque" }) });
  assert.equal(opaque.state, "unverified");
  assert.equal((await core.request(async () => ({ ok: true, json: async () => ({ ok: 1 }) }), "https://example.test")).status, 200);
});
