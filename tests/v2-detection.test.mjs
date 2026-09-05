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
    timezone: "America/New_York", language: "en-US",
  };
}

function dualInput() {
  const input = overviewInput();
  input.families.push({ ...input.families[0], family: "ipv6", ip: ipv6, addresses: [ipv6] });
  input.webrtc = core.assessWebrtc(Array.from({ length: 20 }, (_, i) => ({ ...good(`node-${i}`), observedIps: [ip, ipv6] })), { ipv4: [ip], ipv6: [ipv6] });
  return input;
}

test("真实双栈场景：IPv6 无候选仍给部分证据参考分，未知权重不算通过", () => {
  const input = dualInput();
  input.webrtc = core.assessWebrtc(Array.from({ length: 16 }, () => good()), { ipv4: [ip], ipv6: [ipv6] });
  input.language = "zh-TW";
  const result = core.assessOverview(input);
  assert.equal(result.scoreState, "partial");
  assert.equal(result.assessedWeight, 87.5);
  assert.equal(result.score, 94);
  assert.equal(result.dimensions.find(item => item.id === "webrtc").assessedWeight, 12.5);
  assert.match(result.missingReasons.join("；"), /IPv6.*WebRTC/);
  assert.ok(result.reasons.some(text => text.includes("语言")));
  assert.ok(result.evidenceMissing);
});

test("评分和来源覆盖率分开；DNS 失败、少量节点与组织标签差异不一票否决", () => {
  const input = overviewInput();
  input.webrtc = core.assessWebrtc([good()], { ipv4: [ip], ipv6: [] });
  input.dns = { state: "network_error", records: [] };
  input.families[0].routes = input.families[0].routes.slice(0, 1);
  input.families[0].intel = input.families[0].intel.slice(0, 3);
  const result = core.assessOverview(input);
  assert.ok(result.coverage < 60);
  assert.equal(result.score, 100);
  assert.equal(result.scoreState, "partial");
  assert.equal(result.assessedWeight, 90);
  assert.match(result.missingReasons.join("；"), /DNS/);
});

test("完全缺失、基础共识不足或可核对权重太少时不伪造评分", () => {
  const input = overviewInput();
  input.families[0].intel = [good()];
  input.families[0].country = core.consensus(input.families[0].intel, "countryCode");
  let result = core.assessOverview(input);
  assert.equal(result.score, null);
  assert.match(result.scoreBlockers.join("；"), /可靠.*共识/);
  input.families[0].intel = Array.from({ length: 3 }, () => ({ ...good(), asn: null, proxy: null, vpn: null, hosting: null, tor: null }));
  input.families[0].country = core.consensus(input.families[0].intel, "countryCode");
  input.families[0].routes = [];
  input.webrtc = core.assessWebrtc([], { ipv4: [ip], ipv6: [] });
  input.dns = { state: "network_error", records: [] };
  input.aiServices = [];
  input.timezone = "Etc/UTC";
  input.language = "en";
  result = core.assessOverview(input);
  assert.equal(result.scoreState, "unavailable");
  assert.match(result.scoreBlockers.join("；"), /40/);
  assert.equal(result.assessedWeight, 10);
});

test("组织名称差异与国家 ASN 明确冲突共用判断，未知字段不能标成全字段一致", () => {
  const input = overviewInput();
  const names = ["Linode", "Akamai Connected Cloud", "Akamai Connected Cloud", "Linode LLC", "Akamai (Linode)", "Akamai Technologies Inc."];
  input.families[0].intel = names.map((organization, i) => ({ ...good(`org-${i}`), organization }));
  const fieldAssessment = core.assessIntel(input.families);
  assert.equal(fieldAssessment.conflicts.length, 0);
  assert.equal(fieldAssessment.organizationDifferences.length, 1);
  assert.match(fieldAssessment.families[0].records[0].label, /国家.*ASN.*一致/);
  assert.match(fieldAssessment.families[0].records[0].label, /组织.*参考/);
  const result = core.assessOverview(input);
  assert.equal(result.score, 100);
  assert.equal(result.needsReview, false);
  assert.match(result.notes.join("；"), /组织名称/);
  assert.ok(!result.reasons.some(text => text.includes("字段分歧")));
  input.families[0].intel.push({ ...good("conflict"), countryCode: "CA", asn: "AS64599" });
  const conflicted = core.assessOverview(input);
  assert.equal(conflicted.intel.conflicts.length, 1);
  assert.ok(conflicted.score < result.score);
  assert.ok(conflicted.reasons.some(text => text.includes("国家 / ASN")));
});

test("部分收集仍保留已观察到的冲突；未知 WebRTC、AI 和缺失风险逐项解释", () => {
  const input = dualInput();
  input.webrtc = core.assessWebrtc([{ ...good(), gatheringComplete: false, observedIps: ["203.0.113.99"] }], { ipv4: [ip], ipv6: [ipv6] });
  input.families.forEach(family => { family.intel = family.intel.map(record => ({ ...record, proxy: null, vpn: null, hosting: null, tor: null })); });
  input.aiServices[2].state = "unverified";
  const result = core.assessOverview(input);
  const rtc = result.dimensions.find(item => item.id === "webrtc");
  assert.equal(rtc.earnedWeight, 0);
  assert.equal(rtc.assessedWeight, 12.5);
  assert.ok(result.score < 100);
  assert.match(result.reasons.join("；"), /WebRTC/);
  for (const term of [/IPv6.*WebRTC/, /收集未完整/, /风险标签/, /Gemini/]) assert.match(result.missingReasons.join("；"), term);
});

test("只取得一个否定风险标签，不能把其余未知标签算通过", () => {
  const input = overviewInput();
  input.families[0].intel = input.families[0].intel.map(record => ({ ...record, vpn: null, tor: null, hosting: null }));
  const result = core.assessOverview(input);
  const risk = result.dimensions.find(item => item.id === "risk");
  assert.equal(risk.assessedWeight, 2.5);
  assert.equal(risk.state, "partial");
  assert.match(result.missingReasons.join("；"), /VPN.*Tor.*Hosting/);
  assert.equal(result.scoreState, "partial");
});

test("时区和语言按全部 HTTP 地址族核对，不能只取主地址族", () => {
  const input = dualInput();
  input.families[1].intel = input.families[1].intel.map(record => ({ ...record, countryCode: "JP" }));
  input.families[1].country = core.consensus(input.families[1].intel, "countryCode");
  const result = core.assessOverview(input);
  assert.deepEqual(result.environment.timezone.map(check => check.mismatch), [false, true]);
  assert.deepEqual(result.environment.language.map(check => check.mismatch), [false, true]);
  assert.equal(result.dimensions.find(item => item.id === "timezone").earnedWeight, 2.5);
  assert.equal(result.dimensions.find(item => item.id === "language").earnedWeight, 2.5);
});

test("同族 HTTP 多出口是独立的已知分歧，不因该族情报弱共识而排除", () => {
  const input = dualInput();
  input.families[1].intel = [];
  input.families[1].country = core.consensus([], "countryCode");
  input.families[1].addresses = [ipv6, "2001:db8::2"];
  input.webrtc = core.assessWebrtc([good()], { ipv4: [ip], ipv6: input.families[1].addresses });
  const result = core.assessOverview(input);
  assert.ok(result.score < 100);
  assert.equal(result.dimensions.find(item => item.id === "network").state, "review");
  assert.match(result.missingReasons.join("；"), /IPv6 国家/);
});

test("已读到 AI HTTP 拒绝不是未知，评分和服务摘要应共用已知受限状态", () => {
  const input = overviewInput();
  input.aiServices[0].state = "restricted";
  const result = core.assessOverview(input);
  assert.equal(result.aiMissing, false);
  assert.equal(result.aiMismatch, true);
  assert.equal(result.scoreState, "complete");
  assert.equal(result.dimensions.find(item => item.id === "ai").state, "review");
});

test("实测部分接口超时：DNS 与已知出口可核对的部分不被另一族缺失整项抹掉", () => {
  const input = dualInput();
  input.families[0].intel = [];
  input.families[0].country = core.consensus([], "countryCode");
  input.families[1].intel = input.families[1].intel.map(record => ({ ...record, vpn: null, tor: null, hosting: null }));
  input.webrtc = core.assessWebrtc([good()], { ipv4: [ip], ipv6: [ipv6] });
  input.aiServices = core.AI_SERVICES.map(service => ({ ...service, state: "timeout" }));
  input.timezone = "Asia/Taipei";
  input.language = "zh-TW";
  const result = core.assessOverview(input);
  assert.equal(result.dimensions.find(item => item.id === "dns").assessedWeight, 5);
  assert.equal(result.assessedWeight, 41.25);
  assert.equal(result.score, 88);
  assert.equal(result.scoreState, "partial");
  assert.match(result.missingReasons.join("；"), /DNS/);
});

test("DNS 按已知比例计分，双栈异地匹配任一已知国家，不借缺失补全", () => {
  for (const { countries, resolvers, weight, earned } of [
    { countries: ["US", "CA"], resolvers: ["CA"], weight: 10, earned: 10 },
    { countries: ["US", "CA"], resolvers: ["US", null], weight: 5, earned: 5 },
    { countries: [null, "CA"], resolvers: ["CA", null], weight: 2.5, earned: 2.5 },
    { countries: ["US", "CA"], resolvers: ["CA", "JP"], weight: 10, earned: 5 },
    { countries: [null, "CA"], resolvers: ["JP"], weight: 5, earned: 0 },
    { countries: [null, null], resolvers: ["US"], weight: 0, earned: 0 },
    { countries: ["US", "CA"], resolvers: [null], weight: 0, earned: 0 },
    { countries: ["US", "CA"], resolvers: [], weight: 0, earned: 0 },
  ]) {
    const input = dualInput();
    input.families.forEach((family, i) => {
      family.intel = family.intel.map(record => ({ ...record, countryCode: countries[i] }));
      family.country = core.consensus(family.intel, "countryCode");
    });
    input.dns.records = resolvers.map((countryCode, i) => ({ observedIp: `198.51.100.${i + 1}`, countryCode }));
    const result = core.assessOverview(input);
    const dns = result.dimensions.find(item => item.id === "dns");
    assert.equal(dns.assessedWeight, weight, JSON.stringify({ countries, resolvers }));
    assert.equal(dns.earnedWeight, earned);
    if (weight < 10) assert.match(result.missingReasons.join("；"), /DNS/);
  }
});

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
  assert.equal(core.assessOverview(baseline).scoreState, "partial");
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
        if (!closed) handlers.get("icecandidate")({ candidate: typeof address === "string" ? { type: "srflx", address } : address });
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

test("公网 host IPv6 参与泄漏核对，但不冒充 STUN 服务器响应", async () => {
  const host = "2606:4700:4700::1111";
  const addresses = [ip, { type: "host", address: host }, ...["192.168.1.2", "10.0.0.2", "127.0.0.1", "169.254.1.2", "100.64.0.1", "fc00::1", "fe80::1", "::1", "ff02::1", "device.local", "::ffff:192.168.1.1"].map(address => ({ type: "host", address })), { type: "relay", address: "8.8.8.8" }];
  const result = await evidence.probeStunNode(evidence.STUN_NODES[0], { createPeerConnection: () => fakePeer({ addresses }) });
  assert.deepEqual(result.observedIps, [ip, host]);
  assert.deepEqual(result.hostIps, [host]);
  assert.deepEqual(result.srflxIps, [ip]);
  assert.equal(core.assessWebrtc([result], { ipv4: [ip], ipv6: [] }).unverified.length, 1);
  const onlyHost = await evidence.probeStunNode(evidence.STUN_NODES[0], { createPeerConnection: () => fakePeer({ addresses: [{ type: "host", address: host }] }) });
  const assessment = core.assessWebrtc([onlyHost], { ipv4: [], ipv6: [host] });
  assert.equal(assessment.successes.length, 1);
  assert.equal(assessment.stunResponses.length, 0);
  assert.equal(assessment.tone, "warn");
});

test("路由响应须匹配查询对象，ASN 分歧进入总览而非只计成功数量", () => {
  const source = id => evidence.ROUTE_SOURCES.find(item => item.id === id);
  const normalize = (id, payload, targetIp = ip) => evidence.normalizeRoutePayload(source(id), payload, { targetIp, asn: "AS64501" });
  for (const [id, payload] of [
    ["ripe-network", { data: { asns: [64501], prefix: "198.51.100.0/24" } }],
    ["rir-rdap", { startAddress: "198.51.100.0", endAddress: "198.51.100.255", name: "Wrong range" }],
    ["peeringdb", { data: [{ asn: 64599, name: "Wrong ASN" }] }],
    ["caida", { data: { asn: { asn: 64599 } } }],
    ["hackertarget", '"198.51.100.1","64501","203.0.113.0/24","Example"'],
  ]) {
    const record = normalize(id, payload);
    assert.equal(record.voteEligible, false, id);
    assert.equal(record.state, "path_mismatch", id);
  }
  const differentOrigin = normalize("ripe-network", { data: { asns: [64599], prefix: "203.0.113.0/24" } });
  assert.equal(differentOrigin.voteEligible, true, "真实目标 IP 的不同路由起源应保留，不能丢弃不利证据");
  const input = overviewInput();
  input.families[0].routes = [differentOrigin];
  const assessment = core.assessOverview(input);
  assert.equal(assessment.needsReview, true);
  assert.match(assessment.reasons.join("；"), /路由.*ASN/);
  const multiOrigin = normalize("ripe-network", { data: { asns: [64599, 64501], prefix: "203.0.113.0/24" } });
  assert.deepEqual(multiOrigin.asns, ["AS64599", "AS64501"]);
  input.families[0].routes = [multiOrigin];
  assert.equal(core.assessRoutes(input.families).conflicts.length, 0, "多起源包含基准时不能误报排他性冲突");
  assert.equal(core.assessRoutes(input.families).multiOrigin.length, 1);
});

test("未知地区与请求失败不计字段冲突，DNS 未知不显示一致", () => {
  assert.equal(core.compareIntel({ ...good(), state: "network_error", voteEligible: false }, { countryCode: "CA" }).conflicts.length, 0);
  assert.equal(core.compareIntel(good(), {}).comparable, 0);
  assert.equal(core.compareIntel(good(), { countryCode: "CA" }).conflicts.length, 1);
  const families = overviewInput().families;
  assert.equal(core.assessDns({ state: "success", records: [{ observedIp: ip }] }, families).missing, true);
  assert.equal(core.assessDns({ state: "success", records: [{ observedIp: ip, countryCode: "US" }] }, []).missing, true);
  const dual = families.concat({ country: { value: "CA" } });
  assert.equal(core.assessDns({ state: "success", records: [{ observedIp: ip, countryCode: "CA" }] }, dual).mismatch, false);
});

test("路由缺失与非法前缀不计有效，多起源的共同 ASN 不误报", () => {
  const normalize = (id, payload, targetIp = ipv6) => evidence.normalizeRoutePayload(evidence.ROUTE_SOURCES.find(item => item.id === id), payload, { targetIp, asn: "AS64501" });
  for (const prefix of ["2001:db8::/abc", "2001:db8::", "2001:db8::/129", "2001:db8::/1.5", "203.0.113.0/24"]) {
    assert.equal(normalize("ripe-network", { data: { asns: [64501], prefix } }).voteEligible, false, prefix);
  }
  for (const [id, payload] of [
    ["rir-rdap", { name: "No range" }], ["peeringdb", { data: [{ name: "No ASN" }] }],
    ["ripe-announced", { data: { resource: "AS64501", prefixes: [{ prefix: "203.0.113.0/24" }] } }],
    ["ripe-network", { data: { asns: [64501] } }],
  ]) assert.equal(normalize(id, payload).voteEligible, false, id);
  assert.equal(normalize("rir-rdap", { startAddress: "2001:db8::", endAddress: "2001:db8::ffff" }).voteEligible, true);
  assert.equal(normalize("rir-rdap", { startAddress: "not-ip", endAddress: ipv6 }).voteEligible, false);
  const announced = normalize("ripe-announced", { data: { resource: "AS64501", prefixes: [{ prefix: "203.0.113.0/24" }, { prefix: "2001:db8::/32" }] } });
  assert.equal(announced.prefix, "2001:db8::/32");
  const input = overviewInput();
  input.families[0].routes = [announced];
  assert.equal(core.assessOverview(input).dimensions.find(item => item.id === "routes").assessedWeight, 0, "ASN 附属资料不能替代目标 IP 的路由起源，但不阻断其他维度评分");
  input.families[0].routes = [{ ...good(), asns: ["AS64599", "AS64501"] }, { ...good("second"), asns: ["AS64501"] }];
  assert.equal(core.assessRoutes(input.families).conflicts.length, 0);
  input.families[0].routes[1].asns = ["AS64588"];
  assert.equal(core.assessRoutes(input.families).conflicts.length, 2);
});

test("候选 SDP 只读取候选地址，不能把 raddr 当成公网候选", async () => {
  const addresses = [
    { candidate: "candidate:1 1 udp 123 host.local 1234 typ host raddr 8.8.8.8 rport 12" },
    { candidate: "candidate:2 1 udp 123 2606:4700::1111 1234 typ host" },
  ];
  const record = await evidence.probeStunNode(evidence.STUN_NODES[0], { createPeerConnection: () => fakePeer({ addresses }) });
  assert.deepEqual(record.observedIps, ["2606:4700::1111"]);
});

test("禁用持久存储时本页仍记住确认，异常或过远的时间戳不自动授权", () => {
  const blocked = { get localStorage() { throw new Error("disabled"); }, get document() { throw new Error("disabled"); } };
  const gate = core.createConfirmationPolicy({ scope: blocked });
  assert.equal(gate.shouldPrompt(), true);
  gate.remember();
  assert.equal(gate.shouldPrompt(), false);
  for (const value of ["NaN", "Infinity", String(Date.now() + 999999999)]) {
    const scope = { localStorage: { getItem: () => value }, document: { cookie: "" } };
    assert.equal(core.createConfirmationPolicy({ scope }).shouldPrompt(), true);
  }
});

test("新版只保存明确确认的 12 小时许可，忽略旧弹窗展示时间戳", () => {
  const values = new Map([["aisg-star-prompt-until", String(Date.now() + 43200000)]]);
  const scope = { localStorage: { getItem: key => values.get(key), setItem: (key, value) => values.set(key, value) }, document: { cookie: "" }, location: { protocol: "https:" } };
  let now = 1000;
  const gate = core.createConfirmationPolicy({ scope, now: () => now });
  assert.equal(gate.shouldPrompt(), true);
  gate.remember();
  assert.equal(gate.shouldPrompt(), false);
  assert.equal(core.createConfirmationPolicy({ scope, now: () => now }).shouldPrompt(), false);
  now += 43200001;
  assert.equal(gate.shouldPrompt(), true);
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
  assert.equal(core.assessOverview(sparse).dimensions.find(item => item.id === "dns").assessedWeight, 0);
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
