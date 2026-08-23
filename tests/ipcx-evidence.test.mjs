import assert from "node:assert/strict";
import test from "node:test";

await import("../networkEvidence.js");

const api = globalThis.AISGIpEvidence;

test("三类实时来源注册表均为 10 个唯一成员", () => {
  assert.ok(api, "AISGIpEvidence 应挂载到 globalThis");

  for (const registry of [
    api.IP_INTEL_SOURCES,
    api.ROUTE_SOURCES,
    api.STUN_NODES,
  ]) {
    assert.equal(registry.length, 10);
    assert.equal(new Set(registry.map(({ id }) => id)).size, 10);
    assert.ok(registry.every(({ id, name }) => id && name));
  }

  assert.deepEqual(
    api.IP_INTEL_SOURCES.map(({ id }) => id),
    [
      "ipwho",
      "ipsb",
      "geojs",
      "dbip",
      "ipapiis",
      "ipinfo",
      "countryis",
      "iplocation",
      "freeipapi",
      "ipguide",
    ],
  );
});

test("IP 情报响应按各家真实字段规范化且不互相借值", () => {
  const ipwho = api.normalizeIntelPayload(
    "ipwho",
    {
      success: true,
      ip: "203.0.113.9",
      country_code: "US",
      country: "United States",
      city: "Seattle",
      connection: { asn: 64501, org: "Example Transit", type: "isp" },
      security: { proxy: false, hosting: false, tor: false },
    },
    { targetIp: "203.0.113.9" },
  );

  assert.equal(ipwho.state, "success");
  assert.equal(ipwho.countryCode, "US");
  assert.equal(ipwho.asn, "AS64501");
  assert.equal(ipwho.organization, "Example Transit");
  assert.equal(ipwho.proxy, false);

  const countryOnly = api.normalizeIntelPayload(
    "countryis",
    { ip: "203.0.113.9", country: "US" },
    { targetIp: "203.0.113.9" },
  );
  assert.equal(countryOnly.state, "partial");
  assert.equal(countryOnly.countryCode, "US");
  assert.equal(countryOnly.asn, null);
  assert.equal(countryOnly.organization, null);

  const mismatch = api.normalizeIntelPayload(
    "dbip",
    { ipAddress: "203.0.113.10", countryCode: "US" },
    { targetIp: "203.0.113.9" },
  );
  assert.equal(mismatch.state, "path_mismatch");
  assert.equal(mismatch.voteEligible, false);
});

test("来源统计保留失败项，票数只使用真实可用字段", () => {
  const records = api.createPendingRecords(api.IP_INTEL_SOURCES).map(
    (record, index) => {
      if (index < 6) {
        return {
          ...record,
          state: "success",
          attempted: true,
          voteEligible: true,
          countryCode: index === 5 ? "CA" : "US",
          asn: "AS64501",
          organization: "Example Transit",
        };
      }
      if (index === 6) {
        return {
          ...record,
          state: "partial",
          attempted: true,
          voteEligible: true,
          countryCode: "US",
        };
      }
      return { ...record, attempted: true, state: index === 7 ? "timeout" : "network_error" };
    },
  );

  const summary = api.summarizeSources(records);
  assert.deepEqual(summary, {
    total: 10,
    attempted: 10,
    responded: 7,
    usable: 7,
    complete: 6,
    partial: 1,
    failed: 3,
  });

  const country = api.computeCountryConsensus(records);
  assert.equal(country.value, "US");
  assert.equal(country.votes, 6);
  assert.equal(country.eligible, 7);
  assert.equal(country.conflicts, 1);
});

test("runIpIntel 对 10 家逐一请求并保留超时或限流状态", async () => {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    const sourceIndex = calls.length - 1;
    if (sourceIndex === 8) {
      return new Response("busy", { status: 429 });
    }
    return new Response(
      JSON.stringify({
        ip: "203.0.113.9",
        ipAddress: "203.0.113.9",
        country: sourceIndex === 6 ? "US" : "United States",
        country_code: "US",
        countryCode: "US",
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  };
  const snapshots = [];
  const records = await api.runIpIntel({
    targetIp: "203.0.113.9",
    fetchImpl,
    timeoutMs: 100,
    onUpdate(next) {
      snapshots.push(next);
    },
  });

  assert.equal(calls.length, 10);
  assert.ok(records.every(({ attempted }) => attempted));
  assert.equal(records.length, 10);
  assert.equal(records[8].state, "rate_limited");
  assert.ok(snapshots.length >= 11, "应先发送 pending，再增量发送每家结果");
  assert.ok(snapshots.every((snapshot) => snapshot.length === 10));
});

test("每个 STUN 节点使用独立 RTCPeerConnection，不借用其他节点候选", async () => {
  const iceServerUrls = [];

  function createPeerConnection(config) {
    const listeners = new Map();
    const url = config.iceServers[0].urls;
    iceServerUrls.push(url);
    return {
      addEventListener(name, listener) {
        listeners.set(name, listener);
      },
      removeEventListener() {},
      createDataChannel() {},
      async createOffer() {
        return { type: "offer", sdp: "" };
      },
      async setLocalDescription() {
        queueMicrotask(() => {
          listeners.get("icecandidate")?.({
            candidate: {
              type: "srflx",
              address: "203.0.113.9",
              candidate: "candidate:1 1 udp 1 203.0.113.9 40000 typ srflx",
            },
          });
        });
      },
      close() {},
    };
  }

  const records = await api.runStunNodes({
    createPeerConnection,
    timeoutMs: 100,
  });

  assert.equal(records.length, 10);
  assert.equal(iceServerUrls.length, 10);
  assert.equal(new Set(iceServerUrls).size, 10);
  assert.ok(records.every(({ state }) => state === "success"));
  assert.ok(records.every(({ observedIp }) => observedIp === "203.0.113.9"));
  assert.ok(records.every(({ attempted }) => attempted));
});

test("路由来源不会因 IPv6 路径编码或裸 ASN 文本丢失真实结果", async () => {
  const calls = [];
  const records = await api.runRouteEvidence({
    targetIp: "2606:4700:4700::1111",
    asn: "AS13335",
    timeoutMs: 100,
    concurrency: 10,
    fetchImpl: async (url) => {
      calls.push(url);
      if (url.includes("hackertarget")) {
        return new Response("13335 Cloudflare, Inc.", { status: 200 });
      }
      if (url.includes("rdap.org")) {
        return new Response(
          JSON.stringify({
            startAddress: "2606:4700::",
            endAddress: "2606:4700:ffff:ffff:ffff:ffff:ffff:ffff",
            name: "CLOUDFLARENET",
            handle: "NET6-2606-4700-1",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      return new Response(JSON.stringify({}), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  assert.ok(calls.some((url) => url.endsWith("/2606:4700:4700::1111")));
  assert.equal(records.find(({ id }) => id === "hackertarget").asn, "AS13335");
  assert.equal(
    records.find(({ id }) => id === "hackertarget").organization,
    "Cloudflare, Inc.",
  );
  assert.equal(records.find(({ id }) => id === "rir-rdap").state, "success");
  assert.equal(calls.length, 10);
});

test("路由证据会先用 IP 来源发现 ASN，再真正请求全部 10 个来源", async () => {
  const calls = [];
  const records = await api.runRouteEvidence({
    targetIp: "203.0.113.9",
    timeoutMs: 100,
    concurrency: 10,
    fetchImpl: async (url) => {
      calls.push(url);
      if (url.includes("network-info")) {
        return new Response(
          JSON.stringify({ data: { asns: [64501], prefix: "203.0.113.0/24" } }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url.includes("hackertarget")) {
        return new Response("64501 Example Transit", { status: 200 });
      }
      return new Response(JSON.stringify({}), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  assert.equal(calls.length, 10);
  assert.equal(new Set(calls).size, 10);
  assert.ok(calls.some((url) => url.includes("peeringdb.com/api/net?asn=64501")));
  assert.ok(calls.some((url) => url.includes("announced-prefixes") && url.includes("AS64501")));
  assert.ok(calls.some((url) => url.includes("asrank.caida.org") && url.endsWith("/64501")));
  assert.ok(records.every(({ attempted }) => attempted));
});

test("HackerTarget 的 IPv6 CSV 响应会保留 ASN、前缀与组织", async () => {
  const records = await api.runRouteEvidence({
    targetIp: "2606:4700:4700::1111",
    asn: "AS13335",
    timeoutMs: 100,
    concurrency: 10,
    fetchImpl: async (url) => {
      if (url.includes("hackertarget")) {
        return new Response(
          '"2606:4700:4700::1111","13335","2606:4700::/32","CLOUDFLARENET, US"',
          { status: 200 },
        );
      }
      return new Response(JSON.stringify({}), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });
  const record = records.find(({ id }) => id === "hackertarget");
  assert.equal(record.state, "success");
  assert.equal(record.asn, "AS13335");
  assert.equal(record.prefix, "2606:4700::/32");
  assert.equal(record.organization, "CLOUDFLARENET, US");
});
