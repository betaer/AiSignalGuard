import assert from "node:assert/strict";
import test from "node:test";

await import("../ipcxSemantics.js");
const semantics = globalThis.AISGIpSemantics;

test("组织名称归一化只消除标点和空白差异", () => {
  assert.equal(
    semantics.normalizeOrganization("FiberState LLC"),
    semantics.normalizeOrganization("FiberState, LLC"),
  );
  assert.notEqual(
    semantics.normalizeOrganization("FiberState LLC"),
    semantics.normalizeOrganization("FiberState Networks LLC"),
  );
});

test("缺失字段不构成冲突", () => {
  assert.deepEqual(
    semantics.compareComparableFields(
      { countryCode: "US", asn: null, organization: null },
      { countryCode: "US", asn: "AS26042", organization: "FiberState LLC" },
    ),
    { comparable: 1, missing: 2, conflicts: [] },
  );
});

test("组织逗号差异不构成冲突，真实组织差异才构成冲突", () => {
  assert.deepEqual(
    semantics.compareComparableFields(
      { countryCode: "US", asn: "AS26042", organization: "FiberState LLC" },
      { countryCode: "US", asn: "AS26042", organization: "FiberState, LLC" },
    ),
    { comparable: 3, missing: 0, conflicts: [] },
  );
  assert.deepEqual(
    semantics.compareComparableFields(
      { countryCode: "US", asn: "AS26042", organization: "FiberState LLC" },
      { countryCode: "US", asn: "AS64501", organization: "Other Transit LLC" },
    ),
    { comparable: 3, missing: 0, conflicts: ["ASN", "组织"] },
  );
});

test("地理投票 7 / 10 按有效票通过，城市不同不影响国家通过", () => {
  assert.deepEqual(
    semantics.evaluateMajority({ US: 7, CA: 2, GB: 1 }),
    { tone: "good", label: "基本一致", winner: "US", votes: 7, eligible: 10 },
  );
  assert.equal(semantics.evaluateMajority({ US: 5, CA: 4, GB: 1 }).tone, "warn");
  assert.equal(semantics.evaluateMajority({ US: 1, CA: 1, GB: 0 }).tone, "neutral");
});

test("STUN 注册表只保留一个 Google 节点并覆盖十家服务方", async () => {
  await import("../ipcxEvidence.js");
  const providers = globalThis.AISGIpEvidence.STUN_NODES.map(({ name }) => name);
  assert.equal(providers.length, 10);
  assert.equal(providers.filter((name) => /^Google/.test(name)).length, 1);
  assert.equal(new Set(providers).size, 10);
  for (const name of ["Cloudflare", "Twilio", "Metered", "Nextcloud", "Linphone", "Stuntman"]) {
    assert.ok(providers.includes(name), `${name} 必须保留为真实 STUN 来源`);
  }
});
