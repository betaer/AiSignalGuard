import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const projectRoot = new URL("../", import.meta.url);
const html = await readFile(new URL("index-ipcx.html", projectRoot), "utf8");
const app = await readFile(new URL("ipcxApp.js", projectRoot), "utf8");
const source = `${html}\n${app}`;

test("IPCX 页面不再携带模拟网络结果", () => {
  assert.doesNotMatch(
    source,
    /38\.92\.27\.182|198\.51\.100\.|本地演示数据|本地模拟结果/,
  );
  assert.doesNotMatch(
    source,
    /(?:US\s*·\s*)?6\s*票|可用\s*·?\s*4\s*\/\s*4|可用\s*·?\s*2\s*\/\s*2|6\s*\/\s*8\s*节点/,
  );
});

test("IPCX 页面由统一的十源证据模块驱动", () => {
  assert.match(html, /<script\s+src="ipcxEvidence\.js"><\/script>/);

  for (const [rowId, evidenceSet] of [
    ["asn-organization", "asnOrganization"],
    ["geo-cross-check", "geoVotes"],
    ["majority-region", "geoVotes"],
    ["conflict-check", "conflictSources"],
    ["ip-intel-sources", "ipIntelSources"],
    ["route-registry-sources", "routeSources"],
  ]) {
    assert.match(
      app,
      new RegExp(
        `id:\\s*"${rowId}"[\\s\\S]*?evidenceSet:\\s*"${evidenceSet}"`,
      ),
      `${rowId} 应映射到 ${evidenceSet}`,
    );
  }

  assert.match(app, /IP_INTEL_SOURCES/);
  assert.match(app, /ROUTE_SOURCES/);
  assert.match(app, /STUN_NODES/);
});

test("所有二级详情的四边留白保持一致", () => {
  assert.match(
    html,
    /\.signal-row-body\s*\{[^}]*padding:\s*12px 14px 14px;/s,
  );
  assert.doesNotMatch(html, /padding:\s*12px 14px 14px 33px/);
});

test("回到顶部只在滚动超过一个视口后可用", () => {
  assert.match(app, /window\.scrollY\s*>=\s*window\.innerHeight/);
  assert.match(app, /setAttribute\("aria-hidden"/);
  assert.match(app, /floatingTop\.tabIndex\s*=/);
  assert.match(html, /#floating-top\[data-visible="false"\]/);
});

test("AI 诊断复制内容包含产品名称与公开链接", () => {
  assert.match(
    app,
    /"AI Signal Guard",\s*"https:\/\/betaer\.github\.io\/AiSignalGuard\/"/,
  );
});
