import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const tools = ["ip", "dns", "stun", "cdn", "split", "multi", "latency"];
const coreIds = ["position-consistency", "asn-organization", "geo-cross-check", "exit-ip-quality", "network-type", "risk-proxy-labels", "system-timezone", "browser-language", "emoji-rendering", "chinese-fonts", "dns-leak", "dns-region-consistency", "webrtc-leak", "stun-nodes", "majority-region", "conflict-check", "network-label-consensus", "ip-intel-sources", "route-registry-sources"];
const html = await readFile(new URL("../index-ipcx-remix-v1.3.0.html", import.meta.url), "utf8");
const controller = await readFile(new URL("../ipcx-remix-v1.3.0.js", import.meta.url), "utf8");

test("v1.3.0 页面与控制器版本化注册", () => {
  assert.match(html, /data-remix-version=["\x271.3.0\x27"]/);
  assert.match(html, /ipcx-remix-v1\.3\.0\.js/);
  assert.match(controller, /REMIX_DEFAULT_ROUTE/);
});

test("首页必须声明全部 19 项结果镜像", () => {
  const refs = [...html.matchAll(/data-core-result-ref=["\x27"]([^"\x27]+)["\x27"]/g)].map((match) => match[1]);
  assert.equal(refs.length, 19, "首页必须有 19 个可见结果镜像");
  assert.deepEqual([...new Set(refs)].sort(), [...coreIds].sort());
  assert.match(html, /data-overview-result-list=["\x27"]core["\x27"]/);
});

test("七个工具详情必须各有结构化明细列表", () => {
  for (const tool of tools) {
    assert.match(html, new RegExp(`data-tool-result-list=["\x27"]${tool}["\x27"]`), `${tool} 缺少结果列表容器`);
    const view = html.slice(html.indexOf(`data-remix-view="tool-${tool}"`));
    assert.match(view, /data-probe-id=/, `${tool} 缺少逐项探针 ID`);
    assert.match(view, /data-probe-name(?:=|\s|>)/, `${tool} 缺少逐项探针名称`);
    assert.match(view, /data-probe-state=/, `${tool} 缺少逐项状态`);
    assert.match(view, /data-probe-evidence(?:=|\s|>)/, `${tool} 缺少逐项证据`);
  }
});

test("工具状态只能使用真实终态枚举", () => {
  const states = [...html.matchAll(/data-probe-state=["\x27"]([^"\x27]+)["\x27"]/g)].map((match) => match[1]);
  assert.ok(states.length >= 7, "每个工具至少应有一条列表项");
  for (const state of states) assert.ok(["success", "warning", "failed", "skipped", "requires-server"].includes(state), state);
});
