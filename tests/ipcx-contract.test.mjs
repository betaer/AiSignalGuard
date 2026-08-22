import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const projectRoot = new URL("../", import.meta.url);
const html = await readFile(new URL("index-ipcx-v1.3.0.html", projectRoot), "utf8");
const app = await readFile(new URL("ipcxApp.js", projectRoot), "utf8");
const semantics = await readFile(new URL("ipcxSemantics.js", projectRoot), "utf8");
const source = `${html}\n${app}\n${semantics}`;

test("IPCX 页面不再携带模拟网络结果", () => {
  assert.doesNotMatch(
    source,
    /38\.92\.27\.182|198\.51\.100\.|本地演示数据|本地模拟结果/,
  );
  assert.doesNotMatch(
    source,
    /(?:US\s*·\s*)?6\s*票|可用\s*·?\s*4\s*\/\s*4|可用\s*·?\s*2\s*\/\s*2|6\s*\/\s*8\s*节点/,
  );
  assert.doesNotMatch(
    html,
    /美国 · 洛杉矶|洛杉矶出口|住宅 \/ 移动网络|ISP · Mobile|多源结果一致|未发现明显泄漏|时区、语言不一致|0 项明确冲突|旗帜彩色|HeiTi \/ SongTi/,
    "初始 HTML 只能包含中性等待状态，不能在实时检测前预设结论",
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

test("来源标题按当前指标的真实字段计数，并公开实际请求数", () => {
  assert.match(app, /return item\.usable === true/);
  assert.match(app, /已请求 " \+ attempted \+ " \/ " \+ items\.length/);
  assert.match(app, /asnFieldCount/);
  assert.match(app, /typeFieldCount/);
  assert.match(app, /riskFieldCount/);
  assert.match(app, /routeSummary\.attempted/);
});

test("完全没有网络证据时不生成基础分或绿色泄漏结论", () => {
  assert.match(app, /var scoreAvailable = evidenceCount > 0/);
  assert.match(app, /scoreAvailable \? String\(score\) : "—"/);
  assert.match(app, /泄漏证据不足/);
  assert.match(app, /!webrtc\.successes\.length \|\| !state\.dns\.records\.length/);
});

test("总览、WebRTC 与浏览器信号组成连续报告，不再被顶部导航隐藏", () => {
  for (const target of ["overview-view", "webrtc-view", "fingerprint-view"]) {
    assert.match(html, new RegExp(`class="module-tab"[^>]+href="#${target}"`));
    assert.doesNotMatch(
      html,
      new RegExp(`<section[^>]+id="${target}"[^>]+hidden`),
      `${target} 不应在初始页面被隐藏`,
    );
  }
  assert.doesNotMatch(app, /panel\.hidden\s*=/);
  assert.match(app, /nearBottom[\s\S]*activePanel\s*=\s*panels\[panels\.length\s*-\s*1\]/);
});

test("实时结果改变页面高度时，模块锚点会自动校正且允许用户中断", () => {
  assert.match(app, /function beginSectionNavigationAlignment\(/);
  assert.match(app, /new ResizeObserver\(/);
  assert.match(app, /event\.preventDefault\(\)/);
  assert.match(app, /\["wheel",\s*"touchstart",\s*"pointerdown"\]/);
  assert.match(app, /scrollBehavior\s*=\s*"auto"/);
  assert.match(app, /location\.hash/);
  assert.match(app, /"hashchange"/);
  assert.match(app, /"popstate"/);
});

test("一级分组默认展开，二级指标默认收起并使用紧凑解释气泡", () => {
  assert.match(app, /function prepareSignalRows\(/);
  assert.match(app, /row\.open\s*=\s*false/);
  assert.doesNotMatch(source, /row-explanation/);
  assert.match(source, /row-help-tip/);
  assert.match(source, /证据说明/);
  assert.match(source, /建议/);
});

test("重要结果完整换行显示，并覆盖桌面、平板与窄屏断点", () => {
  assert.match(html, /viewport-fit=cover/);
  assert.match(html, /--content-max:/);
  assert.match(html, /@media \(max-width: 960px\)/);
  assert.match(html, /@media \(max-width: 480px\)/);
  assert.match(html, /--safe-top:\s*env\(safe-area-inset-top/);
  assert.match(html, /--safe-left:\s*env\(safe-area-inset-left/);
  assert.match(html, /\.demo-header\s*\{[^}]*var\(--safe-top\)/s);
  assert.match(html, /\.page-shell\s*\{[^}]*var\(--safe-left\)/s);
  assert.match(html, /\.data-value\s*\{[^}]*overflow-wrap:\s*anywhere/s);
  assert.doesNotMatch(html, /\.data-value\s*\{[^}]*text-overflow:\s*ellipsis/s);
  assert.doesNotMatch(html, /\.signal-row-title small\s*\{[^}]*text-overflow:\s*ellipsis/s);
});

test("三类浏览器摘要同时可见且 JA3 / JA4 不伪造", () => {
  assert.equal(
    (html.match(/<article class="fingerprint-card" data-fingerprint-card=/g) || []).length,
    3,
  );
  assert.doesNotMatch(html, /class="fingerprint-tabs"/);
  assert.match(app, /\[data-fingerprint-value\]/);
  assert.match(app, /普通网页脚本无法直接读取 TLS ClientHello/);
});

test("低频术语使用键盘和触控均可操作的说明气泡", () => {
  assert.match(html, /class="info-tip"/);
  assert.match(html, /<summary[^>]+aria-label="网络参考分说明"/);
  assert.match(app, /function makeInfoTip\(/);
  assert.match(app, /function positionInfoTip\(/);
  assert.match(app, /有效表示当前指标拥有可参与判断的字段/);
  assert.match(html, /\.info-tip > summary\s*\{[^}]*width:\s*24px;[^}]*height:\s*24px;/s);
  assert.match(html, /\.info-tip-bubble\s*\{[^}]*position:\s*fixed;/s);
  assert.match(html, /\.info-tip:hover\s*>\s*\.info-tip-bubble/);
  assert.match(html, /summary:focus-visible\s*\+\s*\.info-tip-bubble/);
  assert.doesNotMatch(html, /\.info-tip\[open\]\s*>\s*\.info-tip-bubble/);
});

test("二级列表边界不露出空白圆角，行内说明气泡独立于列表裁切", () => {
  assert.match(html, /\.signal-subsection-rows\s*\{[^}]*overflow:\s*hidden;[^}]*border-radius:\s*0;/s);
  assert.match(html, /\.row-help-bubble\s*\{[^}]*position:\s*absolute;/s);
  assert.match(app, /function positionRowHelpTip\(/);
  assert.match(html, /\.row-help-tip:hover\s*>\s*\.row-help-bubble/);
  assert.match(html, /summary:focus-visible\s*\+\s*\.row-help-bubble/);
  assert.doesNotMatch(html, /\.row-help-tip\[open\]\s*>\s*\.row-help-bubble/);
});

test("WebRTC 明细页的页头状态会绑定最终评估", () => {
  assert.match(html, /id="webrtc-panel-status"[^>]*>检测中</);
  assert.match(app, /function updateWebrtcPanel\(/);
  assert.match(app, /webrtc-panel-status/);
});

test("实时证据更新复用现有 DOM，不打断气泡和键盘焦点", () => {
  assert.match(app, /function updateEvidenceSection\(/);
  assert.doesNotMatch(app, /body\.querySelector\(":scope > \.metric-evidence"\)\?\.remove\(\)/);
  assert.doesNotMatch(app, /host\.replaceChildren\(buildEvidenceSection/);
});

test("移动端阅读明细时工具栏向下滚动自动让位", () => {
  assert.match(html, /\.floating-tool-dock\[data-reading="true"\]/);
  assert.match(html, /\.floating-tool-dock\[data-reading="true"\]:focus-within/);
  assert.match(app, /currentY\s*>\s*lastScrollY\s*\+\s*8/);
  assert.match(app, /dock\.dataset\.reading/);
});
