// IPCX 真实浏览器回归：覆盖响应式布局、气泡可见性、焦点稳定性和 Hash 导航。
// 运行：npm run test:ipcx-ui
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
};

const server = createServer(async (request, response) => {
  const pathname = decodeURIComponent(new URL(request.url, "http://localhost/").pathname);
  const file = resolve(projectRoot, `.${pathname === "/" ? "/index-ipcx-v1.3.0.html" : pathname}`);
  if (!file.startsWith(`${projectRoot.replace(/\/$/, "")}${sep}`)) {
    response.writeHead(403).end();
    return;
  }
  try {
    const body = await readFile(file);
    response.writeHead(200, {
      "Cache-Control": "no-store",
      "Content-Type": mimeTypes[extname(file).toLowerCase()] || "application/octet-stream",
    });
    response.end(body);
  } catch {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" }).end("Not Found");
  }
});

await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
const baseUrl = `http://127.0.0.1:${server.address().port}/index-ipcx-v1.3.0.html`;
let browser;

try {
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  await context.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.hostname === "127.0.0.1") {
      await route.continue();
      return;
    }
    // 给首轮实时渲染留出窗口，以验证更新期间不会替换已聚焦的气泡节点。
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 450));
    await route.abort("failed");
  });

  const page = await context.newPage();
  await page.setViewportSize({ width: 1200, height: 800 });
  await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
  const starContinue = page.locator("#star-support-continue");
  if (await starContinue.isVisible().catch(() => false)) await starContinue.click();
  await page.locator('.signal-row[data-row-id="exit-ip-quality"] > summary').click();
  const firstTip = page.locator('.signal-row[data-row-id="exit-ip-quality"] .metric-evidence .info-tip').first();
  await firstTip.locator("summary").waitFor({ state: "visible" });
  await firstTip.locator("summary").hover();
  const visibleInfoBubble = await firstTip.locator(".info-tip-bubble").evaluate((node) => {
    const style = getComputedStyle(node);
    const rect = node.getBoundingClientRect();
    const clippingAncestors = [".metric-evidence", ".signal-subsection-rows", ".signal-group", ".result-card"]
      .map((selector) => node.closest(selector))
      .filter(Boolean)
      .filter((ancestor) => getComputedStyle(ancestor).overflow !== "visible")
      .map((ancestor) => ancestor.className);
    return {
      x: rect.x,
      y: rect.y,
      width: rect.width,
      height: rect.height,
      opacity: style.opacity,
      visibility: style.visibility,
      pointerEvents: style.pointerEvents,
      clippingAncestors,
    };
  });
  assert.equal(visibleInfoBubble.opacity, "1", "桌面悬停信息按钮应直接显示气泡");
  assert.equal(visibleInfoBubble.visibility, "visible", "桌面悬停信息按钮气泡应可见");
  assert.equal(visibleInfoBubble.pointerEvents, "none", "气泡不应接管鼠标，以便移出按钮后立即隐藏");
  assert.deepEqual(visibleInfoBubble.clippingAncestors, [], "信息气泡不应被父级圆角容器裁切");
  assert.ok(
    visibleInfoBubble.x >= 0 && visibleInfoBubble.y >= 0 &&
      visibleInfoBubble.x + visibleInfoBubble.width <= 1200 && visibleInfoBubble.y + visibleInfoBubble.height <= 800,
    "桌面悬停信息气泡应完整位于视口内",
  );
  await page.mouse.move(18, 18);
  await page.waitForTimeout(180);
  const hoverBubbleState = await firstTip.locator(".info-tip-bubble").evaluate((node) => {
    const style = getComputedStyle(node);
    return { opacity: style.opacity, visibility: style.visibility, pointerEvents: style.pointerEvents };
  });
  assert.deepEqual(
    hoverBubbleState,
    { opacity: "0", visibility: "hidden", pointerEvents: "none" },
    "鼠标移出信息按钮后气泡应立即隐藏",
  );
  await firstTip.locator("summary").hover();
  await firstTip.locator("summary").click();
  assert.equal(await firstTip.evaluate((node) => node.open), false, "鼠标点击信息按钮不应固定展开气泡");
  await firstTip.locator("summary").press("Enter");
  await firstTip.locator("summary").focus();
  await firstTip.evaluate((node) => { window.__aisgFocusedTip = node; });

  const bubble = await firstTip.locator(".info-tip-bubble").boundingBox();
  assert.ok(bubble, "桌面信息气泡应可见");
  assert.ok(bubble.width >= 240 && bubble.height >= 40, "桌面信息气泡不应被容器裁切");
  assert.ok(
    bubble.x >= 0 && bubble.y >= 0 && bubble.x + bubble.width <= 1200 && bubble.y + bubble.height <= 800,
    "桌面信息气泡应完整位于视口内",
  );

  await page.waitForTimeout(900);
  await page.waitForFunction(
    () => document.querySelector("#webrtc-panel-status")?.textContent.trim() !== "检测中",
    null,
    { timeout: 6000 },
  );
  assert.notEqual(
    await page.locator("#webrtc-panel-status").textContent(),
    "检测中",
    "WebRTC 检测结束后页头状态不能停留在检测中",
  );
  const focusState = await page.evaluate(() => ({
    connected: window.__aisgFocusedTip?.isConnected === true,
    sameNode: window.__aisgFocusedTip === document.querySelector('.signal-row[data-row-id="exit-ip-quality"] .metric-evidence .info-tip'),
    open: window.__aisgFocusedTip?.open === true,
    focused: document.activeElement === window.__aisgFocusedTip?.querySelector("summary"),
  }));
  assert.deepEqual(
    focusState,
    { connected: true, sameNode: true, open: true, focused: true },
    "实时来源更新不应关闭气泡、替换节点或夺走键盘焦点",
  );

  await page.locator('.signal-row[data-row-id="exit-ip-quality"] > summary').click();

  await page.setViewportSize({ width: 390, height: 844 });
  await page.locator('.signal-row[data-row-id="position-consistency"] > summary').click();
  const rowHelp = page.locator('.signal-row[data-row-id="position-consistency"] .row-help-tip').first();
  await rowHelp.scrollIntoViewIfNeeded();
  await rowHelp.locator("summary").hover();
  const rowHelpBubble = await rowHelp.locator(".row-help-bubble").evaluate((node) => {
    const style = getComputedStyle(node);
    const rect = node.getBoundingClientRect();
    const clippingAncestors = [".signal-subsection-rows", ".signal-group"]
      .map((selector) => node.closest(selector))
      .filter(Boolean)
      .filter((ancestor) => getComputedStyle(ancestor).overflow !== "visible")
      .map((ancestor) => ancestor.className);
    return {
      x: rect.x,
      y: rect.y,
      width: rect.width,
      height: rect.height,
      opacity: style.opacity,
      visibility: style.visibility,
      pointerEvents: style.pointerEvents,
      clippingAncestors,
    };
  });
  assert.equal(rowHelpBubble.opacity, "1", "移动端悬停行内说明应直接显示气泡");
  assert.equal(rowHelpBubble.visibility, "visible", "移动端悬停行内说明应直接可见");
  assert.equal(rowHelpBubble.pointerEvents, "none", "行内气泡不应接管鼠标事件");
  assert.deepEqual(rowHelpBubble.clippingAncestors, [], "行内说明气泡不应被父级圆角容器裁切");
  assert.ok(
    rowHelpBubble.x >= 0 && rowHelpBubble.y >= 0 &&
      rowHelpBubble.x + rowHelpBubble.width <= 390 && rowHelpBubble.y + rowHelpBubble.height <= 844,
    "移动端行内说明气泡不应被二级列表或视口裁切",
  );
  await rowHelp.locator("summary").click();
  assert.equal(await rowHelp.evaluate((node) => node.open), false, "鼠标点击说明胶囊不应触发展开状态");
  await page.mouse.move(18, 18);
  await page.waitForTimeout(180);
  const rowHoverState = await rowHelp.locator(".row-help-bubble").evaluate((node) => {
    const style = getComputedStyle(node);
    return { opacity: style.opacity, visibility: style.visibility, pointerEvents: style.pointerEvents };
  });
  assert.deepEqual(
    rowHoverState,
    { opacity: "0", visibility: "hidden", pointerEvents: "none" },
    "鼠标移出行内说明后气泡应立即隐藏",
  );
  await page.locator('.signal-row[data-row-id="position-consistency"] > summary').click();

  for (const viewport of [
    { width: 320, height: 700 },
    { width: 390, height: 844 },
    { width: 768, height: 900 },
    { width: 1440, height: 1000 },
  ]) {
    await page.setViewportSize(viewport);
    const layout = await page.evaluate(() => ({
      pageOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      navOverflow: document.querySelector(".module-tabs").scrollWidth - document.querySelector(".module-tabs").clientWidth,
      panelsVisible: Array.from(document.querySelectorAll("[data-panel]")).every(
        (node) => !node.hidden && getComputedStyle(node).display !== "none",
      ),
      openEvidence: Array.from(document.querySelectorAll(".signal-row")).filter((node) => node.open).length,
      openHelpTips: Array.from(document.querySelectorAll(".row-help-tip")).filter((node) => node.open).length,
    }));
    assert.equal(layout.pageOverflow, 0, `${viewport.width}px 页面不应横向溢出`);
    assert.equal(layout.navOverflow, 0, `${viewport.width}px 模块导航不应横向溢出`);
    assert.equal(layout.panelsVisible, true, `${viewport.width}px 三个主模块应同时可见`);
    assert.equal(layout.openEvidence, 0, `${viewport.width}px 二级指标应默认收起`);
    assert.equal(layout.openHelpTips, 0, `${viewport.width}px 说明气泡应默认收起`);
  }

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${baseUrl}#fingerprint-view`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(700);
  const directHash = await page.evaluate(() => ({
    current: document.querySelector('.module-tab[aria-current="true"]')?.getAttribute("href"),
    top: document.querySelector("#fingerprint-view").getBoundingClientRect().top,
  }));
  assert.equal(directHash.current, "#fingerprint-view", "Hash 直达时应高亮浏览器指纹导航");
  assert.ok(directHash.top >= 90 && directHash.top <= 180, "Hash 直达后目标应紧贴吸顶导航下方");

  await page.getByRole("link", { name: "总览" }).click();
  await page.getByRole("link", { name: "浏览器指纹" }).click();
  await page.waitForTimeout(350);
  const clickedHash = await page.evaluate(() => ({
    current: document.querySelector('.module-tab[aria-current="true"]')?.getAttribute("href"),
    top: document.querySelector("#fingerprint-view").getBoundingClientRect().top,
  }));
  assert.equal(clickedHash.current, "#fingerprint-view", "检测期间点击导航应立即保持正确高亮");
  assert.ok(clickedHash.top >= 90 && clickedHash.top <= 180, "检测期间点击导航应快速定位到目标");

  console.log("PASS IPCX 真实浏览器布局、气泡、焦点与 Hash 导航回归");
  await context.close();
} finally {
  await browser?.close().catch(() => {});
  await new Promise((resolveClose) => server.close(resolveClose));
}
