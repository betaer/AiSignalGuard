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
  const servedPath = pathname === "/" || pathname === "/index.html"
    ? "/index.html"
    : pathname === "/v2/"
      ? "/v2/index.html"
      : pathname;
  const file = resolve(projectRoot, `.${servedPath}`);
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

await new Promise((resolveListen, rejectListen) => {
  server.once("error", rejectListen);
  server.listen(0, "127.0.0.1", resolveListen);
});

const baseUrl = `http://127.0.0.1:${server.address().port}`;
let browser;

async function createContext() {
  const context = await browser.newContext();
  const externalRequests = [];
  await context.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.hostname === "127.0.0.1") {
      await route.continue();
      return;
    }
    externalRequests.push(url.href);
    if (url.hostname === "github.com") {
      await route.fulfill({
        status: 200,
        contentType: "text/html; charset=utf-8",
        body: "<!doctype html><title>GitHub repository</title>",
      });
      return;
    }
    await route.abort("failed");
  });
  return { context, externalRequests };
}

async function assertInitialGate(pathname) {
  const { context, externalRequests } = await createContext();
  try {
    const page = await context.newPage();
    await page.goto(`${baseUrl}${pathname}`, { waitUntil: "domcontentloaded" });
    const dialog = page.locator("#star-support-dialog");
    await dialog.waitFor({ state: "visible" });
    await page.waitForTimeout(250);
    assert.equal(externalRequests.length, 0, `${pathname} 弹窗确认前不应发起第三方检测请求`);
    assert.equal(await page.locator("#audio-fingerprint-runs > li").count(), 0, `${pathname} 弹窗确认前不应运行 WebAudio`);
    assert.equal(
      await page.locator('[data-fingerprint-value="v3"]').textContent(),
      "等待检测",
      `${pathname} 弹窗确认前不应计算浏览器摘要`,
    );

    await page.locator("#star-support-continue").click();
    await dialog.waitFor({ state: "hidden" });
    await page.waitForFunction(() => document.querySelector("#floating-recheck")?.disabled === true);
    await page.waitForFunction(() => document.querySelectorAll("#audio-fingerprint-runs > li").length > 0);
    await page.waitForFunction(
      () => document.querySelector('[data-fingerprint-value="v3"]')?.textContent !== "等待检测",
    );
    await page.waitForFunction(() => performance.getEntriesByType("resource").length > 0);
    assert.ok(externalRequests.length > 0, `${pathname} 点击“先测试”后应开始第三方检测`);

    const requestsBeforeRefresh = externalRequests.length;
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.waitForTimeout(100);
    assert.equal(await dialog.isVisible(), false, `${pathname} 12 小时内刷新不应再次弹窗`);
    await page.waitForFunction(() => document.querySelector("#floating-recheck")?.disabled === true);
    await page.waitForFunction(() => document.querySelectorAll("#audio-fingerprint-runs > li").length > 0);
    assert.ok(externalRequests.length > requestsBeforeRefresh, `${pathname} 12 小时内刷新应直接检测`);

    if (pathname === "/") {
      await page.waitForFunction(() => document.querySelector("#floating-recheck")?.disabled === false, null, { timeout: 15000 });
      const requestsBeforeRecheck = externalRequests.length;
      await page.locator("#floating-recheck").click();
      await page.waitForFunction(() => document.querySelector("#floating-recheck")?.disabled === true);
      assert.equal(await dialog.isVisible(), false, "12 小时内点击右下角重测不应再次弹窗");
      assert.equal(await page.locator("#recheck-loading").isVisible(), true, "重测应显示当前检测进度");
      assert.ok(externalRequests.length > requestsBeforeRecheck, "重测应立即启动新一轮检测");
    }
  } finally {
    await context.close();
  }
}

async function assertStarAndCloseFlows() {
  const starFlow = await createContext();
  try {
    const page = await starFlow.context.newPage();
    await page.goto(`${baseUrl}/`, { waitUntil: "domcontentloaded" });
    await page.locator("#star-support-dialog").waitFor({ state: "visible" });
    const popupPromise = page.waitForEvent("popup");
    await page.locator("#star-support-github").click();
    const popup = await popupPromise;
    await popup.waitForLoadState("domcontentloaded").catch(() => {});
    assert.match(popup.url(), /^https:\/\/github\.com\/betaer\/AiSignalGuard\/?/);
    await page.waitForFunction(() => document.querySelector("#floating-recheck")?.disabled === true);
    assert.ok(starFlow.externalRequests.length > 0, "点击 Star 后当前页应同步开始检测");
  } finally {
    await starFlow.context.close();
  }

  const closeFlow = await createContext();
  try {
    const page = await closeFlow.context.newPage();
    await page.goto(`${baseUrl}/v2/`, { waitUntil: "domcontentloaded" });
    await page.locator("#star-support-dialog").waitFor({ state: "visible" });
    await page.locator("#star-support-close").click();
    await page.waitForTimeout(250);
    assert.equal(closeFlow.externalRequests.length, 0, "关闭首次弹窗不应启动检测");
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.waitForTimeout(100);
    assert.equal(await page.locator("#star-support-dialog").isVisible(), false, "关闭后 12 小时内刷新不应再次打扰");
    await page.waitForFunction(() => document.querySelector("#floating-recheck")?.disabled === true);
    assert.ok(closeFlow.externalRequests.length > 0, "关闭后的刷新应直接开始检测");
  } finally {
    await closeFlow.context.close();
  }
}

try {
  browser = await chromium.launch({ headless: true });
  await assertInitialGate("/");
  await assertInitialGate("/v2/");
  await assertStarAndCloseFlows();
  console.log("最新版首次 Star 闸门、刷新抑制与新窗口流程通过。");
} finally {
  await browser?.close().catch(() => {});
  await new Promise((resolveClose) => server.close(resolveClose));
}
