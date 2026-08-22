// IPCX Remix v1.3.0 浏览器回归：主页结果索引、七个工具明细和 Hash 路由。
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const PAGE_FILE = "index-ipcx-remix-v1.3.0.html";
const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const rootPrefix = `${projectRoot.replace(/\/$/, "")}${sep}`;
const mimeTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
};

const server = createServer(async (request, response) => {
  const pathname = decodeURIComponent(new URL(request.url, "http://127.0.0.1/").pathname);
  const relativePath = pathname === "/" ? PAGE_FILE : pathname.replace(/^\/+/, "");
  const file = resolve(projectRoot, relativePath);
  if (!file.startsWith(rootPrefix)) {
    response.writeHead(403).end();
    return;
  }
  try {
    const body = await readFile(file);
    response.writeHead(200, { "Cache-Control": "no-store", "Content-Type": mimeTypes[extname(file).toLowerCase()] || "application/octet-stream" });
    response.end(body);
  } catch {
    response.writeHead(404).end("Not Found");
  }
});

await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
const baseUrl = `http://127.0.0.1:${server.address().port}/${PAGE_FILE}`;
let browser;

try {
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const pageErrors = [];
  const page = await context.newPage();
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await context.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.hostname === "127.0.0.1") return route.continue();
    return route.abort("failed");
  });

  await page.goto(`${baseUrl}#/overview`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(450);
  assert.equal(await page.locator('[data-remix-view="overview"]').isVisible(), true, "主页总览应可见");
  assert.equal(await page.locator("[data-core-result-ref]").count(), 19, "主页应显示 19 项核心结果");
  assert.ok((await page.locator("#overview-results-status").textContent()).includes("19"), "主页应显示结算计数");

  const tools = ["ip", "dns", "stun", "cdn", "split", "multi", "latency"];
  const allowedStates = new Set(["success", "warning", "failed", "skipped", "requires-server"]);
  for (const tool of tools) {
    await page.goto(`${baseUrl}#/tools/${tool}`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(180);
    const list = page.locator(`[data-tool-result-list="${tool}"]`);
    assert.equal(await list.isVisible(), true, `${tool} 明细列表应可见`);
    const cards = list.locator("[data-probe-id]");
    assert.ok(await cards.count() > 0, `${tool} 至少应显示一条明细`);
    for (const state of await cards.evaluateAll((nodes) => nodes.map((node) => node.dataset.probeState))) {
      assert.ok(allowedStates.has(state), `${tool} 出现未定义状态 ${state}`);
    }
    assert.ok(await cards.first().locator("[data-probe-name]").count(), `${tool} 缺少探针名称`);
    assert.ok(await cards.first().locator("[data-probe-evidence]").count(), `${tool} 缺少逐项证据`);
  }
  assert.deepEqual(pageErrors, [], `v1.3.0 页面不应抛出运行时错误：${pageErrors.join(" | ")}`);
  console.log("PASS IPCX Remix v1.3.0 主页结果与七工具明细浏览器回归");
  await context.close();
} finally {
  await browser?.close().catch(() => {});
  await new Promise((resolveClose) => server.close(resolveClose));
}
