// IPCX Remix v1.2.0 真实浏览器回归：路由、键盘、隐私、离线真实性、响应式与控制器覆盖率。
// 运行：node tests/ipcx-remix-v1.2.0-ui.e2e.mjs
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const PAGE_FILE = "index-ipcx-remix-v1.2.0.html";
const CONTROLLER_FILE = "ipcx-remix-v1.2.0.js";
const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const rootPrefix = `${projectRoot.replace(/\/$/, "")}${sep}`;
const resultRoutes = ["overview", "network", "leaks", "paths", "browser"];
const toolRoutes = ["ip", "dns", "stun", "cdn", "split", "multi", "latency"];
const viewports = [
  { width: 320, height: 700 },
  { width: 390, height: 844 },
  { width: 844, height: 390 },
  { width: 768, height: 900 },
  { width: 1200, height: 800 },
  { width: 1440, height: 1000 },
];
const mimeTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".webp": "image/webp",
};

const server = createServer(async (request, response) => {
  if (request.method !== "GET" && request.method !== "HEAD") {
    response.writeHead(405, { Allow: "GET, HEAD" }).end();
    return;
  }

  let pathname;
  try {
    pathname = decodeURIComponent(new URL(request.url, "http://127.0.0.1/").pathname);
  } catch {
    response.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" }).end("Bad Request");
    return;
  }

  const relativePath = pathname === "/" ? PAGE_FILE : pathname.replace(/^\/+/, "");
  const file = resolve(projectRoot, relativePath);
  if (!file.startsWith(rootPrefix)) {
    response.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" }).end("Forbidden");
    return;
  }

  try {
    const body = await readFile(file);
    response.writeHead(200, {
      "Cache-Control": "no-store",
      "Content-Type": mimeTypes[extname(file).toLowerCase()] || "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
    });
    response.end(request.method === "HEAD" ? undefined : body);
  } catch {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" }).end("Not Found");
  }
});

async function settleLayout(page) {
  await page.evaluate(() => new Promise((resolveFrame) => {
    requestAnimationFrame(() => requestAnimationFrame(resolveFrame));
  }));
}

async function waitForDetectionIdle(page) {
  const recheck = page.locator("#floating-recheck");
  await recheck.waitFor({ state: "visible" });
  await page.waitForFunction(() => {
    const button = document.querySelector("#floating-recheck");
    return Boolean(
      button &&
      !button.disabled &&
      button.getAttribute("aria-busy") !== "true" &&
      button.dataset.running !== "true",
    );
  }, undefined, { timeout: 15_000 });
  await settleLayout(page);
}

async function assertActiveView(page, viewName, expectedHash, options = {}) {
  const resultRoute = resultRoutes.includes(viewName) ? viewName : null;
  await page.waitForFunction(
    ({ name, hash }) => {
      const views = Array.from(document.querySelectorAll("[data-remix-view]"));
      const rendered = views.filter((view) => {
        const style = getComputedStyle(view);
        return !view.hidden && style.display !== "none" && style.visibility !== "hidden" && view.getClientRects().length > 0;
      });
      return (
        location.hash === hash &&
        rendered.length === 1 &&
        rendered[0].dataset.remixView === name
      );
    },
    { name: viewName, hash: expectedHash },
  );
  await settleLayout(page);

  const state = await page.evaluate(({ name, route }) => {
    const views = Array.from(document.querySelectorAll("[data-remix-view]"));
    const rendered = views.filter((view) => {
      const style = getComputedStyle(view);
      return !view.hidden && style.display !== "none" && style.visibility !== "hidden" && view.getClientRects().length > 0;
    });
    const active = rendered[0] || null;
    const title = active?.querySelector('h2[tabindex="-1"]') || null;
    const currentLinks = Array.from(
      document.querySelectorAll('.module-tab[data-route][aria-current="page"]'),
    );
    const announcer = document.querySelector("#route-announcer");
    return {
      renderedViews: rendered.map((view) => view.dataset.remixView),
      titleExists: Boolean(title),
      titleFocused: document.activeElement === title,
      currentRoutes: currentLinks.map((link) => link.dataset.route),
      expectedLinkHref: route
        ? document.querySelector(`.module-tab[data-route="${route}"]`)?.getAttribute("href") || null
        : null,
      announcerText: announcer?.textContent.trim() || "",
      announcerRole: announcer?.getAttribute("role") || null,
      announcerLive: announcer?.getAttribute("aria-live") || null,
    };
  }, { name: viewName, route: resultRoute });

  assert.deepEqual(state.renderedViews, [viewName], `${expectedHash} 必须只显示 ${viewName} 视图`);
  assert.equal(state.titleExists, true, `${expectedHash} 当前视图必须有可编程聚焦的 h2`);
  if (options.expectFocus !== false) {
    assert.equal(state.titleFocused, true, `${expectedHash} 切换后必须把焦点移到当前 h2`);
  }
  assert.equal(state.announcerRole, "status", "路由播报区必须使用 status 语义");
  assert.equal(state.announcerLive, "polite", "路由播报区必须礼貌播报");
  assert.ok(state.announcerText, `${expectedHash} 切换后必须提供文本播报`);

  if (resultRoute) {
    assert.deepEqual(state.currentRoutes, [resultRoute], `${expectedHash} 必须且只能有一个 aria-current=page`);
    assert.equal(state.expectedLinkHref, expectedHash, `${resultRoute} 导航链接必须使用稳定 Hash`);
  } else {
    assert.deepEqual(state.currentRoutes, [], `${expectedHash} 不得把任一结果域误标为当前页`);
  }
}

async function navigateWithHash(page, hash, viewName, options) {
  await page.evaluate((nextHash) => {
    location.hash = nextHash;
  }, hash);
  await assertActiveView(page, viewName, hash, options);
}

async function clickResultRoute(page, route) {
  const link = page.locator(`.module-tab[data-route="${route}"][href="#/${route}"]`);
  assert.equal(await link.count(), 1, `${route} 必须有且只有一个普通 Hash 导航链接`);
  await link.click();
  await assertActiveView(page, route, `#/${route}`);
}

async function assertToolBoundary(page, tool) {
  const card = page.locator(`a.advanced-tool-card[data-tool="${tool}"][href="#/tools/${tool}"]`);
  assert.equal(await card.count(), 1, `${tool} 必须有唯一的高级工具卡链接`);
  const cardText = (await card.innerText()).trim();
  assert.match(cardText, /未启用|规划中/, `${tool} 卡片必须明确当前未启用`);
  assert.match(cardText, /查看检测边界/, `${tool} 卡片主操作必须是“查看检测边界”`);

  await card.click();
  await assertActiveView(page, `tool-${tool}`, `#/tools/${tool}`);

  const detail = page.locator(`[data-remix-view="tool-${tool}"]`);
  const detailText = (await detail.innerText()).trim();
  assert.match(detailText, /未启用|规划中/, `${tool} 详情必须保持中性状态`);
  assert.match(detailText, /检测边界|尚未接入|不会运行/, `${tool} 详情必须解释真实能力边界`);
  assert.equal(
    await detail.locator("button, a").filter({ hasText: /^(?:开始|立即)(?:检测|扫描|运行)$/ }).count(),
    0,
    `${tool} 未接入时不得提供虚假的开始操作`,
  );

  const back = detail.locator('[data-tools-back][href="#/tools"]');
  assert.equal(await back.count(), 1, `${tool} 详情必须有唯一返回工具中心的链接`);
  await back.click();
  await assertActiveView(page, "tools", "#/tools");
}

async function assertOfflineFailureSemantics(page) {
  await waitForDetectionIdle(page);
  await navigateWithHash(page, "#/overview", "overview");
  const score = await page.evaluate(() => ({
    value: document.querySelector(".score-number")?.textContent.trim() || "",
    label: document.querySelector(".score-ring")?.getAttribute("aria-label") || "",
  }));
  assert.match(score.value, /^(?:—|--|未知|未确认|证据不足)$/, "外部证据全失败时不得生成数字分数");
  assert.match(score.label, /证据不足|未生成|未知|未确认/, "分数的无障碍名称必须如实说明证据不足");

  await navigateWithHash(page, "#/leaks", "leaks");
  const rows = await page.evaluate(() => {
    const read = (rowId) => {
      const row = document.querySelector(`.signal-row[data-row-id="${rowId}"]`);
      const value = row?.querySelector(".signal-row-value");
      return {
        text: value?.textContent.trim() || "",
        good: Boolean(value?.classList.contains("good")),
      };
    };
    return {
      dns: read("dns-leak"),
      dnsRegion: read("dns-region-consistency"),
      webrtc: read("webrtc-leak"),
      stun: read("stun-nodes"),
    };
  });
  assert.match(rows.dns.text, /失败|未知|未确认|证据不足|无结果/, "DNS 外网失败必须保留失败语义");
  assert.match(rows.dnsRegion.text, /证据不足|未知|未确认|无结果/, "DNS 地区不得在无证据时判绿");
  assert.match(rows.webrtc.text, /证据不足|未知|未确认|无结果/, "WebRTC 被替身阻断时必须显示证据不足");
  assert.match(rows.stun.text, /0\s*\/\s*10|证据不足|未知|未确认/, "STUN 无响应必须如实显示零响应或证据不足");
  for (const [name, row] of Object.entries(rows)) {
    assert.equal(row.good, false, `${name} 无外部证据时不得使用绿色成功状态`);
  }

  await navigateWithHash(page, "#/network", "network");
  const networkRows = await page.evaluate(() => {
    const value = (id) => {
      const node = document.querySelector(`.signal-row[data-row-id="${id}"] .signal-row-value`);
      return { text: node?.textContent.trim() || "", good: Boolean(node?.classList.contains("good")) };
    };
    return {
      exit: value("exit-ip-quality"),
      intel: value("ip-intel-sources"),
      route: value("route-registry-sources"),
    };
  });
  assert.match(networkRows.exit.text, /失败|错误|未取得|未知|未确认|阻止/, "公网出口失败必须原样呈现");
  assert.match(networkRows.intel.text, /可用\s*0\s*\/\s*10|证据不足|未确认/, "IP 情报不得伪造可用来源");
  assert.match(networkRows.route.text, /可用\s*0\s*\/\s*10|证据不足|未确认/, "路由来源不得伪造可用来源");
  assert.equal(networkRows.exit.good, false, "未取得出口时不得显示绿色状态");
  assert.equal(networkRows.intel.good, false, "IP 情报零来源时不得显示绿色状态");
  assert.equal(networkRows.route.good, false, "路由来源零来源时不得显示绿色状态");
}

async function assertTopLayout(page, viewport, label) {
  const metrics = await page.evaluate(({ touchWidth }) => {
    const renderedStyle = (style, rect) => (
      style.display !== "none" &&
      style.visibility !== "hidden" &&
      Number(style.opacity || "1") > 0.01 &&
      rect.width > 0 &&
      rect.height > 0
    );
    const rectData = (rect) => ({
      top: rect.top,
      right: rect.right,
      bottom: rect.bottom,
      left: rect.left,
      width: rect.width,
      height: rect.height,
    });
    const rendered = (node) => {
      const rect = node.getBoundingClientRect();
      return !node.hidden && renderedStyle(getComputedStyle(node), rect);
    };
    const activeView = Array.from(document.querySelectorAll("[data-remix-view]")).find(rendered);
    const title = activeView?.querySelector('h2[tabindex="-1"]') || null;
    const titleRect = title?.getBoundingClientRect() || null;
    const pointBlockers = (target) => {
      if (!target) return ["missing-target"];
      const rect = target.getBoundingClientRect();
      const inset = 2;
      const points = [
        [rect.left + rect.width / 2, rect.top + rect.height / 2],
        [rect.left + inset, rect.top + inset],
        [rect.right - inset, rect.bottom - inset],
      ];
      return Array.from(new Set(points.flatMap(([x, y]) => {
        if (x < 0 || y < 0 || x >= innerWidth || y >= innerHeight) return ["outside-viewport"];
        return document.elementsFromPoint(x, y)
          .filter((node) => !target.contains(node) && !node.contains(target))
          .filter((node) => getComputedStyle(node).pointerEvents !== "none")
          .slice(0, 1)
          .map((node) => node.id || node.className || node.tagName);
      })));
    };
    const tabs = Array.from(document.querySelectorAll(".module-tab[data-route]"));
    const current = document.querySelector('.module-tab[data-route][aria-current="page"]');
    const currentRect = current?.getBoundingClientRect() || null;
    const navScroller = tabs[0]?.parentElement || null;
    const navStyle = navScroller ? getComputedStyle(navScroller) : null;
    const webkitScrollbar = navScroller ? getComputedStyle(navScroller, "::-webkit-scrollbar") : null;
    const actions = ["privacy-toggle", "floating-copy", "floating-recheck"].map((id) => {
      const node = document.getElementById(id);
      const rect = node?.getBoundingClientRect() || null;
      return { id, rendered: Boolean(node && rendered(node)), rect: rect ? rectData(rect) : null };
    });
    const overlapPairs = [];
    for (let left = 0; left < actions.length; left += 1) {
      for (let right = left + 1; right < actions.length; right += 1) {
        const a = actions[left];
        const b = actions[right];
        if (!a.rect || !b.rect) continue;
        const overlapWidth = Math.max(0, Math.min(a.rect.right, b.rect.right) - Math.max(a.rect.left, b.rect.left));
        const overlapHeight = Math.max(0, Math.min(a.rect.bottom, b.rect.bottom) - Math.max(a.rect.top, b.rect.top));
        if (overlapWidth * overlapHeight > 1) overlapPairs.push(`${a.id}/${b.id}`);
      }
    }

    const touchSelector = [
      "a[href]",
      "button",
      "input:not([type=hidden])",
      "select",
      "textarea",
      "summary",
      '[role="button"]',
      '[tabindex]:not([tabindex="-1"])',
    ].join(",");
    const touchOffenders = touchWidth
      ? Array.from(document.querySelectorAll(touchSelector))
        .filter((node, index, all) => all.indexOf(node) === index)
        .filter((node) => !node.closest("[hidden]") && !node.closest("dialog:not([open])"))
        .filter((node) => !node.matches(".skip-link"))
        .filter((node) => {
          const rect = node.getBoundingClientRect();
          const style = getComputedStyle(node);
          return renderedStyle(style, rect) && style.pointerEvents !== "none" && rect.right > 0 && rect.left < innerWidth;
        })
        .map((node) => ({
          name: node.id || node.getAttribute("data-route") || node.getAttribute("data-tool") || node.getAttribute("aria-label") || node.textContent.trim().slice(0, 28) || node.tagName,
          width: node.getBoundingClientRect().width,
          height: node.getBoundingClientRect().height,
        }))
        .filter((item) => item.width < 43.5 || item.height < 43.5)
      : [];

    return {
      pageOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      activeView: activeView?.dataset.remixView || null,
      titleRect: titleRect ? rectData(titleRect) : null,
      titleBlockers: pointBlockers(title),
      titleFocused: document.activeElement === title,
      currentRect: currentRect ? rectData(currentRect) : null,
      navOverflow: navScroller ? navScroller.scrollWidth - navScroller.clientWidth : null,
      navScrollbarHidden: Boolean(
        navScroller &&
        navScroller.scrollWidth - navScroller.clientWidth > 1 &&
        (navStyle?.scrollbarWidth === "none" || webkitScrollbar?.display === "none"),
      ),
      actions,
      overlapPairs,
      touchOffenders,
    };
  }, { touchWidth: viewport.width <= 844 });

  assert.ok(metrics.activeView, `${label} 必须存在唯一可见视图`);
  assert.ok(metrics.pageOverflow <= 1, `${label} 页面横向溢出 ${metrics.pageOverflow}px`);
  assert.ok(metrics.titleRect, `${label} 必须有当前视图标题`);
  assert.ok(metrics.titleRect.top >= -1, `${label} 标题顶部不得移出视口：${JSON.stringify(metrics.titleRect)}`);
  assert.ok(metrics.titleRect.bottom <= viewport.height + 1, `${label} 标题必须位于当前视口`);
  assert.deepEqual(metrics.titleBlockers, [], `${label} 标题不得被吸顶导航或其他层遮挡`);
  assert.equal(metrics.titleFocused, true, `${label} 路由标题必须保持程序化焦点`);
  assert.equal(metrics.navScrollbarHidden, false, `${label} 可滚动导航不得隐藏滚动条`);
  if (metrics.currentRect) {
    assert.ok(metrics.currentRect.left >= -1, `${label} 当前导航项左侧必须完整可见`);
    assert.ok(metrics.currentRect.right <= viewport.width + 1, `${label} 当前导航项右侧必须完整可见`);
  }
  for (const action of metrics.actions) {
    assert.equal(action.rendered, true, `${label} ${action.id} 必须可见`);
    assert.ok(action.rect.left >= -1 && action.rect.right <= viewport.width + 1, `${label} ${action.id} 不得横向越界`);
    if (viewport.width <= 844) {
      assert.ok(action.rect.width >= 43.5 && action.rect.height >= 43.5, `${label} ${action.id} 触控目标不得小于 44×44`);
    }
  }
  assert.deepEqual(metrics.overlapPairs, [], `${label} 三项固定操作不得彼此重叠`);
  assert.deepEqual(
    metrics.touchOffenders.slice(0, 12),
    [],
    `${label} 存在小于 44×44 的可见触控目标：${metrics.touchOffenders.map((item) => `${item.name}(${item.width.toFixed(1)}×${item.height.toFixed(1)})`).join("、")}`,
  );
}

async function assertPageEndNotCovered(page, viewport, label) {
  await page.evaluate(() => {
    const renderedStyle = (style, rect) => (
      style.display !== "none" &&
      style.visibility !== "hidden" &&
      Number(style.opacity || "1") > 0.01 &&
      rect.width > 0 &&
      rect.height > 0
    );
    const selector = [
      "a[href]",
      "button",
      "input:not([type=hidden])",
      "select",
      "textarea",
      "summary",
      '[role="button"]',
      '[tabindex]:not([tabindex="-1"])',
    ].join(",");
    const candidates = Array.from(document.querySelectorAll(selector)).filter((node) => {
      if (node.closest("[hidden]") || node.closest("dialog:not([open])") || node.closest("[data-floating-tools]")) return false;
      const rect = node.getBoundingClientRect();
      const style = getComputedStyle(node);
      return renderedStyle(style, rect) && !["fixed", "sticky"].includes(style.position);
    });
    const target = candidates.sort((left, right) => {
      const leftBottom = left.getBoundingClientRect().bottom + scrollY;
      const rightBottom = right.getBoundingClientRect().bottom + scrollY;
      return leftBottom - rightBottom;
    }).at(-1);
    if (target) {
      target.dataset.e2eLastFocusable = "true";
      target.scrollIntoView({ block: "end", inline: "nearest" });
    }
    window.scrollTo({ top: document.documentElement.scrollHeight, behavior: "instant" });
  });
  await settleLayout(page);

  const state = await page.evaluate(() => {
    const renderedStyle = (style, rect) => (
      style.display !== "none" &&
      style.visibility !== "hidden" &&
      Number(style.opacity || "1") > 0.01 &&
      rect.width > 0 &&
      rect.height > 0
    );
    const target = document.querySelector('[data-e2e-last-focusable="true"]');
    const rect = target?.getBoundingClientRect() || null;
    const bottomLayers = Array.from(document.body.querySelectorAll("*")).filter((node) => {
      if (node === target || node.contains(target) || target?.contains(node)) return false;
      const nodeRect = node.getBoundingClientRect();
      const style = getComputedStyle(node);
      return (
        ["fixed", "sticky"].includes(style.position) &&
        renderedStyle(style, nodeRect) &&
        style.pointerEvents !== "none" &&
        nodeRect.bottom >= innerHeight - 1 &&
        nodeRect.top > 0
      );
    });
    const overlayTop = bottomLayers.length
      ? Math.min(...bottomLayers.map((node) => node.getBoundingClientRect().top))
      : innerHeight;
    const blockers = target && rect
      ? document.elementsFromPoint(
        Math.max(0, Math.min(innerWidth - 1, rect.left + rect.width / 2)),
        Math.max(0, Math.min(innerHeight - 1, rect.bottom - 2)),
      ).filter((node) => !target.contains(node) && !node.contains(target))
        .filter((node) => getComputedStyle(node).pointerEvents !== "none")
        .slice(0, 3)
        .map((node) => node.id || node.className || node.tagName)
      : [];
    return {
      target: target?.id || target?.getAttribute("aria-label") || target?.textContent.trim().slice(0, 40) || null,
      rect: rect ? { top: rect.top, bottom: rect.bottom, left: rect.left, right: rect.right } : null,
      overlayTop,
      blockers,
      pageOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    };
  });

  assert.ok(state.target && state.rect, `${label} 页面末尾必须保留可访问的交互目标`);
  assert.ok(state.rect.top >= -1 && state.rect.bottom <= viewport.height + 1, `${label} 页面末尾目标必须能滚入视口`);
  assert.ok(state.rect.bottom <= state.overlayTop + 1, `${label} 页面末尾目标不得被底部操作栏遮挡`);
  assert.deepEqual(state.blockers, [], `${label} 页面末尾目标不得被其他可交互层覆盖`);
  assert.ok(state.pageOverflow <= 1, `${label} 滚到底部后仍不得横向溢出`);
  await page.evaluate(() => document.querySelector('[data-e2e-last-focusable="true"]')?.removeAttribute("data-e2e-last-focusable"));
}

async function assertCurrentLayout(page, viewport, label) {
  await assertTopLayout(page, viewport, label);
  await assertPageEndNotCovered(page, viewport, label);
}

async function assertResponsiveMatrix(page) {
  for (const viewport of viewports) {
    await page.setViewportSize(viewport);

    for (const route of resultRoutes) {
      await navigateWithHash(page, `#/${route}`, route);
      await assertCurrentLayout(page, viewport, `${viewport.width}×${viewport.height} · #/${route}`);
    }

    await navigateWithHash(page, "#/tools", "tools");
    await assertCurrentLayout(page, viewport, `${viewport.width}×${viewport.height} · #/tools`);
    for (const tool of toolRoutes) {
      await navigateWithHash(page, `#/tools/${tool}`, `tool-${tool}`);
      await assertCurrentLayout(page, viewport, `${viewport.width}×${viewport.height} · #/tools/${tool}`);
    }
  }
}

function controllerCoverageReport(entries, source) {
  const targets = entries.filter((entry) => {
    try {
      return new URL(entry.url).pathname.endsWith(`/${CONTROLLER_FILE}`);
    } catch {
      return false;
    }
  });
  assert.ok(targets.length > 0, `JavaScript Coverage 必须包含 ${CONTROLLER_FILE}`);

  const total = Math.max(
    source.length,
    ...targets.map((entry) => entry.source?.length || 0),
  );
  const ranges = targets
    .flatMap((entry) => {
      if (Array.isArray(entry.ranges)) return entry.ranges;
      return (entry.functions || []).flatMap((coverageFunction) => coverageFunction.ranges || []);
    })
    .filter((range) => range.count === undefined || range.count > 0)
    .map((range) => ({
      start: Math.max(0, Math.min(total, range.start ?? range.startOffset ?? 0)),
      end: Math.max(0, Math.min(total, range.end ?? range.endOffset ?? 0)),
    }))
    .filter((range) => range.end > range.start)
    .sort((left, right) => left.start - right.start || left.end - right.end);

  const merged = [];
  for (const range of ranges) {
    const previous = merged.at(-1);
    if (!previous || range.start > previous.end) merged.push({ ...range });
    else previous.end = Math.max(previous.end, range.end);
  }
  const executed = merged.reduce((sum, range) => sum + range.end - range.start, 0);
  return { executed, total, ratio: total ? executed / total : 0, entries: targets.length };
}

await new Promise((resolveListen, rejectListen) => {
  server.once("error", rejectListen);
  server.listen(0, "127.0.0.1", resolveListen);
});

const serverAddress = server.address();
assert.ok(serverAddress && typeof serverAddress !== "string", "本地 HTTP Server 必须成功监听随机端口");
const localOrigin = `http://127.0.0.1:${serverAddress.port}`;
const baseUrl = `${localOrigin}/${PAGE_FILE}`;
const externalHttp = [];
const localHttp = [];
const externalWebSockets = [];
const consoleErrors = [];
const pageErrors = [];
let browser;
let context;
let page;
let coverageStarted = false;

try {
  browser = await chromium.launch({ headless: true });
  context = await browser.newContext({
    locale: "zh-CN",
    serviceWorkers: "block",
    timezoneId: "Asia/Taipei",
    viewport: { width: 1200, height: 800 },
  });

  await context.route("**/*", async (route) => {
    const request = route.request();
    let url;
    try {
      url = new URL(request.url());
    } catch {
      externalHttp.push({ method: request.method(), resourceType: request.resourceType(), url: request.url() });
      await route.abort("blockedbyclient");
      return;
    }

    if (url.protocol === "http:" && url.origin === localOrigin && url.hostname === "127.0.0.1") {
      localHttp.push(request.url());
      await route.continue();
      return;
    }

    externalHttp.push({
      method: request.method(),
      resourceType: request.resourceType(),
      url: request.url(),
    });
    await route.abort("blockedbyclient");
  });

  await context.routeWebSocket("**", async (socket) => {
    externalWebSockets.push(socket.url());
    await socket.close({ code: 1008, reason: "E2E blocks every WebSocket" });
  });

  await context.addInitScript(() => {
    const clipboardWrites = [];
    const clipboard = Object.freeze({
      writeText(text) {
        clipboardWrites.push(String(text));
        return Promise.resolve();
      },
      readText() {
        return Promise.resolve(clipboardWrites.at(-1) || "");
      },
    });
    Object.defineProperty(globalThis, "__e2eClipboardWrites", {
      configurable: true,
      value: clipboardWrites,
    });
    try {
      Object.defineProperty(navigator, "clipboard", { configurable: true, value: clipboard });
    } catch {
      Object.defineProperty(Navigator.prototype, "clipboard", { configurable: true, get: () => clipboard });
    }

    const rtcConfigurations = [];
    class OfflineRTCPeerConnection extends EventTarget {
      constructor(configuration = {}) {
        super();
        this.configuration = structuredClone(configuration);
        this.connectionState = "new";
        this.iceConnectionState = "new";
        this.iceGatheringState = "new";
        this.localDescription = null;
        rtcConfigurations.push(this.configuration);
      }

      createDataChannel(label) {
        return Object.freeze({ label: String(label), close() {} });
      }

      createOffer() {
        return Promise.reject(new DOMException("E2E 已阻断外部 STUN", "NetworkError"));
      }

      setLocalDescription(description) {
        this.localDescription = description;
        return Promise.resolve();
      }

      close() {
        this.connectionState = "closed";
        this.iceConnectionState = "closed";
      }

      getConfiguration() {
        return structuredClone(this.configuration);
      }
    }
    Object.defineProperty(OfflineRTCPeerConnection, "__e2eOffline", { value: true });
    for (const name of ["RTCPeerConnection", "webkitRTCPeerConnection", "mozRTCPeerConnection"]) {
      Object.defineProperty(globalThis, name, {
        configurable: true,
        writable: false,
        value: OfflineRTCPeerConnection,
      });
    }
    Object.defineProperty(globalThis, "__e2eRtcConfigurations", {
      configurable: true,
      value: rtcConfigurations,
    });

    try {
      localStorage.setItem("aisg-star-prompt-until", String(Date.now() + 24 * 60 * 60 * 1000));
    } catch {}
  });

  page = await context.newPage();
  page.on("console", (message) => {
    if (message.type() === "error") {
      consoleErrors.push({ text: message.text(), location: message.location() });
    }
  });
  page.on("pageerror", (error) => {
    pageErrors.push(error.stack || error.message || String(error));
  });

  await page.coverage.startJSCoverage({ resetOnNavigation: false, reportAnonymousScripts: false });
  coverageStarted = true;

  const firstResponse = await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
  assert.equal(
    firstResponse?.status(),
    200,
    `${PAGE_FILE} 必须由本地 HTTP Server 返回 200（TDD 红灯时该文件尚不存在）`,
  );
  await assertActiveView(page, "overview", "#/overview");
  await waitForDetectionIdle(page);

  // 非法 Hash 必须在一次全新文档加载时规范化，不能留下不可分享的未知状态。
  await page.goto("about:blank");
  const invalidResponse = await page.goto(`${baseUrl}#/not-a-real-route`, { waitUntil: "domcontentloaded" });
  assert.equal(invalidResponse?.status(), 200, "非法 Hash 直开仍必须加载 Remix 页面");
  await assertActiveView(page, "overview", "#/overview");
  await waitForDetectionIdle(page);

  // 五个结果路由都必须由普通链接驱动。
  for (const route of ["network", "leaks", "paths", "browser", "overview"]) {
    await clickResultRoute(page, route);
  }

  // 直接深链与刷新必须恢复相同视图。
  await page.goto("about:blank");
  const deepLinkResponse = await page.goto(`${baseUrl}#/paths`, { waitUntil: "domcontentloaded" });
  assert.equal(deepLinkResponse?.status(), 200, "结果域深链必须由本地页面承载");
  await assertActiveView(page, "paths", "#/paths");
  await page.reload({ waitUntil: "domcontentloaded" });
  await assertActiveView(page, "paths", "#/paths");
  await waitForDetectionIdle(page);

  // SPA 历史必须保留真实 back / forward 行为。
  await clickResultRoute(page, "overview");
  await clickResultRoute(page, "network");
  await clickResultRoute(page, "leaks");
  await page.goBack();
  await assertActiveView(page, "network", "#/network");
  await page.goForward();
  await assertActiveView(page, "leaks", "#/leaks");

  // 普通链接采用浏览器原生 Tab / Shift+Tab / Enter，不实现伪 ARIA Tab 的方向键模型。
  await clickResultRoute(page, "overview");
  const overviewLink = page.locator('.module-tab[data-route="overview"]');
  await overviewLink.focus();
  await page.keyboard.press("Tab");
  assert.equal(
    await page.evaluate(() => document.activeElement?.getAttribute("data-route")),
    "network",
    "Tab 必须按 DOM 顺序进入下一个结果链接",
  );
  await page.keyboard.press("Shift+Tab");
  assert.equal(
    await page.evaluate(() => document.activeElement?.getAttribute("data-route")),
    "overview",
    "Shift+Tab 必须返回上一个结果链接",
  );
  await page.keyboard.press("Tab");
  await page.keyboard.press("Enter");
  await assertActiveView(page, "network", "#/network");

  // 工具中心与七个详情都必须可分享、可返回，并保持未启用的诚实语义。
  await navigateWithHash(page, "#/tools", "tools");
  const firstToolCard = page.locator('a.advanced-tool-card[data-tool="ip"]');
  await firstToolCard.focus();
  await page.keyboard.press("Tab");
  assert.equal(
    await page.evaluate(() => document.activeElement?.getAttribute("data-tool")),
    "dns",
    "工具卡必须可按 Tab 顺序访问",
  );
  await page.keyboard.press("Shift+Tab");
  await page.keyboard.press("Enter");
  await assertActiveView(page, "tool-ip", "#/tools/ip");
  await page.locator('[data-remix-view="tool-ip"] [data-tools-back][href="#/tools"]').click();
  await assertActiveView(page, "tools", "#/tools");

  for (const tool of toolRoutes) {
    await assertToolBoundary(page, tool);
  }

  // 工具详情也必须参与原生历史栈。
  await page.locator('a.advanced-tool-card[data-tool="latency"]').click();
  await assertActiveView(page, "tool-latency", "#/tools/latency");
  await page.goBack();
  await assertActiveView(page, "tools", "#/tools");
  await page.goForward();
  await assertActiveView(page, "tool-latency", "#/tools/latency");
  await page.locator('[data-remix-view="tool-latency"] [data-tools-back]').click();
  await assertActiveView(page, "tools", "#/tools");

  // 浏览器本地摘要提供真实的敏感值，用它验证隐私开关、跨路由保持和复制脱敏。
  await navigateWithHash(page, "#/browser", "browser");
  const fingerprint = page.locator('[data-fingerprint-value="v3"]');
  await page.waitForFunction(() => /^[0-9a-f]{16,}$/i.test(
    document.querySelector('[data-fingerprint-value="v3"]')?.textContent.trim() || "",
  ));
  const rawFingerprint = (await fingerprint.textContent()).trim();
  const privacy = page.locator("#privacy-toggle");
  assert.equal(await privacy.getAttribute("aria-pressed"), "false", "隐私遮罩默认必须关闭");
  await privacy.click();
  assert.equal(await privacy.getAttribute("aria-pressed"), "true", "隐私按钮必须暴露 pressed 状态");
  assert.notEqual((await fingerprint.textContent()).trim(), rawFingerprint, "隐私模式必须遮罩本地指纹摘要");
  assert.match(
    await page.locator("#floating-action-status").innerText(),
    /隐私|遮罩|隐藏|原值/,
    "隐私变化必须提供文本反馈",
  );

  for (const route of ["network", "leaks", "browser"]) {
    await navigateWithHash(page, `#/${route}`, route);
    assert.equal(await privacy.getAttribute("aria-pressed"), "true", `隐私状态必须跨 #/${route} 保持`);
    const leaks = await page.evaluate(() => Array.from(document.querySelectorAll("[data-sensitive-value]"))
      .map((node) => ({ raw: node.dataset.sensitiveValue || "", shown: node.textContent.trim() }))
      .filter((item) => (
        /^(?:\d{1,3}\.){3}\d{1,3}$/.test(item.raw) ||
        item.raw.includes(":") ||
        /^[0-9a-f]{16,}$/i.test(item.raw)
      ))
      .filter((item) => item.raw === item.shown));
    assert.deepEqual(leaks, [], `隐私模式不得在 #/${route} 暴露 data-sensitive-value 原值`);
  }

  const writesBeforeCopy = await page.evaluate(() => globalThis.__e2eClipboardWrites.length);
  await page.locator("#floating-copy").click();
  await page.waitForFunction((count) => globalThis.__e2eClipboardWrites.length > count, writesBeforeCopy);
  const copiedSummary = await page.evaluate(() => globalThis.__e2eClipboardWrites.at(-1));
  assert.ok(copiedSummary.trim(), "复制摘要必须向确定性剪贴板写入非空文本");
  assert.equal(copiedSummary.includes(rawFingerprint), false, "隐私模式复制摘要不得泄漏完整指纹");
  assert.match(
    await page.locator("#floating-action-status").innerText(),
    /已复制|复制成功|摘要.*复制/,
    "复制完成必须提供文本反馈",
  );

  await privacy.click();
  assert.equal((await fingerprint.textContent()).trim(), rawFingerprint, "关闭隐私模式必须恢复本地原值");
  await privacy.click();
  assert.notEqual((await fingerprint.textContent()).trim(), rawFingerprint, "再次开启隐私模式必须重新遮罩");

  // 重测必须产生状态反馈、保留隐私状态，并再次走完全阻断的外部探针。
  await page.evaluate(() => {
    globalThis.__e2eActionStatusHistory = [];
    const status = document.querySelector("#floating-action-status");
    const record = () => globalThis.__e2eActionStatusHistory.push(status?.textContent.trim() || "");
    record();
    new MutationObserver(record).observe(status, { childList: true, characterData: true, subtree: true });
  });
  const httpAttemptsBeforeRecheck = externalHttp.length;
  const rtcAttemptsBeforeRecheck = await page.evaluate(() => globalThis.__e2eRtcConfigurations.length);
  await page.locator("#floating-recheck").click();
  await page.waitForFunction(() => globalThis.__e2eActionStatusHistory.some((text) => /重测|检测|正在|完成/.test(text)));
  await waitForDetectionIdle(page);
  assert.ok(externalHttp.length > httpAttemptsBeforeRecheck, "重测必须重新执行既有实时 HTTP 探针");
  assert.ok(
    await page.evaluate(() => globalThis.__e2eRtcConfigurations.length) > rtcAttemptsBeforeRecheck,
    "重测必须重新调用不会联网的 RTCPeerConnection 替身",
  );
  assert.equal(await privacy.getAttribute("aria-pressed"), "true", "重测不得关闭用户的隐私遮罩");

  await assertOfflineFailureSemantics(page);

  // 六个验收视口覆盖五结果域、工具中心和七个详情。
  await assertResponsiveMatrix(page);

  const rtcIsolation = await page.evaluate(() => ({
    fakeInstalled: globalThis.RTCPeerConnection?.__e2eOffline === true,
    calls: globalThis.__e2eRtcConfigurations.length,
    allConfigured: globalThis.__e2eRtcConfigurations.every((config) => Array.isArray(config.iceServers)),
  }));
  assert.equal(rtcIsolation.fakeInstalled, true, "浏览器必须始终使用离线 RTCPeerConnection 替身");
  assert.ok(rtcIsolation.calls >= 10, "10 个 STUN 节点都必须经过离线替身而非真实网络");
  assert.equal(rtcIsolation.allConfigured, true, "每次 WebRTC 调用都应保留可审计的 iceServers 配置");
  assert.ok(externalHttp.length > 0, "页面应尝试真实证据来源，以便验证阻断后的诚实失败语义");
  assert.ok(localHttp.length > 0, "页面及本地资源必须只从 127.0.0.1 HTTP Server 加载");
  assert.equal(
    localHttp.every((url) => new URL(url).origin === localOrigin && new URL(url).hostname === "127.0.0.1"),
    true,
    "被放行的 HTTP 请求只能指向当前 127.0.0.1 Server",
  );
  assert.equal(
    externalWebSockets.every((url) => /^wss?:/i.test(url)),
    true,
    "任何 WebSocket 尝试都只能进入记录后关闭的拦截器",
  );

  const coverageEntries = await page.coverage.stopJSCoverage();
  coverageStarted = false;
  const controllerSource = await readFile(resolve(projectRoot, CONTROLLER_FILE), "utf8");
  const coverage = controllerCoverageReport(coverageEntries, controllerSource);
  assert.ok(
    coverage.ratio >= 0.8,
    `${CONTROLLER_FILE} 已执行字节覆盖率必须 >= 80%，当前 ${(coverage.ratio * 100).toFixed(2)}%（${coverage.executed}/${coverage.total}）`,
  );

  const unexpectedConsoleErrors = consoleErrors.filter(({ text }) => !(
    /Failed to load resource.*(?:ERR_FAILED|ERR_BLOCKED_BY_CLIENT)/i.test(text) ||
    /WebSocket connection to .* failed/i.test(text)
  ));
  assert.deepEqual(pageErrors, [], `页面不得抛出 pageerror：\n${pageErrors.join("\n")}`);
  assert.deepEqual(
    unexpectedConsoleErrors,
    [],
    `页面不得输出非预期 console.error：\n${unexpectedConsoleErrors.map((item) => item.text).join("\n")}`,
  );

  console.log(
    `PASS IPCX Remix v1.2.0 路由、键盘、隐私、离线真实性与六视口回归；控制器覆盖率 ${(coverage.ratio * 100).toFixed(2)}%；阻断 HTTP ${externalHttp.length} / WebSocket ${externalWebSockets.length}`,
  );
} finally {
  if (coverageStarted && page) await page.coverage.stopJSCoverage().catch(() => {});
  await context?.close().catch(() => {});
  await browser?.close().catch(() => {});
  await new Promise((resolveClose) => server.close(resolveClose));
}
