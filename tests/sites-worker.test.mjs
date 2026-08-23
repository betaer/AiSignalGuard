import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const clientRoot = resolve(projectRoot, "dist", "client");
const mimeTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
};

async function loadWorker() {
  const workerUrl = pathToFileURL(
    resolve(projectRoot, "dist", "server", "index.js"),
  );
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  return (await import(workerUrl.href)).default;
}

function mockAssets() {
  return {
    async fetch(request) {
      const url = new URL(request.url);
      let pathname = decodeURIComponent(url.pathname);
      if (pathname.endsWith("/")) {
        pathname += "index.html";
      }

      const file = resolve(clientRoot, `.${pathname}`);
      if (file !== clientRoot && !file.startsWith(`${clientRoot}${sep}`)) {
        return new Response("Not Found", { status: 404 });
      }

      try {
        const body = await readFile(file);
        return new Response(body, {
          headers: {
            "Content-Type":
              mimeTypes[extname(file).toLowerCase()] ||
              "application/octet-stream",
          },
        });
      } catch (error) {
        if (error?.code === "ENOENT" || error?.code === "EISDIR") {
          return new Response("Not Found", {
            status: 404,
            headers: { "Content-Type": "text/plain; charset=utf-8" },
          });
        }
        throw error;
      }
    },
  };
}

function context() {
  return {
    waitUntil() {},
    passThroughOnException() {},
  };
}

test("serves the product homepage and rewrites share metadata to its Sites origin", async () => {
  const worker = await loadWorker();
  const response = await worker.fetch(
    new Request("https://ai-signal-guard.example/", {
      headers: { accept: "text/html" },
    }),
    { ASSETS: mockAssets() },
    context(),
  );

  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") || "", /^text\/html/);
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");

  const html = await response.text();
  assert.match(html, /<title>AI Signal Guard/);
  assert.match(html, /https:\/\/ai-signal-guard\.example\/assets\//);
  assert.doesNotMatch(html, /betaer\.github\.io\/aisignalguard/i);
});

test("serves fixed v1 and v2 directories while keeping one public share root", async () => {
  const worker = await loadWorker();
  const env = { ASSETS: mockAssets() };

  for (const [pathname, version] of [["/v1/", "1.0.0"], ["/v2/", "2.0.0"]]) {
    const response = await worker.fetch(
      new Request(`https://ai-signal-guard.example${pathname}`, {
        headers: { accept: "text/html" },
      }),
      env,
      context(),
    );
    assert.equal(response.status, 200, pathname);
    const html = await response.text();
    assert.match(html, new RegExp(`data-version="${version.replaceAll(".", "\\.")}"`), pathname);
    assert.match(html, /<link rel="canonical" href="https:\/\/ai-signal-guard\.example\/">/, pathname);
    assert.match(html, /<meta property="og:url" content="https:\/\/ai-signal-guard\.example\/">/, pathname);
    assert.doesNotMatch(html, /betaer\.github\.io\/aisignalguard/i, pathname);
  }
});

test("serves the browser bundle through the assets binding", async () => {
  const worker = await loadWorker();
  const response = await worker.fetch(
    new Request("https://ai-signal-guard.example/app.min.js"),
    { ASSETS: mockAssets() },
    context(),
  );

  assert.equal(response.status, 200);
  assert.match(
    response.headers.get("content-type") || "",
    /^text\/javascript/,
  );
  const javascript = await response.text();
  assert.ok(javascript.length > 50_000);
  assert.match(javascript, /new URL\("\/",\s*window\.location\.href\)\.href/);
  assert.doesNotMatch(javascript, /betaer\.github\.io\/aisignalguard/i);
});

test("serves the dated wide-diagnostics page with its raw shared stylesheet", async () => {
  const worker = await loadWorker();
  const env = { ASSETS: mockAssets() };
  const htmlResponse = await worker.fetch(
    new Request("https://ai-signal-guard.example/index-20260719.html", {
      headers: { accept: "text/html" },
    }),
    env,
    context(),
  );

  assert.equal(htmlResponse.status, 200);
  const html = await htmlResponse.text();
  assert.match(html, /<body class="dated-wide-diagnostics" data-app-stage="select">/);
  assert.match(html, /href="styles\.min\.css\?v=/);
  assert.match(html, /src="app\.min\.js\?v=/);

  const stylesheetResponse = await worker.fetch(
    new Request("https://ai-signal-guard.example/styles.min.css"),
    env,
    context(),
  );
  assert.equal(stylesheetResponse.status, 200);
  assert.match(stylesheetResponse.headers.get("content-type") || "", /^text\/css/);
  assert.ok((await stylesheetResponse.text()).length > 50_000);
});

test("serves the live IPCX page and all of its browser controllers", async () => {
  const worker = await loadWorker();
  const env = { ASSETS: mockAssets() };
  const htmlResponse = await worker.fetch(
    new Request("https://ai-signal-guard.example/index-ipcx-v1.5.0.html", {
      headers: { accept: "text/html" },
    }),
    env,
    context(),
  );

  assert.equal(htmlResponse.status, 200);
  const html = await htmlResponse.text();
  assert.match(html, /src="starPromptPolicy\.js"/);
  assert.match(html, /src="signalSemantics\.js\?v=1\.5\.0"/);
  assert.match(html, /src="networkEvidence\.js\?v=1\.5\.0"/);
  assert.match(html, /src="signalGuardApp\.js\?v=1\.5\.0"/);

  const legacyResponse = await worker.fetch(
    new Request("https://ai-signal-guard.example/index-ipcx.html", {
      headers: { accept: "text/html" },
    }),
    env,
    context(),
  );
  assert.match(await legacyResponse.text(), /index-ipcx-v1\.5\.0\.html/);

  for (const [pathname, marker] of [
    ["/starPromptPolicy.js", /AISGStarPromptPolicy/],
    ["/networkEvidence.js", /AISGIpEvidence/],
    ["/signalGuardApp.js", /runLiveDetection/],
  ]) {
    const response = await worker.fetch(
      new Request(`https://ai-signal-guard.example${pathname}`),
      env,
      context(),
    );
    assert.equal(response.status, 200, pathname);
    assert.match(response.headers.get("content-type") || "", /^text\/javascript/);
    assert.match(await response.text(), marker, pathname);
  }
});

test("serves the versioned IPCX Remix page without aliasing missing versions", async () => {
  const worker = await loadWorker();
  const env = { ASSETS: mockAssets() };
  const htmlPath = "/index-ipcx-remix-v1.2.0.html";
  const controllerPath = "/ipcx-remix-v1.2.0.js";

  const htmlResponse = await worker.fetch(
    new Request(`https://ai-signal-guard.example${htmlPath}`, {
      headers: { accept: "text/html" },
    }),
    env,
    context(),
  );
  assert.equal(htmlResponse.status, 200);
  assert.match(htmlResponse.headers.get("content-type") || "", /^text\/html/);
  assert.equal(htmlResponse.headers.get("cache-control"), "no-cache");
  assert.equal(htmlResponse.headers.get("x-content-type-options"), "nosniff");
  assert.equal(htmlResponse.headers.get("x-frame-options"), "DENY");
  const html = await htmlResponse.text();
  assert.match(html, /data-remix-version="1\.2\.0"/);
  assert.match(html, /src="starPromptPolicy\.js"/);
  assert.match(html, /src="networkEvidence\.js"/);
  assert.match(html, /src="ipcx-remix-v1\.2\.0\.js"/);

  const controllerResponse = await worker.fetch(
    new Request(`https://ai-signal-guard.example${controllerPath}`),
    env,
    context(),
  );
  assert.equal(controllerResponse.status, 200);
  assert.match(
    controllerResponse.headers.get("content-type") || "",
    /^text\/javascript/,
  );
  assert.equal(controllerResponse.headers.get("x-content-type-options"), "nosniff");
  assert.match(await controllerResponse.text(), /renderRemixRoute/);

  for (const pathname of [htmlPath, controllerPath]) {
    const response = await worker.fetch(
      new Request(`https://ai-signal-guard.example${pathname}`, { method: "HEAD" }),
      env,
      context(),
    );
    assert.equal(response.status, 200, pathname);
    assert.equal(await response.text(), "", pathname);
  }

  const missingVersion = await worker.fetch(
    new Request("https://ai-signal-guard.example/index-ipcx-remix-v1.2.1.html", {
      headers: { accept: "text/html" },
    }),
    env,
    context(),
  );
  assert.equal(missingVersion.status, 404);
  assert.doesNotMatch(await missingVersion.text(), /data-remix-version="1\.2\.0"/);
});

test("serves the isolated identity demo and its browser assets", async () => {
  const worker = await loadWorker();
  const env = { ASSETS: mockAssets() };
  const htmlResponse = await worker.fetch(
    new Request("https://ai-signal-guard.example/demo/index-new.html", {
      headers: { accept: "text/html" },
    }),
    env,
    context(),
  );

  assert.equal(htmlResponse.status, 200);
  const html = await htmlResponse.text();
  assert.match(html, /data-demo-version="identity-v2"/);
  assert.match(html, /https:\/\/ai-signal-guard\.example\/demo\/index-new\.html/);
  assert.match(html, /href="\.\.\/favicon\.svg/);
  assert.match(html, /styles-new\.min\.css/);
  assert.match(html, /app-new\.min\.js/);
  assert.match(html, /src="\.\.\/assets\/merged_ai_logo\.svg\?v=20260720-1"/);
  assert.doesNotMatch(html, /(?:src|href)="favicon\.svg/);

  for (const [pathname, contentType] of [
    ["/demo/styles-new.min.css", /^text\/css/],
    ["/demo/app-new.min.js", /^text\/javascript/],
    ["/assets/merged_ai_logo.svg", /^image\/svg\+xml/],
  ]) {
    const response = await worker.fetch(
      new Request(`https://ai-signal-guard.example${pathname}`),
      env,
      context(),
    );
    assert.equal(response.status, 200, pathname);
    assert.match(response.headers.get("content-type") || "", contentType, pathname);
  }
});

test("keeps the merged AI diagnostic icon as a transparent vector on every page", async () => {
  const icon = await readFile(resolve(projectRoot, "assets", "merged_ai_logo.svg"), "utf8");
  assert.match(icon, /^<svg\b/);
  assert.match(icon, /<path\b/);
  assert.doesNotMatch(icon, /<(?:image|rect|pattern)\b/i);
  assert.doesNotMatch(icon, /data:image|mix-blend-mode|filter=/i);

  const [rootHtml, datedHtml, demoHtml] = await Promise.all([
    readFile(resolve(projectRoot, "index.html"), "utf8"),
    readFile(resolve(projectRoot, "index-20260719.html"), "utf8"),
    readFile(resolve(projectRoot, "demo", "index-new.html"), "utf8"),
  ]);
  assert.match(rootHtml, /src="assets\/merged_ai_logo\.svg\?v=20260720-1"/);
  assert.match(datedHtml, /src="assets\/merged_ai_logo\.svg\?v=20260720-1"/);
  assert.match(demoHtml, /src="\.\.\/assets\/merged_ai_logo\.svg\?v=20260720-1"/);
});

test("returns the branded 404 page with an actual 404 status", async () => {
  const worker = await loadWorker();
  const response = await worker.fetch(
    new Request("https://ai-signal-guard.example/missing", {
      headers: { accept: "text/html" },
    }),
    { ASSETS: mockAssets() },
    context(),
  );

  assert.equal(response.status, 404);
  assert.match(await response.text(), /这个页面没有信号/);
});

test("supports HEAD and rejects mutating methods", async () => {
  const worker = await loadWorker();
  const env = { ASSETS: mockAssets() };

  const head = await worker.fetch(
    new Request("https://ai-signal-guard.example/", { method: "HEAD" }),
    env,
    context(),
  );
  assert.equal(head.status, 200);
  assert.equal(await head.text(), "");

  const post = await worker.fetch(
    new Request("https://ai-signal-guard.example/", { method: "POST" }),
    env,
    context(),
  );
  assert.equal(post.status, 405);
  assert.equal(post.headers.get("allow"), "GET, HEAD");
});
