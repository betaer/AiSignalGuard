# IPCX Live Ten-Source Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace every simulated network result in `index-ipcx.html` with ten-source live evidence, keep every failed source visible, equalize secondary-detail padding, and hide the back-to-top action throughout the first viewport.

**Architecture:** Add a browser-compatible `ipcxEvidence.js` module that owns provider definitions, normalization, aggregation, cancellation, and STUN probing. `index-ipcx.html` remains the view/controller and renders all affected evidence sets from one live state object. The implementation stays GitHub-Pages-compatible: every upstream request is made to a fixed public HTTPS/CORS endpoint and no secret or fallback result is bundled.

**Tech Stack:** Vanilla HTML/CSS/JavaScript, browser Fetch API, WebRTC `RTCPeerConnection`, Node.js test runner, existing Vite/Cloudflare static build, Playwright browser verification.

---

## File map

- Create `ipcxEvidence.js`: provider registry, response normalizers, result-state model, ten-source aggregators, live-run cancellation and isolated STUN probes.
- Create `tests/ipcx-evidence.test.mjs`: pure data-model and orchestration tests using injected fetch and WebRTC doubles.
- Create `tests/ipcx-contract.test.mjs`: source-level contracts for no simulated values, equal padding, ten-row mappings, dynamic copy, and first-screen back-to-top behavior.
- Modify `index-ipcx.html`: load the evidence module, replace frozen demo records with live state, render status/count changes, bind live recheck, update copy text and back-to-top visibility.
- Modify `package.json`: add the IPCX test command to the default test chain.
- Modify `build/sites-vite-plugin.js`: expose `index-ipcx.html` and `ipcxEvidence.js` in the Cloudflare/static build so the same page can be verified after build.
- Modify `tests/sites-worker.test.mjs`: verify both IPCX assets are served.

### Task 1: Establish failing IPCX contracts

**Files:**
- Create: `tests/ipcx-contract.test.mjs`
- Modify: `package.json`

- [ ] **Step 1: Write the source-level contract test**

Create tests which read `index-ipcx.html` and assert:

```js
assert.doesNotMatch(html, /38\.92\.27\.182|198\.51\.100\.|本地演示数据|本地模拟结果/);
assert.match(html, /\.signal-row-body\s*\{[^}]*padding:\s*12px 14px 14px;/s);
assert.doesNotMatch(html, /padding:\s*12px 14px 14px 33px/);
assert.match(html, /AI Signal Guard",\s*"https:\/\/betaer\.github\.io\/AiSignalGuard\//);
assert.match(html, /scrollY\s*>=\s*window\.innerHeight/);
assert.match(html, /setAttribute\("aria-hidden"/);
```

Also assert that the row mappings for `asnOrganization`, `geoVotes`, `conflictSources`, `sourceCoverage`, `ipIntelSources`, and `routeSources` use live ten-source collections rather than literal 6/8/4/2 counts.

- [ ] **Step 2: Register the test command**

Add:

```json
"test:ipcx": "node --test tests/ipcx-evidence.test.mjs tests/ipcx-contract.test.mjs"
```

and include `npm run test:ipcx` in `npm test` before the build.

- [ ] **Step 3: Run the contract test and verify failure**

Run:

```bash
npm run test:ipcx
```

Expected: FAIL because `ipcxEvidence.js` and its tests do not exist, the page still contains simulated addresses and `.signal-row-body` still has 33px left padding.

- [ ] **Step 4: Commit the red contract**

```bash
git add package.json tests/ipcx-contract.test.mjs
git commit -m "test: define live ipcx evidence contracts"
```

### Task 2: Build the ten-source evidence core

**Files:**
- Create: `ipcxEvidence.js`
- Create: `tests/ipcx-evidence.test.mjs`

- [ ] **Step 1: Write failing source-registry tests**

Assert exact unique members for `IP_INTEL_SOURCES`, `ROUTE_SOURCES`, and `STUN_NODES`:

```js
assert.equal(api.IP_INTEL_SOURCES.length, 10);
assert.equal(new Set(api.IP_INTEL_SOURCES.map(({ id }) => id)).size, 10);
assert.equal(api.ROUTE_SOURCES.length, 10);
assert.equal(api.STUN_NODES.length, 10);
```

The IP source IDs must be `ipwho`, `ipsb`, `geojs`, `dbip`, `ipapiis`, `ipinfo`, `countryis`, `iplocation`, `freeipapi`, and `ipguide`.

- [ ] **Step 2: Run the source-registry tests**

Run `npm run test:ipcx`.

Expected: FAIL because `globalThis.AISGIpEvidence` is undefined.

- [ ] **Step 3: Implement immutable provider registries**

Expose a global API using the same browser/Node pattern as `starPromptPolicy.js`:

```js
(function attach(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.AISGIpEvidence = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function createApi() {
  "use strict";
  // registries and helpers
  return Object.freeze({ IP_INTEL_SOURCES, ROUTE_SOURCES, STUN_NODES });
});
```

Each provider must define a fixed endpoint builder and a dedicated normalizer; endpoint builders may interpolate only an encoded, validated IP or ASN.

- [ ] **Step 4: Write failing normalization tests**

Use representative real response shapes for all ten IP providers and assert normalized `observedIp`, `countryCode`, `city`, `asn`, `organization`, `networkType`, `proxy`, and `hosting`. Add cases for HTTP 429, timeout, malformed JSON, missing fields and a mismatched observed IP.

- [ ] **Step 5: Implement normalization and status classification**

Implement:

```js
normalizeIp(value)
normalizeAsn(value)
normalizeCountryCode(value)
createPendingRecord(source)
classifyFailure(error)
normalizeIntelPayload(sourceId, payload, context)
isUsableFor(record, fields)
```

Never copy values from another provider. A response with a missing required field becomes `partial`; an observed-IP mismatch becomes `path_mismatch` and cannot vote.

- [ ] **Step 6: Write failing aggregation tests**

Verify:

- ten input records always produce ten displayed records;
- only valid country fields contribute to `geoConsensus`;
- missing ASN/organization fields do not count as conflicts;
- unavailable sources remain in output;
- counts distinguish `responded`, `usable`, `partial`, and `failed`.

- [ ] **Step 7: Implement aggregation**

Add pure helpers:

```js
summarizeSources(records)
computeCountryConsensus(records)
computeAsnConsensus(records)
buildConflictRecords(records, consensus)
buildNetworkLabelRecords(records)
```

Every summary denominator is `10`; every numerator is computed from the current records.

- [ ] **Step 8: Write failing request-orchestration tests**

Inject a fake `fetchImpl` and assert that `runIpIntel()`:

- starts exactly ten fixed requests;
- emits a pending snapshot before results;
- emits incremental updates;
- preserves timeout/error rows;
- aborts stale runs;
- never retries with another provider's data.

- [ ] **Step 9: Implement request orchestration**

Implement `fetchWithTimeout`, `runPool`, `runIpIntel`, and `runRouteEvidence` with a concurrency limit of four and per-source timeout. IANA/RDAP resolves the authoritative RIR from the actual bootstrap response. When no ASN is supplied, `runRouteEvidence` first requests the seven IP-address sources, derives a real consensus ASN, and only then requests PeeringDB, RIPEstat Announced Prefixes, and CAIDA. If ASN discovery fails, those three remain explicitly blocked and the UI reports the actual attempted count.

- [ ] **Step 10: Write and implement isolated STUN tests**

Use an injected `createPeerConnection` double to prove that every node gets a separate connection containing exactly one `iceServers` URL, that the first `srflx` candidate is attributed to that node, and that timeout returns no borrowed IP.

Implement `probeStunNode()` and `runStunNodes()` with a three-node concurrency pool and cancellation.

- [ ] **Step 11: Run tests and commit the evidence core**

Run `npm run test:ipcx` and expect all evidence-core tests to pass while source contracts still fail on the HTML.

```bash
git add ipcxEvidence.js tests/ipcx-evidence.test.mjs
git commit -m "feat: add live ten-source evidence core"
```

### Task 3: Replace static IPCX records with live state

**Files:**
- Modify: `index-ipcx.html`

- [ ] **Step 1: Load the evidence core**

Add `<script src="ipcxEvidence.js"></script>` before the inline page controller and fail visibly if `globalThis.AISGIpEvidence` is unavailable.

- [ ] **Step 2: Replace simulated observations**

Remove the fixed `observations`, `sourceRecords`, `dnsResolverRecords`, and `stunNodeRecords`. Initialize state with browser-derived timezone/languages and pending records returned by the evidence core:

```js
const state = {
  ...existingUiState,
  runId: 0,
  runController: null,
  completedAt: null,
  observations: createEmptyObservations(),
  ipIntel: evidenceApi.createPendingRecords(evidenceApi.IP_INTEL_SOURCES),
  routes: evidenceApi.createPendingRecords(evidenceApi.ROUTE_SOURCES),
  stun: evidenceApi.createPendingRecords(evidenceApi.STUN_NODES),
  dns: []
};
```

- [ ] **Step 3: Make evidence catalogs derived and mutable**

Replace the frozen one-time `evidenceCatalog` with `buildEvidenceCatalog(state)`. Ensure these sets always have ten records: `asnOrganization`, `geoVotes`, `exitQualitySources`, `networkTypeSources`, `riskSourceRecords`, `conflictSources`, `sourceCoverage`, `ipIntelSources`, `routeSources`, and `stunNodes`.

- [ ] **Step 4: Render current source states**

Update `renderEvidenceLists()` to replace existing evidence sections on each state update. The caption must show “实时检测 · 可用 N / 10” and rows must use truthful status labels such as “检测中”“可用”“字段缺失”“路径不同”“超时”“限流”“HTTP 403”.

- [ ] **Step 5: Bind ten-source summaries to row headers**

Update the values and detail copy for `ASN 与组织`, `多源地区判断`, `主流地区`, `冲突检查`, `网络标签共识`, `IP 情报来源`, and `路由与注册来源` after every incremental result. Do not leave static `6 项`, `6 票`, `4 / 4`, or `2 / 2` text in the HTML.

- [ ] **Step 6: Run the first live detection on page load**

Implement `runLiveDetection({ reveal })` which increments `runId`, aborts the previous controller, resets evidence, runs IP intelligence, derives the target IP, then runs route and STUN evidence. Late results check both `runId` and `AbortSignal` before rendering.

- [ ] **Step 7: Connect recheck Loading to real completion**

Replace fixed result generation in `runRecheck()` with `await runLiveDetection({ reveal: true })`. Keep a short minimum display duration, but do not reveal until all requests settle or their real timeouts expire. Remove “本地模拟结果已更新”.

- [ ] **Step 8: Derive copy text from live state**

Generate summary and AI report counts from current records. Insert:

```text
AI Signal Guard
https://betaer.github.io/AiSignalGuard/
```

after the AI instruction paragraph. Replace the last requested-answer item with a statement about failed or incomplete live sources, not static demo limitations.

- [ ] **Step 9: Run tests and commit live page binding**

Run `npm run test:ipcx`.

Expected: data and count contracts pass; layout/back-to-top contracts may still fail.

```bash
git add index-ipcx.html
git commit -m "feat: render live ten-source ipcx results"
```

### Task 4: Correct spacing and back-to-top behavior

**Files:**
- Modify: `index-ipcx.html`

- [ ] **Step 1: Equalize secondary-detail padding**

Change desktop CSS to:

```css
.signal-row-body {
  padding: 12px 14px 14px;
  border-top: 1px solid var(--line);
  background: var(--surface-soft);
}
```

Keep mobile at `10px 11px 12px`. Verify `.row-detail-grid` and `.metric-evidence` share the same left/right content edge.

- [ ] **Step 2: Add an inaccessible hidden state for back-to-top**

Add CSS using `data-visible`:

```css
#floating-top[data-visible="false"] {
  display: none;
}
```

Implement `updateBackToTopVisibility()` using `window.scrollY >= window.innerHeight`, and update `aria-hidden` plus `tabIndex`. Use one passive scroll listener throttled by `requestAnimationFrame`, and rerun on resize.

- [ ] **Step 3: Run contract tests**

Run `npm run test:ipcx`.

Expected: all IPCX tests pass.

- [ ] **Step 4: Commit layout behavior**

```bash
git add index-ipcx.html
git commit -m "fix: align ipcx details and defer back to top"
```

### Task 5: Include IPCX in builds and worker asset tests

**Files:**
- Modify: `build/sites-vite-plugin.js`
- Modify: `tests/sites-worker.test.mjs`

- [ ] **Step 1: Write the failing build-asset test**

Assert `/index-ipcx.html` returns HTML containing `ipcxEvidence.js`, and `/ipcxEvidence.js` returns JavaScript exposing `AISGIpEvidence`.

- [ ] **Step 2: Run the worker test**

Run `npm run build && node --test tests/sites-worker.test.mjs`.

Expected: FAIL because the new files are not copied into `dist/client`.

- [ ] **Step 3: Expose the IPCX assets**

Add `index-ipcx.html` and `ipcxEvidence.js` to `STATIC_FILES` in `build/sites-vite-plugin.js`.

- [ ] **Step 4: Run tests and commit**

Run `npm run build && node --test tests/sites-worker.test.mjs` and expect PASS.

```bash
git add build/sites-vite-plugin.js tests/sites-worker.test.mjs
git commit -m "build: publish live ipcx evidence assets"
```

### Task 6: Full automated and visual verification

**Files:**
- Modify if necessary: `tests/e2e-smoke.mjs`
- Create test artifacts only under: `output/playwright/`

- [ ] **Step 1: Run all static checks**

Run:

```bash
npm run check
```

Expected: all unit tests, build checks and worker tests pass.

- [ ] **Step 2: Run full E2E regression**

Run:

```bash
npm run test:e2e
```

Expected: all existing scenarios pass without regressions.

- [ ] **Step 3: Verify desktop live UI with Playwright CLI**

Open `http://127.0.0.1:4173/index-ipcx.html`, snapshot, expand `ASN 与组织` and `多源地区判断`, and assert each evidence list has ten rows. Capture a desktop screenshot after sources settle.

- [ ] **Step 4: Verify 390px and 320px mobile UI**

At each width, assert no horizontal overflow, all evidence values wrap, and the detail body's left/right gap differs by at most 2px.

- [ ] **Step 5: Verify back-to-top threshold**

At desktop and mobile widths:

- at `scrollY = 0`, the button is hidden and not focusable;
- at `scrollY < innerHeight`, it remains hidden;
- at `scrollY >= innerHeight`, it becomes visible and focusable;
- after activating it and returning to the first viewport, it hides again.

- [ ] **Step 6: Verify failure honesty**

Block one provider and delay another. Confirm the UI still contains ten rows, labels those two sources accurately, excludes them from the valid vote count, and never copies another source's values into them.

- [ ] **Step 7: Final diff and commit**

Run:

```bash
git diff --check
git status --short
```

Review every changed file, then commit any final test-only refinements with:

```bash
git add tests/e2e-smoke.mjs
git commit -m "test: verify live ipcx evidence experience"
```

## Self-review result

- Spec coverage: all ten-source mappings, live failures, no fallback values, STUN, dynamic copy, spacing, build publication and back-to-top behavior are assigned to explicit tasks.
- Placeholder scan: no deferred implementation markers or unspecified test steps remain.
- Type consistency: every UI collection derives from the `SourceRecord` fields defined in Task 2; source IDs and state names remain consistent across tests and rendering.
