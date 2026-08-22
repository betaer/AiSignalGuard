# IPCX Remix v1.3.0 Results Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Make the v1.3.0 Remix page show all 19 real results on the homepage and structured details on all seven tool routes while preserving the static browser-only constraint.

**Architecture:** Copy the v1.2.0 Remix page/controller into versioned v1.3.0 files, keep one canonical set of 19 signal rows, and derive homepage/tool projections from the existing live state. Tool projections are read-only renderers: IP, DNS, STUN, Multi and Latency use existing records; CDN and Split expose itemized browser/server boundaries without inventing results.

**Tech Stack:** Vanilla HTML/CSS/JavaScript, Hash routing, browser Fetch/WebRTC APIs, Node node:test, Playwright Chromium E2E, Vite static-site plugin.

---

### Task 1: Register v1.3.0 and write failing contracts

**Files:** Create index-ipcx-remix-v1.3.0.html and ipcx-remix-v1.3.0.js from v1.2.0; create tests/ipcx-remix-v1.3.0-contract.test.mjs; modify package.json and build/sites-vite-plugin.js.

- [ ] Step 1: Copy the page/controller, replace only new-file version references with v1.3.0, and point the new HTML at ipcx-remix-v1.3.0.js.
- [ ] Step 2: Add a contract that asserts 19 data-core-result-ref entries and one data-tool-result-list for each tool. Every list template must contain data-probe-id, data-probe-name, data-probe-state, and data-probe-evidence.
- [ ] Step 3: Run the contract before implementation.

```bash
npm test -- --test-name-pattern='v1.3.0|首页结果|工具列表'
```

Expected: FAIL because the copied page has no v1.3.0 list containers.

- [ ] Step 4: Commit the red contract and versioned shell.

```bash
git add index-ipcx-remix-v1.3.0.html ipcx-remix-v1.3.0.js tests/ipcx-remix-v1.3.0-contract.test.mjs package.json build/sites-vite-plugin.js
git commit -m 'test: define ipcx remix v1.3.0 result lists'
```

### Task 2: Add homepage result projections

**Files:** Modify index-ipcx-remix-v1.3.0.html, ipcx-remix-v1.3.0.js, and the v1.3.0 contract/UI tests.

- [ ] Step 1: Add data-overview-result-list='core' below the summary card. Generated items use data-core-result-ref, data-result-state, a value, coverage text, and a Hash link.
- [ ] Step 2: Define the exact 19-ID mapping: position-consistency, asn-organization, geo-cross-check, exit-ip-quality, network-type, risk-proxy-labels, system-timezone, browser-language, emoji-rendering, chinese-fonts, dns-leak, dns-region-consistency, webrtc-leak, stun-nodes, majority-region, conflict-check, network-label-consensus, ip-intel-sources, route-registry-sources.
- [ ] Step 3: Implement buildCoreResultModels(state) and renderOverviewResultIndex(models) from canonical state, never from hidden route text. Call the renderer at the end of render().
- [ ] Step 4: E2E must navigate #/overview, wait for detection idle, assert 19 visible projection items, and verify the first item is inside the first desktop viewport.
- [ ] Step 5: Commit the homepage projection.

```bash
git add index-ipcx-remix-v1.3.0.html ipcx-remix-v1.3.0.js tests/ipcx-remix-v1.3.0-*
git commit -m 'feat: show remix v1.3.0 results on overview'
```

### Task 3: Add structured tool result lists

**Files:** Modify the seven tool views and CSS in index-ipcx-remix-v1.3.0.html; modify the registry/renderers in ipcx-remix-v1.3.0.js; modify v1.3.0 contract, semantics and UI tests.

- [ ] Step 1: Retain purpose/boundary copy but add data-tool-result-list='tool' to every tool view. Do not add fake start buttons.
- [ ] Step 2: Implement renderProbeList(container, models), creating one article per model with data-probe-id, data-probe-name, data-probe-state, data-probe-evidence, status text, and optional sensitive nodes.
- [ ] Step 3: Map IP from publicIp and all 10 ipIntel records; DNS from dns.records plus the bash.ws lifecycle; STUN from all 10 stun records; Multi from 10 IP + 10 Route + 10 STUN; Latency from existing latencyMs; CDN and Split from explicit skipped rows with exact browser/CORS/server reasons.
- [ ] Step 4: Deterministic semantics must assert IP=10, DNS fixture count, STUN=10, Multi=30, latency rows, and only success/warning/failed/skipped/requires-server states.
- [ ] Step 5: Commit tool lists.

```bash
git add index-ipcx-remix-v1.3.0.html ipcx-remix-v1.3.0.js tests/ipcx-remix-v1.3.0-*
git commit -m 'feat: add remix v1.3.0 tool detail lists'
```

### Task 4: Finish routing, privacy and regression coverage

**Files:** Modify ipcx-remix-v1.3.0.js and package.json; create a file E2E only if the existing harness cannot cover file URLs.

- [ ] Step 1: Call renderToolResultLists(state) from the same render pass as canonical rows; route switching only toggles visibility and never starts a second network run.
- [ ] Step 2: Privacy E2E must mask raw IP, ASN, organization, and candidates in both overview and tool lists, and in copied summary and AI report.
- [ ] Step 3: For all 5 result routes and 7 tool routes assert one active view, active heading focus, and a visible list in the active view; never read a hidden view as the answer.
- [ ] Step 4: Run all viewports and full regression.

```bash
npm run test:ipcx-remix-v1.3.0-ui
npm run test:ipcx-remix-v1.3.0-semantics
npm run check:full
```

Expected: all existing suites plus v1.3.0 suites pass; controller coverage remains at least 80%; originals and v1.2.0 remain unchanged.

- [ ] Step 5: Commit the completed implementation.

```bash
git add index-ipcx-remix-v1.3.0.html ipcx-remix-v1.3.0.js tests package.json build/sites-vite-plugin.js
git commit -m 'feat: ship ipcx remix v1.3.0 result center'
```

## Self-review checklist

- Every design requirement maps to a task: homepage 19 rows (Task 2), all seven tools (Task 3), server boundaries (Task 3), routing/privacy (Task 4), tests (Tasks 1–4).
- No step relies on a placeholder or an unintroduced function; shared renderer and model builders are defined before use.
- v1.3.0 files stay isolated from dirty pre-existing user changes and v1.2.0 rollback files.
