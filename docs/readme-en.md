# AI Signal Guard

[简体中文](../README.md) · [English](readme-en.md)

## Browser-side AI network and environment signal checks

Cross-check exit IP, DNS, WebRTC, timezone, language, browser environment, and AI-service paths to quickly surface leaks, conflicts, and anomalous signals.

Designed for network troubleshooting, environment-consistency checks, and preflight testing before using AI services such as Claude, ChatGPT, and Gemini.

[Run the diagnostic](https://betaer.github.io/AiSignalGuard/) · [Report an issue](https://github.com/betaer/AiSignalGuard/issues/new/choose) · [View source](https://github.com/betaer/AiSignalGuard) · [![Visitors](https://visitor-badge.laobi.icu/badge?page_id=betaer.AiSignalGuard)](https://github.com/betaer/AiSignalGuard)

[![AI Signal Guard social preview](https://raw.githubusercontent.com/betaer/AiSignalGuard/main/tuiguang/social-preview.png)](https://github.com/betaer/AiSignalGuard/blob/main/tuiguang/social-preview.png)

AI Signal Guard does not determine a visitor's real nationality, occupation, or personal identity, and it does not promise account access or platform-risk avoidance. It answers a narrower question: **which network and environment signals are visible to different endpoints, whether those signals agree, and whether the available evidence is sufficient.**

> The network reference score is based on signals observable in the current run. It does not represent platform-account status, ban probability, or an internal platform risk-control decision.

## Core advantages

- **Multi-source evidence:** IP intelligence, route registration, WebRTC, and STUN keep source-level states and evidence.
- **Failure is not safety:** timeouts, missing fields, and failed requests remain failed or unknown and do not become positive votes.
- **Traceable conclusions:** summaries, scores, reasons, and suggestions link back to their evidence modules.
- **Explicit boundaries:** local browser computation, third-party requests, heuristic inference, and unverifiable business state are kept separate.

## Core capabilities

| Module | What it checks | Why it matters |
|---|---|---|
| Exit IP | IPv4/IPv6, country and region, ASN, organization, network type, source conflicts | Shows what different address families and endpoints observe |
| DNS leak | Standard and deeper DNS probes, resolver ownership | Checks whether DNS follows the expected network path |
| WebRTC | Primary public candidates, supplemental STUN evidence, mDNS/private-address classification | Finds differences between browser candidates and HTTP exit addresses |
| Route and registry | IANA, RIR, RIS, WHOIS, Cymru, PeeringDB, and related evidence | Cross-checks ASN, prefix, and registered organization |
| Environment consistency | Browser language, system timezone, emoji, Chinese fonts, exposed device information | Finds obvious contradictions across geography, language, timezone, and browser signals |
| Browser fingerprint surface | Canvas, local summaries, screen, platform, logical processors, memory estimate, WebAudio | Shows what the current browser exposes or can calculate |
| Service connectivity | AI, content, commerce, developer, global, and China-focused sites | Determines whether this browser request path obtained a response |
| AI path and status | Endpoint-side country/node labels and official status APIs | Separates path issues from publicly reported platform incidents |
| Reports and sharing | Redacted Markdown diagnostics and short summaries | Supports manual review or user-controlled sharing with an AI assistant |

## Multi-source evidence architecture

### Deterministic source registries

The current v2 build validates these registry sizes and unique entries at startup:

| Evidence pool | Size | Scheduling |
|---|---:|---|
| IP-intelligence providers | 10 per available address family | IPv4 and IPv6 are queried and summarized separately |
| Route and registry providers | 10 per available address family | Starts after an ASN consensus exists for that family |
| Primary WebRTC pool | 10 independent nodes | Each node uses its own `RTCPeerConnection` |
| Supplemental STUN pool | 10 independent nodes | Does not reuse primary-pool candidates and preserves its own terminal state |

The two WebRTC/STUN pools produce up to 20 node attempts in total, but the product reports them as “10 primary + 10 supplemental” because the pools have different diagnostic roles.

### Only eligible evidence votes

Each source record preserves pending, successful, partial, timeout, and error states. A record becomes `voteEligible` only after normalization and after it satisfies the requirements of the current metric:

```text
eligible source → may participate in country / ASN / organization consensus
timeout or error → remains failure evidence and does not vote
missing field   → contributes only available fields and does not fabricate a conflict
```

Coverage means “the share of real sources that returned fields usable for the current metric.” It is neither page-loading progress nor a safety score.

### Per-provider normalization

IP providers use different schemas for country, region, ASN, organization, and proxy classifications. The project maintains provider-specific adapters and then converts responses into a common record. A field absent from one source is not guessed from unrelated fields.

### Network reference score and coverage

- The network reference score combines observable IP, route, DNS, WebRTC, and environment differences to help prioritize follow-up checks.
- Coverage counts only fields that were actually returned and usable for the current metric; it is not loading progress and does not turn timeouts or failures into positive evidence.
- When core evidence is insufficient, the product avoids pseudo-precise conclusions. Source conflicts remain visible and link back to their details.

The network reference score is based on signals observable in the current run. It does not represent platform-account status, ban probability, or an internal platform risk-control decision.

## Diagnostic semantics

### Connectivity is not account state

Service probes have two terminal labels:

- **Reachable:** a target or fallback endpoint produced a browser-observable HTTP response.
- **Not connected this time:** neither the primary nor fallback probe produced a usable response signal in this run.

“Reachable” does not mean logged in, account enabled, region unlocked, payments working, or the complete product functioning. “Not connected this time” does not prove an outage; browser extensions, DNS/TLS failure, cross-origin policy, network policy, and timeout can all cause it.

### AI path is not physical location

Country or node information returned by ChatGPT, Claude, OpenAI, Perplexity, or Cloudflare describes the path visible to that endpoint. It is not the physical location of a user, carrier, or server. Split tunneling, WARP, Private Relay, and domain-based proxy rules may give different endpoints different exits; the page preserves those differences.

### Fingerprint summaries are not identities

Canvas, WebAudio, and environment summaries describe visible browser signals. Equal summaries do not prove the same user, and different summaries do not prove different devices. The WebAudio check performs three offline renders with `OfflineAudioContext`; it does not open a live audio path or request microphone access.

## Privacy and data boundaries

AI Signal Guard is a static frontend application without a project-owned diagnostic-data backend, but several checks necessarily connect to public third-party services.

| Data or operation | External request | Detail |
|---|---:|---|
| Language, timezone, fonts, emoji, local fingerprint summaries | No | Read or computed in the current browser |
| Three-round WebAudio check | No | Uses an offline audio graph only |
| Exit IP and multi-source intelligence | Yes | Providers observe normal request metadata |
| DNS diagnostics | Yes | Uses third-party DNS-leak services |
| WebRTC/STUN | Yes | Connects to STUN services to obtain candidates |
| Connectivity, AI path, official status | Yes | Requests public endpoints or fallbacks |
| Share summary | No | Clipboard only; excludes IP, DNS, and fingerprint raw values |
| Copy diagnostic for AI | No | Clipboard only; never auto-sends to an AI service |
| Google Analytics | Yes | Basic visit measurement; diagnostic results are not uploaded as analytics events |

Third-party services have their own logging, privacy, and availability boundaries. In highly sensitive environments, consider an isolated browser or controlled network before running external checks.

## Report redaction

“Copy diagnostic for AI” applies a fixed redaction policy:

- IPv4 values preserve network-level context while hiding the host portion.
- IPv6 values retain only a limited prefix, not the full address.
- DNS, WebRTC, and AI-path addresses pass through the same redaction layer.
- Raw mDNS, Canvas, and WebAudio identifiers are omitted.
- Share summaries contain coverage, major anomalies or conflicts, and follow-up suggestions only.

The user chooses where to paste the report. The page does not automatically open an AI service, send the report, or create an external session.

## Appropriate uses

- Verify whether a VPN, proxy, WARP, or split-tunnel rule behaves as expected.
- Check whether DNS and WebRTC expose addresses different from the HTTP exit.
- Compare IPv4/IPv6, ASN, organization, region, language, and timezone consistency.
- Understand the Canvas, WebAudio, font, and device-summary surface visible to a webpage.
- Separate endpoint-path failures, browser-probe failures, and public platform incidents.
- Produce a redacted, human-reviewable network diagnostic report.

## Not appropriate for

- It is not a VPN, anonymity network, anti-fingerprinting browser, or endpoint-protection product.
- It cannot predict bans, guarantee access, prove account safety, or bypass platform risk controls.
- Heuristic network type, geography, and identity profiles are not legal, compliance, or identity-verification conclusions.
- A browser cannot verify facts that require system privileges, carrier-internal data, or platform-account permissions.

## Quick start

1. Open [https://betaer.github.io/AiSignalGuard/](https://betaer.github.io/AiSignalGuard/).
2. On the first visit, choose to Star the project or select “test first” to continue. Refreshes and reruns within 12 hours do not repeat the prompt.
3. Wait for IP, DNS, WebRTC, route, AI-service path, and browser-environment evidence to complete in stages.
4. Read the network reference score, coverage, and anomaly notices before expanding source-level evidence.
5. When needed, copy the redacted Markdown report and paste it manually into a destination you trust.

## Versioned entry points

| Entry | URL | Purpose |
|---|---|---|
| Current release | [Project root](https://betaer.github.io/AiSignalGuard/) | Tracks the latest production release, currently v2 |
| v1 archive | [v1/](https://betaer.github.io/AiSignalGuard/v1/) | Preserves previous behavior |
| v2 archive | [v2/](https://betaer.github.io/AiSignalGuard/v2/) | Fixed v2 entry |

## Local development

Node.js `>= 22.13.0` is required:

```bash
npm install
npm run dev
```

Production build:

```bash
npm run build
```

## Tests and verification

```bash
npm test
npm run test:e2e
```

Full pre-release verification:

```bash
npm run check:full
```

The suite covers identity profiles, source registries, `voteEligible` semantics, versioned pages, IPCX contracts, privacy toggles, report redaction, service probes, keyboard behavior, responsive viewports, and build artifacts. `npm run test:connectivity-live` contacts real Claude and Perplexity endpoints and should be treated as a separate network-contract check.

## Project layout

```text
.
├── index.html                     # Current production page and inline diagnostics
├── networkEvidence.js             # IP, route, WebRTC/STUN sources and normalization
├── identityProfiles.js            # Retained experimental profile configuration
├── identityAnalysis.js            # Retained experimental profile analysis
├── signalSemantics.js             # Signal states and semantic boundaries
├── signalGuardApp.js              # IPCX application controller
├── v1/ / v2/                      # Fixed version entry points
├── tests/                         # Node.js and Playwright regression tests
├── assets/                        # Product captures, social assets, and icons
├── docs/readme-en.md              # English README
└── worker/ / build/               # Build and hosting adapters
```

## SEO, GEO, and machine-readable information

- The page includes a canonical URL, Open Graph metadata, a Twitter Card, and a social preview image.
- `WebSite`, `SoftwareApplication`, and `BreadcrumbList` JSON-LD describe the product and site hierarchy.
- Static first-screen and explanatory content remain readable to crawlers that do not fully execute JavaScript.
- Root-site `robots.txt` and `sitemap.xml` list the canonical product URL, with project facts available for generative retrieval.

## Boundaries and licensing

- The network reference score and risk labels are diagnostic heuristics, not platform-account status, ban probability, or internal platform-risk decisions.
- Third-party endpoints can change, rate-limit, conflict, or become unavailable. The page preserves failure evidence where possible but cannot guarantee external-source availability.
- The repository currently has no open-source license. Publicly readable source does not by itself grant permission to copy, modify, or redistribute it.
