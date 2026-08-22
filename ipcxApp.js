(function bootstrapIpcxPage() {
  "use strict";

  var evidenceApi = globalThis.AISGIpEvidence;
  var semanticsApi = globalThis.AISGIpSemantics;
  var starPolicyApi = globalThis.AISGStarPromptPolicy;
  if (!evidenceApi) {
    throw new Error("IPCX 实时证据模块加载失败");
  }
  if (!semanticsApi) {
    throw new Error("IPCX 状态语义模块加载失败");
  }

  var GITHUB_REPO = "betaer/AiSignalGuard";
  var PROJECT_URL = "https://betaer.github.io/AiSignalGuard/";
  var STAR_CACHE_KEY = "aisg-github-stars";
  var STAR_CACHE_TTL_MS = 30 * 60 * 1000;
  var $ = function (selector) {
    return document.querySelector(selector);
  };
  var $$ = function (selector) {
    return Array.from(document.querySelectorAll(selector));
  };
  var starPromptPolicy = starPolicyApi
    ? starPolicyApi.create()
    : { shouldPrompt: function () { return false; }, remember: function () {} };

  var rowDefinitions = Object.freeze([
    { id: "position-consistency", title: "位置一致性", evidenceSet: "positionConsistency", evidenceTitle: "一致性指标" },
    { id: "asn-organization", title: "ASN 与组织", evidenceSet: "asnOrganization", evidenceTitle: "归属来源" },
    { id: "geo-cross-check", title: "多源地区判断", evidenceSet: "geoVotes", evidenceTitle: "地理来源" },
    { id: "exit-ip-quality", title: "出口 IP 质量", evidenceSet: "exitQualitySources", evidenceTitle: "质量来源" },
    { id: "network-type", title: "网络类型", evidenceSet: "networkTypeSources", evidenceTitle: "类型来源" },
    { id: "risk-proxy-labels", title: "威胁与代理标签", evidenceSet: "riskSourceRecords", evidenceTitle: "风险与代理来源" },
    { id: "system-timezone", title: "系统时区", evidenceSet: null, evidenceTitle: null },
    { id: "browser-language", title: "浏览器语言", evidenceSet: "languageSignals", evidenceTitle: "语言指标" },
    { id: "emoji-rendering", title: "Emoji 渲染", evidenceSet: "emojiSignals", evidenceTitle: "渲染指标" },
    { id: "chinese-fonts", title: "中文字体", evidenceSet: "fontSignals", evidenceTitle: "字体指标" },
    { id: "dns-leak", title: "DNS 泄漏", evidenceSet: "dnsResolvers", evidenceTitle: "解析器明细" },
    { id: "dns-region-consistency", title: "DNS 地区一致性", evidenceSet: "dnsResolvers", evidenceTitle: "解析器地区" },
    { id: "webrtc-leak", title: "WebRTC 泄漏", evidenceSet: "webrtcCandidates", evidenceTitle: "HTTP 与 STUN 候选" },
    { id: "stun-nodes", title: "STUN 节点", evidenceSet: "stunNodes", evidenceTitle: "STUN 节点" },
    { id: "majority-region", title: "主流地区", evidenceSet: "geoVotes", evidenceTitle: "地理投票" },
    { id: "conflict-check", title: "冲突检查", evidenceSet: "conflictSources", evidenceTitle: "逐来源字段" },
    { id: "network-label-consensus", title: "网络标签共识", evidenceSet: "sourceCoverage", evidenceTitle: "来源标签与可用性" },
    { id: "ip-intel-sources", title: "IP 情报来源", evidenceSet: "ipIntelSources", evidenceTitle: "IP 情报来源" },
    { id: "route-registry-sources", title: "路由与注册来源", evidenceSet: "routeSources", evidenceTitle: "路由与注册来源" },
  ]);
  var rowEvidenceMap = Object.freeze(
    Object.fromEntries(
      rowDefinitions
        .filter(function (row) { return row.evidenceSet; })
        .map(function (row) {
          return [row.id, Object.freeze({ set: row.evidenceSet, title: row.evidenceTitle })];
        }),
    ),
  );

  var timezone = "未知";
  try {
    timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || "未知";
  } catch (error) {}
  var languages = Array.isArray(navigator.languages) && navigator.languages.length
    ? navigator.languages.slice()
    : [navigator.language || "未知"];

  var state = {
    privacy: false,
    running: false,
    runCount: 0,
    runId: 0,
    runController: null,
    pendingRecheck: false,
    completedAt: null,
    publicIp: { state: "pending", ip: null, status: "等待检测" },
    observations: {
      exitIp: null,
      timezone: timezone,
      languages: languages,
      countryCode: null,
      countryName: null,
      city: null,
      asn: null,
      organization: null,
      networkType: null,
    },
    ipIntel: evidenceApi.createPendingRecords(evidenceApi.IP_INTEL_SOURCES),
    routes: evidenceApi.createPendingRecords(evidenceApi.ROUTE_SOURCES),
    stun: evidenceApi.createPendingRecords(evidenceApi.STUN_NODES),
    dns: { state: "pending", running: false, records: [], error: null },
    fingerprints: {
      v3: {
        label: "LOCAL STABLE HASH",
        value: "计算中…",
        description: "本页未加载 FingerprintJS v3+ SDK；这里显示由当前浏览器本地稳定信号生成的摘要，不冒充官方 Visitor ID。",
      },
      v2: {
        label: "LOCAL BROAD HASH",
        value: "计算中…",
        description: "本页未加载 FingerprintJS2；这里使用更宽的本地浏览器信号生成一次性摘要，并明确与官方算法区分。",
      },
      tls: {
        label: "JA3 / JA4",
        value: "浏览器端不可读取",
        description: "普通网页脚本无法直接读取 TLS ClientHello，因此不生成或伪造 JA3 / JA4 值。",
      },
    },
    localSignals: collectLocalSignals(),
  };

  function collectLocalSignals() {
    var platform = navigator.userAgentData && navigator.userAgentData.platform
      ? navigator.userAgentData.platform
      : navigator.platform || "未知";
    var screenValue = typeof screen !== "undefined"
      ? screen.width + " × " + screen.height + " · DPR " + (window.devicePixelRatio || 1)
      : "不可读取";
    var canvasAvailable = false;
    try {
      var canvas = document.createElement("canvas");
      canvasAvailable = Boolean(canvas.getContext("2d"));
    } catch (error) {}
    var fontNames = ["PingFang SC", "Microsoft YaHei", "Songti SC", "Noto Sans CJK SC"];
    var detectedFonts = [];
    if (document.fonts && typeof document.fonts.check === "function") {
      detectedFonts = fontNames.filter(function (font) {
        try {
          return document.fonts.check('16px "' + font + '"');
        } catch (error) {
          return false;
        }
      });
    }
    return {
      platform: platform,
      userAgent: navigator.userAgent || "未知",
      screen: screenValue,
      hardwareConcurrency: navigator.hardwareConcurrency || null,
      deviceMemory: navigator.deviceMemory || null,
      colorDepth: typeof screen !== "undefined" ? screen.colorDepth : null,
      canvasAvailable: canvasAvailable,
      detectedFonts: detectedFonts,
    };
  }

  function invariant(condition, message) {
    if (!condition) throw new Error("[IPCX] " + message);
  }

  function validatePageContract() {
    invariant(evidenceApi.IP_INTEL_SOURCES.length === 10, "IP 情报来源必须是 10 家");
    invariant(evidenceApi.ROUTE_SOURCES.length === 10, "路由与注册来源必须是 10 路");
    invariant(evidenceApi.STUN_NODES.length === 10, "STUN 节点必须是 10 个");
    var rows = $$(".signal-row");
    invariant(rows.length === rowDefinitions.length, "详情行数量与定义不一致");
    rowDefinitions.forEach(function (definition) {
      var row = document.querySelector('.signal-row[data-row-id="' + definition.id + '"]');
      invariant(row, "缺少详情行 " + definition.id);
    });
  }

  function stringValue(value) {
    if (value === null || value === undefined) return null;
    var text = String(value).trim();
    return text && text !== "null" && text !== "undefined" ? text : null;
  }

  function boolLabel(value) {
    return value === null || value === undefined ? "未提供" : value ? "是" : "否";
  }

  function latencyLabel(record) {
    return Number.isFinite(record.latencyMs) ? record.latencyMs + "ms" : "未计时";
  }

  function sourceTone(record) {
    if (record.state === "success") return "good";
    if (record.state === "partial" || record.state === "timeout" || record.state === "blocked") return "warn";
    if (record.state === "pending" || record.state === "loading") return "neutral";
    return "bad";
  }

  function sourceUsable(record) {
    return record.state === "success" || record.state === "partial";
  }

  function sourceMeta(record, fieldSummary) {
    return [fieldSummary, latencyLabel(record)].filter(Boolean).join(" · ");
  }

  function intelFields(record) {
    var fields = [];
    if (record.countryCode || record.countryName) fields.push("国家");
    if (record.city) fields.push("城市");
    if (record.asn) fields.push("ASN");
    if (record.organization) fields.push("组织");
    if (record.networkType) fields.push("类型");
    if (record.proxy !== null || record.hosting !== null) fields.push("风险");
    return fields.length ? fields.join(" / ") : "无可用字段";
  }

  function toEvidenceItem(record, value, options) {
    var config = options || {};
    return {
      name: record.name,
      meta: sourceMeta(record, config.meta || intelFields(record)),
      value: value || record.detail || "本轮未取得可核对结果",
      status: record.status || evidenceApi.statusLabel(record.state),
      tone: sourceTone(record),
      sensitive: config.sensitive || null,
      rawState: record.state,
      attempted: Boolean(record.attempted),
      usable: config.usable === undefined ? Boolean(record.voteEligible) : Boolean(config.usable),
    };
  }

  function simpleConsensus(records, field) {
    var counts = new Map();
    records.forEach(function (record) {
      if (!record.voteEligible) return;
      var value = stringValue(record[field]);
      if (!value) return;
      var key = value.toLowerCase();
      var entry = counts.get(key) || { value: value, votes: 0 };
      entry.votes += 1;
      counts.set(key, entry);
    });
    var ranked = Array.from(counts.values()).sort(function (left, right) {
      return right.votes - left.votes || left.value.localeCompare(right.value);
    });
    return ranked[0] || { value: null, votes: 0 };
  }

  function conflictState(record, country, asn, organization) {
    if (!sourceUsable(record)) return { label: record.status, tone: sourceTone(record) };
    var comparison = semanticsApi.compareComparableFields(record, {
      countryCode: country,
      asn: asn,
      organization: organization,
    });
    if (comparison.conflicts.length) {
      return { label: comparison.conflicts.join(" / ") + "冲突", tone: "bad" };
    }
    if (!comparison.comparable) return { label: "字段不足", tone: "neutral" };
    return { label: record.state === "partial" ? "已提供字段一致" : "一致", tone: record.state === "partial" ? "warn" : "good" };
  }

  function browserLanguageEvidence() {
    return state.observations.languages.map(function (language, index) {
      return {
        name: index === 0 ? "navigator.language" : "navigator.languages[" + index + "]",
        meta: index === 0 ? "首选语言" : "语言优先级 " + (index + 1),
        value: language,
        status: "已读取",
        tone: "good",
        rawState: "success",
        attempted: true,
        usable: true,
      };
    });
  }

  function dnsEvidence() {
    if (state.dns.records.length) {
      return state.dns.records.map(function (record) {
        return {
          name: record.name,
          meta: [record.countryName || record.countryCode || "地区未知", record.asn || "ASN 未提供"]
            .join(" · "),
          value: record.observedIp || "未提供地址",
          status: record.status,
          tone: sourceTone(record),
          sensitive: record.observedIp ? "ip" : null,
          rawState: record.state,
          attempted: Boolean(record.attempted),
          usable: Boolean(record.observedIp),
        };
      });
    }
    return [{
      name: "bash.ws DNS Leak Test",
      meta: "权威 DNS 探针",
      value: state.dns.error || (state.dns.running ? "正在等待解析器回传" : "等待检测"),
      status: state.dns.error ? "检测失败" : state.dns.running ? "检测中" : "等待检测",
      tone: state.dns.error ? "bad" : "neutral",
      rawState: state.dns.error ? "network_error" : state.dns.running ? "loading" : "pending",
      attempted: state.dns.state !== "pending",
      usable: false,
    }];
  }

  function buildEvidenceCatalog() {
    var country = evidenceApi.computeCountryConsensus(state.ipIntel);
    var asn = evidenceApi.computeAsnConsensus(state.ipIntel);
    var organization = evidenceApi.computeOrganizationConsensus(state.ipIntel);
    var intel = state.ipIntel;
    var route = state.routes;
    var stun = state.stun;
    var position = [
      {
        name: "公网出口位置",
        meta: "10 家 IP 情报的主流结果",
        value: country.value
          ? [country.value, state.observations.city, state.observations.exitIp].filter(Boolean).join(" · ")
          : state.publicIp.status,
        status: country.value ? "已读取" : state.publicIp.status,
        tone: country.value ? "good" : sourceTone(state.publicIp),
        sensitive: state.observations.exitIp ? "ip" : null,
        rawState: state.publicIp.state,
        attempted: state.publicIp.state !== "pending",
        usable: Boolean(country.value),
      },
      {
        name: "系统时区",
        meta: "浏览器 Intl API",
        value: state.observations.timezone,
        status: "已读取",
        tone: "good",
        rawState: "success",
        attempted: true,
        usable: true,
      },
      {
        name: "浏览器语言",
        meta: "Navigator Languages API",
        value: state.observations.languages.join(" · "),
        status: "已读取",
        tone: "good",
        rawState: "success",
        attempted: true,
        usable: true,
      },
    ];

    var asnRows = intel.map(function (record) {
      return toEvidenceItem(
        record,
        (record.asn || "未提供 ASN") + " · " + (record.organization || "未提供组织"),
        { usable: Boolean(record.asn || record.organization) },
      );
    });
    var geoRows = intel.map(function (record) {
      var vote = record.voteEligible && record.countryCode && record.countryCode === country.value;
      var item = toEvidenceItem(
        record,
        [record.countryCode || record.countryName || "未提供国家", record.city || "未提供城市"].join(" · "),
        { usable: Boolean(record.countryCode || record.countryName) },
      );
      if (record.voteEligible && record.countryCode) {
        item.status = vote ? record.countryCode + " 票" : "地区分歧";
        item.tone = vote ? "good" : "bad";
      }
      return item;
    });
    var riskRows = intel.map(function (record) {
      return toEvidenceItem(
        record,
        "Proxy：" + boolLabel(record.proxy) + " · VPN：" + boolLabel(record.vpn) +
          " · Tor：" + boolLabel(record.tor) + " · Hosting：" + boolLabel(record.hosting),
        { usable: [record.proxy, record.vpn, record.tor, record.hosting].some(function (value) { return value !== null; }) },
      );
    });
    var typeRows = intel.map(function (record) {
      return toEvidenceItem(
        record,
        "网络类型：" + (record.networkType || "未提供") + " · 组织：" + (record.organization || "未提供"),
        { usable: Boolean(record.networkType) },
      );
    });
    var coverageRows = intel.map(function (record) {
      return toEvidenceItem(
        record,
        "字段：" + intelFields(record) + " · 观察地址：" + (record.observedIp || "未提供"),
        { sensitive: record.observedIp ? "ip" : null, usable: Boolean(record.voteEligible) },
      );
    });
    var conflictRows = intel.map(function (record) {
      var conflict = conflictState(record, country.value, asn.value, organization.value);
      var item = toEvidenceItem(
        record,
        "国家：" + (record.countryCode || "缺失") + " · ASN：" + (record.asn || "缺失") +
          " · 组织：" + (record.organization || "缺失"),
        { usable: Boolean(record.countryCode || record.asn || record.organization) },
      );
      item.status = conflict.label;
      item.tone = conflict.tone;
      return item;
    });
    var routeRows = route.map(function (record) {
      return toEvidenceItem(
        record,
        [record.asn, record.organization, record.prefix, record.registry].filter(Boolean).join(" · ") ||
          record.detail || "本轮未取得路由字段",
        { meta: "ASN / 前缀 / 注册组织", usable: Boolean(record.voteEligible) },
      );
    });
    var stunRows = stun.map(function (record) {
      var node = evidenceApi.STUN_NODES.find(function (source) { return source.id === record.id; });
      return toEvidenceItem(
        record,
        record.observedIp || record.detail || "未返回公网候选",
        { meta: (node ? node.url : "STUN") + " · " + latencyLabel(record), sensitive: record.observedIp ? "ip" : null, usable: Boolean(record.observedIp) },
      );
    });
    var webrtcRows = [{
      name: "HTTP 可见地址",
      meta: "ipify 出口观测",
      value: state.observations.exitIp || state.publicIp.status,
      status: state.publicIp.status,
      tone: sourceTone(state.publicIp),
      sensitive: state.observations.exitIp ? "ip" : null,
      rawState: state.publicIp.state,
      attempted: state.publicIp.state !== "pending",
      usable: Boolean(state.observations.exitIp),
    }].concat(stunRows.map(function (item) {
      return Object.assign({}, item, { name: "STUN · " + item.name });
    }));
    var emojiRows = [{
      name: "Canvas 2D",
      meta: "浏览器本地能力检查",
      value: state.localSignals.canvasAvailable ? "可创建 2D 渲染上下文" : "不可创建 2D 渲染上下文",
      status: state.localSignals.canvasAvailable ? "可用" : "不可用",
      tone: state.localSignals.canvasAvailable ? "good" : "warn",
      rawState: state.localSignals.canvasAvailable ? "success" : "partial",
      attempted: true,
      usable: state.localSignals.canvasAvailable,
    }];
    var fonts = state.localSignals.detectedFonts;
    var fontRows = fonts.length
      ? fonts.map(function (font) {
          return { name: font, meta: "document.fonts.check", value: "浏览器报告字体可用", status: "检测到", tone: "good", rawState: "success", attempted: true, usable: true };
        })
      : [{ name: "字体 API", meta: "document.fonts.check", value: "未读取到候选中文字体", status: "无结果", tone: "warn", rawState: "partial", attempted: true, usable: false }];

    return {
      positionConsistency: position,
      asnOrganization: asnRows,
      geoVotes: geoRows,
      exitQualitySources: coverageRows,
      networkTypeSources: typeRows,
      riskSourceRecords: riskRows,
      languageSignals: browserLanguageEvidence(),
      emojiSignals: emojiRows,
      fontSignals: fontRows,
      dnsResolvers: dnsEvidence(),
      webrtcCandidates: webrtcRows,
      stunNodes: stunRows,
      conflictSources: conflictRows,
      sourceCoverage: coverageRows,
      ipIntelSources: coverageRows,
      routeSources: routeRows,
    };
  }

  function makeTextElement(tagName, className, text) {
    var node = document.createElement(tagName);
    if (className) node.className = className;
    node.textContent = text;
    return node;
  }

  function positionInfoTip(tip) {
    if (window.innerWidth <= 480) return;
    var summary = tip.querySelector("summary");
    var bubble = tip.querySelector(".info-tip-bubble");
    if (!summary || !bubble) return;
    var summaryRect = summary.getBoundingClientRect();
    var bubbleRect = bubble.getBoundingClientRect();
    var viewportPadding = 12;
    var viewportWidth = window.visualViewport ? window.visualViewport.width : document.documentElement.clientWidth;
    var viewportHeight = window.visualViewport ? window.visualViewport.height : document.documentElement.clientHeight;
    var left = Math.min(
      Math.max(viewportPadding, summaryRect.right - bubbleRect.width),
      viewportWidth - bubbleRect.width - viewportPadding,
    );
    var top = summaryRect.top - bubbleRect.height - 8;
    if (top < viewportPadding) top = summaryRect.bottom + 8;
    top = Math.min(
      Math.max(viewportPadding, top),
      viewportHeight - bubbleRect.height - viewportPadding,
    );
    bubble.style.setProperty("--info-tip-left", Math.round(left) + "px");
    bubble.style.setProperty("--info-tip-top", Math.round(top) + "px");
  }

  function positionRowHelpTip(tip) {
    var summary = tip.querySelector("summary");
    var bubble = tip.querySelector(".row-help-bubble");
    if (!summary || !bubble) return;
    var summaryRect = summary.getBoundingClientRect();
    var bubbleRect = bubble.getBoundingClientRect();
    var viewportPadding = 12;
    var container = tip.closest(".signal-subsection-rows");
    var viewportWidth = window.visualViewport ? window.visualViewport.width : document.documentElement.clientWidth;
    var desiredLeft = Math.min(
      Math.max(viewportPadding, summaryRect.right - bubbleRect.width),
      viewportWidth - bubbleRect.width - viewportPadding,
    );
    var tipRect = tip.getBoundingClientRect();
    bubble.style.left = Math.round(desiredLeft - tipRect.left) + "px";
    bubble.style.right = "auto";
  }

  function setupRowHelpTip(tip) {
    if (tip.dataset.rowHelpReady === "true") return;
    tip.dataset.rowHelpReady = "true";
    var summary = tip.querySelector("summary");
    var container = tip.closest(".signal-subsection-rows");
    var syncContainer = function () {
      if (!container) return;
      var visible = Array.from(container.querySelectorAll(".row-help-tip")).some(function (item) {
        return item.matches(":hover") || Boolean(item.querySelector("summary:focus-visible"));
      });
      container.classList.toggle("is-help-visible", visible);
    };
    // 鼠标提示只由 hover 控制，避免原生 details 的第一次点击把提示固定成展开态。
    // 键盘仍保留原生 details 行为，方便键盘用户查看完整说明。
    if (summary) {
      var pointerActivation = false;
      summary.addEventListener("pointerdown", function (event) {
        if (event.pointerType !== "mouse" && event.pointerType !== "pen") return;
        pointerActivation = true;
        event.preventDefault();
        tip.open = false;
        summary.blur();
        syncContainer();
      });
      summary.addEventListener("click", function (event) {
        if (!pointerActivation) return;
        pointerActivation = false;
        event.preventDefault();
        tip.open = false;
        summary.blur();
        syncContainer();
      });
      summary.addEventListener("pointercancel", function () {
        pointerActivation = false;
      });
    }
    tip.addEventListener("toggle", function () {
      syncContainer();
      requestAnimationFrame(function () { positionRowHelpTip(tip); });
    });
    tip.addEventListener("mouseenter", function () {
      syncContainer();
      requestAnimationFrame(function () { positionRowHelpTip(tip); });
    });
    tip.addEventListener("mouseleave", syncContainer);
    tip.addEventListener("focusin", function () {
      syncContainer();
      requestAnimationFrame(function () { positionRowHelpTip(tip); });
    });
    tip.addEventListener("focusout", syncContainer);
  }

  function setupInfoTip(tip) {
    if (tip.dataset.infoTipReady === "true") return;
    tip.dataset.infoTipReady = "true";
    tip.addEventListener("toggle", function () {
      requestAnimationFrame(function () { positionInfoTip(tip); });
    });
    tip.addEventListener("mouseenter", function () {
      requestAnimationFrame(function () { positionInfoTip(tip); });
    });
    tip.addEventListener("focusin", function () {
      requestAnimationFrame(function () { positionInfoTip(tip); });
    });
  }

  function makeInfoTip(label, text) {
    var tip = document.createElement("details");
    tip.className = "info-tip";
    var summary = document.createElement("summary");
    summary.setAttribute("aria-label", label);
    summary.textContent = "i";
    var bubble = makeTextElement("span", "info-tip-bubble", text);
    bubble.setAttribute("role", "note");
    tip.append(summary, bubble);
    setupInfoTip(tip);
    return tip;
  }

  function createEvidenceListItem() {
    var listItem = document.createElement("li");
    listItem.className = "metric-evidence-item";
    listItem.append(makeTextElement("span", "metric-evidence-index", ""));
    var source = document.createElement("span");
    source.className = "metric-evidence-source";
    source.append(makeTextElement("strong", "", ""));
    source.append(makeTextElement("small", "", ""));
    listItem.append(source);
    listItem.append(makeTextElement("span", "metric-evidence-value", ""));
    listItem.append(makeTextElement("span", "metric-evidence-status neutral", ""));
    return listItem;
  }

  function updateEvidenceListItem(listItem, item, index) {
    listItem.dataset.evidenceName = item.name;
    listItem.dataset.rawState = item.rawState || "unknown";
    listItem.querySelector(".metric-evidence-index").textContent = String(index + 1).padStart(2, "0");
    listItem.querySelector(".metric-evidence-source strong").textContent = item.name;
    listItem.querySelector(".metric-evidence-source small").textContent = item.meta || "—";
    var value = listItem.querySelector(".metric-evidence-value");
    value.className = "metric-evidence-value";
    value.textContent = item.value || "—";
    delete value.dataset.sensitive;
    delete value.dataset.sensitiveValue;
    if (item.sensitive === "ip" && item.value) {
      value.classList.add("sensitive-value");
      value.dataset.sensitive = "ip";
      value.dataset.sensitiveValue = item.value;
    }
    var status = listItem.querySelector(".metric-evidence-status");
    status.className = "metric-evidence-status " + (item.tone || "neutral");
    status.textContent = item.status || "已记录";
  }

  function updateEvidenceSection(section, setName, title, catalog) {
    var items = catalog[setName] || [];
    var usable = items.filter(function (item) { return item.usable === true; }).length;
    var attempted = items.filter(function (item) { return item.attempted === true; }).length;
    section.dataset.evidenceSet = setName;
    section.setAttribute("aria-label", title + "，共 " + items.length + " 项");
    section.querySelector(".metric-evidence-title").textContent = title + " · " + items.length + " 项";
    section.querySelector(".metric-evidence-caption").textContent = "实时检测 · 有效 " + usable + " / " + items.length + " · 已请求 " + attempted + " / " + items.length;

    var list = section.querySelector(".metric-evidence-list");
    var existingItems = new Map();
    Array.from(list.children).forEach(function (listItem) {
      existingItems.set(listItem.dataset.evidenceName, listItem);
    });
    items.forEach(function (item, index) {
      var listItem = existingItems.get(item.name) || createEvidenceListItem();
      existingItems.delete(item.name);
      updateEvidenceListItem(listItem, item, index);
      list.append(listItem);
    });
    existingItems.forEach(function (listItem) { listItem.remove(); });
  }

  function buildEvidenceSection(setName, title, catalog) {
    var section = document.createElement("section");
    section.className = "metric-evidence";
    var head = document.createElement("div");
    head.className = "metric-evidence-head";
    head.append(makeTextElement("strong", "metric-evidence-title", ""));
    var meta = document.createElement("div");
    meta.className = "metric-evidence-meta";
    meta.append(makeTextElement("span", "metric-evidence-caption", ""));
    meta.append(makeInfoTip(
      title + "计数说明",
      "有效表示当前指标拥有可参与判断的字段；已请求表示本轮确实发起过访问。超时、失败和字段缺失会保留，但不会计为有效。",
    ));
    head.append(meta);
    section.append(head);
    var list = document.createElement("ol");
    list.className = "metric-evidence-list";
    section.append(list);
    updateEvidenceSection(section, setName, title, catalog);
    return section;
  }

  function renderEvidenceLists() {
    var catalog = buildEvidenceCatalog();
    Object.entries(rowEvidenceMap).forEach(function (entry) {
      var rowId = entry[0];
      var mapping = entry[1];
      var row = document.querySelector('.signal-row[data-row-id="' + rowId + '"]');
      if (!row) return;
      var body = row.querySelector(".signal-row-body");
      body.querySelector(".source-badges")?.remove();
      var section = body.querySelector(":scope > .metric-evidence");
      if (section) updateEvidenceSection(section, mapping.set, mapping.title, catalog);
      else body.append(buildEvidenceSection(mapping.set, mapping.title, catalog));
    });
    $$('[data-evidence-set]').filter(function (host) {
      return !host.classList.contains("metric-evidence");
    }).forEach(function (host) {
      var setName = host.dataset.evidenceSet;
      var title = host.dataset.evidenceTitle || "证据明细";
      var section = host.querySelector(":scope > .metric-evidence");
      if (section) updateEvidenceSection(section, setName, title, catalog);
      else host.append(buildEvidenceSection(setName, title, catalog));
    });
  }

  function prepareSignalRows() {
    rowDefinitions.forEach(function (definition) {
      var row = document.querySelector('.signal-row[data-row-id="' + definition.id + '"]');
      if (!row) return;
      row.open = false;
      row.dataset.defaultVisibility = "summary";

      var detailGrid = row.querySelector(".row-detail-grid");
      if (!detailGrid || detailGrid.dataset.prepared === "true") return;
      detailGrid.dataset.prepared = "true";
      var detailItems = Array.from(detailGrid.children).filter(function (child) {
        return child.classList.contains("row-detail-item");
      });
      var resultItem = detailItems[0];
      if (resultItem) {
        resultItem.dataset.detailKind = "result";
        resultItem.classList.add("row-detail-result");
      }
      var helpItems = detailItems.slice(1).map(function (item) {
        var label = item.querySelector("span")?.textContent.trim() || "说明";
        var copy = item.querySelector("p")?.textContent.trim() || "本轮没有补充说明。";
        var help = document.createElement("details");
        help.className = "row-help-tip";
        help.dataset.helpKind = label === "建议" ? "advice" : "evidence";
        var summary = document.createElement("summary");
        summary.textContent = label;
        var bubble = makeTextElement("span", "row-help-bubble", copy);
        bubble.setAttribute("role", "note");
        help.append(summary, bubble);
        setupRowHelpTip(help);
        return help;
      });
      detailGrid.replaceChildren.apply(detailGrid, [resultItem].concat(helpItems).filter(Boolean));
    });
  }

  function maskIpValue(value) {
    var text = String(value || "");
    if (text.indexOf(" / ") >= 0) {
      return text.split(" / ").map(maskIpValue).join(" / ");
    }
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(text)) {
      var parts = text.split(".");
      return parts[0] + "." + parts[1] + ".x.x";
    }
    if (text.indexOf(":") >= 0) {
      return text.split(":").slice(0, 3).join(":") + ":…";
    }
    return text;
  }

  function setSensitiveValue(node, rawValue) {
    if (!node) return;
    var value = rawValue || "未取得";
    node.dataset.sensitiveValue = value;
    node.textContent = state.privacy ? maskIpValue(value) : value;
  }

  function displayedFingerprint(type) {
    var data = state.fingerprints[type || "v3"];
    if (!data) return "不可用";
    if (!state.privacy || !/^[0-9a-f]{16,}$/i.test(data.value)) return data.value;
    return data.value.slice(0, 8) + "••••••••";
  }

  function toneLabel(tone) {
    return tone === "good" ? "通过" : tone === "warn" ? "需核对" : tone === "bad" ? "冲突或失败" : "未检测";
  }

  function updateSensitiveValues() {
    $$('[data-sensitive="ip"]').forEach(function (node) {
      var raw = node.dataset.sensitiveValue;
      if (!raw || raw === "检测中…") raw = state.observations.exitIp || raw || "未取得";
      node.textContent = state.privacy ? maskIpValue(raw) : raw;
    });
    $$('[data-fingerprint-value]').forEach(function (node) {
      node.textContent = displayedFingerprint(node.dataset.fingerprintValue);
    });
    var privacyAction = state.privacy ? "显示原值" : "隐藏原值";
    $("#privacy-label").textContent = privacyAction;
    $("#privacy-toggle").dataset.privacyActive = String(state.privacy);
    $("#privacy-toggle").setAttribute("aria-pressed", String(state.privacy));
    $("#privacy-toggle").setAttribute("aria-label", privacyAction);
  }

  function countryName(code) {
    if (!code) return null;
    try {
      return new Intl.DisplayNames(["zh-CN"], { type: "region" }).of(code) || code;
    } catch (error) {
      return code;
    }
  }

  function timezoneRegion(timezoneValue) {
    var value = String(timezoneValue || "");
    if (/^America\//.test(value)) return "US";
    if (value === "Asia/Shanghai" || value === "Asia/Chongqing") return "CN";
    if (value === "Asia/Taipei") return "TW";
    if (value === "Asia/Tokyo") return "JP";
    if (value === "Asia/Seoul") return "KR";
    if (value === "Europe/London") return "GB";
    return null;
  }

  function languageRegion(language) {
    var match = String(language || "").match(/[-_]([A-Za-z]{2})\b/);
    return match ? match[1].toUpperCase() : null;
  }

  function webrtcAssessment() {
    var successes = state.stun.filter(function (record) { return record.state === "success" && record.observedIp; });
    var ips = Array.from(new Set(successes.map(function (record) { return record.observedIp; })));
    var exitIp = state.observations.exitIp;
    function family(ip) { return ip && ip.indexOf(":") >= 0 ? 6 : ip ? 4 : 0; }
    var conflicts = exitIp ? successes.filter(function (record) {
      return family(record.observedIp) === family(exitIp) && record.observedIp !== exitIp;
    }) : [];
    var alternateFamily = exitIp ? successes.filter(function (record) {
      return family(record.observedIp) !== family(exitIp);
    }) : [];
    return {
      successes: successes,
      ips: ips,
      conflicts: conflicts,
      alternateFamily: alternateFamily,
      tone: !successes.length ? "warn" : conflicts.length ? "bad" : alternateFamily.length ? "warn" : "good",
      label: !successes.length
        ? "证据不足"
        : conflicts.length
          ? "同地址族候选分歧"
          : alternateFamily.length
            ? "检测到双栈公网候选"
            : "候选与出口一致",
    };
  }

  function setRow(rowId, config) {
    var row = document.querySelector('.signal-row[data-row-id="' + rowId + '"]');
    if (!row) return;
    var tone = config.tone || "neutral";
    var value = row.querySelector(".signal-row-value");
    var dot = row.querySelector(".row-status-dot");
    [value, dot].forEach(function (node) {
      if (!node) return;
      node.classList.remove("good", "warn", "bad", "neutral");
      node.classList.add(tone);
    });
    if (value) {
      value.textContent = config.value;
      value.dataset.statusLabel = config.status || toneLabel(tone);
      value.setAttribute("aria-label", (config.status || toneLabel(tone)) + "：" + config.value);
    }
    row.dataset.tone = tone;
    row.dataset.statusLabel = config.status || toneLabel(tone);
    var result = row.querySelector('[data-detail-kind="result"] strong');
    var evidence = row.querySelector('.row-help-bubble[data-help-kind="evidence"]');
    var advice = row.querySelector('.row-help-bubble[data-help-kind="advice"]');
    if (result && config.result) result.textContent = config.result;
    if (evidence && config.evidence) evidence.textContent = config.evidence;
    if (advice && config.advice) advice.textContent = config.advice;
  }

  function updateRowSummaries() {
    var intelSummary = evidenceApi.summarizeSources(state.ipIntel);
    var routeSummary = evidenceApi.summarizeSources(state.routes);
    var country = evidenceApi.computeCountryConsensus(state.ipIntel);
    var countryMajority = semanticsApi.evaluateMajority(
      Object.fromEntries(country.distribution.map(function (item) { return [item.value, item.votes]; })),
    );
    var asn = evidenceApi.computeAsnConsensus(state.ipIntel);
    var organization = evidenceApi.computeOrganizationConsensus(state.ipIntel);
    var type = simpleConsensus(state.ipIntel, "networkType");
    var asnFieldCount = state.ipIntel.filter(function (record) {
      return sourceUsable(record) && Boolean(record.asn || record.organization);
    }).length;
    var typeFieldCount = state.ipIntel.filter(function (record) {
      return sourceUsable(record) && Boolean(record.networkType);
    }).length;
    var riskFieldCount = state.ipIntel.filter(function (record) {
      return sourceUsable(record) && [record.proxy, record.vpn, record.tor, record.hosting]
        .some(function (value) { return value !== null; });
    }).length;
    var conflictFieldCount = state.ipIntel.filter(function (record) {
      return sourceUsable(record) && Boolean(record.countryCode || record.asn || record.organization);
    }).length;
    var countryLabel = country.value || "待判定";
    var timezoneCountry = timezoneRegion(state.observations.timezone);
    var timezoneMismatch = Boolean(country.value && timezoneCountry && country.value !== timezoneCountry);
    var languageCountry = languageRegion(state.observations.languages[0]);
    var languageMismatch = Boolean(country.value && languageCountry && country.value !== languageCountry);
    var webrtc = webrtcAssessment();
    var riskFlags = state.ipIntel.filter(function (record) {
      return record.proxy === true || record.vpn === true || record.tor === true || record.hosting === true;
    });
    var countryConflict = state.ipIntel.filter(function (record) {
      return sourceUsable(record) && country.value && record.countryCode &&
        semanticsApi.normalizeCountry(record.countryCode) !== semanticsApi.normalizeCountry(country.value);
    }).length;
    var asnConflict = state.ipIntel.filter(function (record) {
      return sourceUsable(record) && asn.value && record.asn &&
        semanticsApi.normalizeAsn(record.asn) !== semanticsApi.normalizeAsn(asn.value);
    }).length;
    var organizationConflict = state.ipIntel.filter(function (record) {
      return sourceUsable(record) && organization.value && record.organization &&
        semanticsApi.normalizeOrganization(record.organization) !== semanticsApi.normalizeOrganization(organization.value);
    }).length;
    var conflictCount = countryConflict + asnConflict + organizationConflict;
    var dnsRecords = state.dns.records;
    var dnsCountryMatches = country.value
      ? dnsRecords.filter(function (record) { return record.countryCode === country.value; }).length
      : 0;
    var dnsTone = state.dns.error ? "bad" : !dnsRecords.length ? "warn" : dnsCountryMatches === dnsRecords.length ? "good" : "warn";

    setRow("position-consistency", {
      value: country.value ? (timezoneMismatch || languageMismatch ? "存在差异" : "未见明确差异") : "等待地理来源",
      tone: !country.value ? "neutral" : timezoneMismatch || languageMismatch ? "warn" : "good",
      result: country.value ? (timezoneMismatch || languageMismatch ? "存在地区提示差异" : "当前信号未见明确冲突") : "尚无足够地理证据",
      evidence: "出口主流地区 " + countryLabel + "，系统时区 " + state.observations.timezone + "，浏览器语言 " + state.observations.languages.join(" · ") + "。",
      advice: "按真实使用地区核对时区与语言；没有明确映射时不强行判定异常。",
    });
    setRow("asn-organization", {
      value: asn.value ? asn.value + " · " + asn.votes + " / 10" : "有效字段 " + asnFieldCount + " / 10",
      tone: asn.value ? "good" : asnFieldCount ? "warn" : "neutral",
      result: asn.value ? "主流 ASN 为 " + asn.value : "尚无 ASN 共识",
      evidence: "10 家来源逐项展示；" + asn.votes + " 家真实返回主流 ASN，组织主流票数为 " + organization.votes + "。",
      advice: "字段缺失不视为冲突；若真实返回的 ASN 分歧，再核对出口与路由。",
    });
    setRow("geo-cross-check", {
      value: country.value ? country.value + " · " + country.votes + " / 10 票" : "0 / 10 票",
      tone: country.value ? countryMajority.tone : "neutral",
      status: country.value ? countryMajority.label : "证据不足",
      result: country.value ? countryName(country.value) + "获得 " + country.votes + " 票，" + countryMajority.label : "尚无可用国家票",
      evidence: "固定列出 10 家地理来源；实际可投票 " + country.eligible + " 家，分歧 " + country.conflicts + " 家。",
      advice: "以国家级共识为主；超时、字段缺失和路径不同均不计票。",
    });
    setRow("exit-ip-quality", {
      value: state.observations.exitIp || state.publicIp.status,
      tone: state.observations.exitIp ? "good" : state.publicIp.state === "pending" ? "neutral" : "bad",
      result: state.observations.exitIp ? "公网出口已实时读取" : "未取得公网出口",
      evidence: "10 家 IP 情报来源中，可使用 " + intelSummary.usable + " 家、完整 " + intelSummary.complete + " 家、部分字段 " + intelSummary.partial + " 家。",
      advice: "不把来源失败或风险字段缺失解释成安全结论。",
    });
    setRow("network-type", {
      value: type.value ? type.value + " · " + type.votes + " 票" : "未形成共识",
      tone: type.value ? "good" : typeFieldCount ? "warn" : "neutral",
      result: type.value ? "主流网络类型：" + type.value : "可用来源未提供足够类型字段",
      evidence: "本轮 " + typeFieldCount + " / 10 家真实提供网络类型字段，未用组织名称猜测或补填。",
      advice: "结合真实 ISP、ASN、DNS 与使用场景理解类型标签。",
    });
    setRow("risk-proxy-labels", {
      value: riskFlags.length ? riskFlags.length + " 家标记风险" : riskFieldCount ? "未收到明确风险标记" : "证据不足",
      tone: riskFlags.length ? "bad" : riskFieldCount ? "good" : "neutral",
      result: riskFlags.length ? "存在 Proxy / VPN / Tor / Hosting 标记" : riskFieldCount ? "已提供风险字段的来源未返回明确标记" : "没有来源提供可判定的风险字段",
      evidence: "本轮 " + riskFieldCount + " / 10 家真实提供风险字段；仅统计明确返回 true 的结果，未提供字段保持“未提供”。",
      advice: "浏览器侧不具备完整商业信誉库，应把该项视为公开情报参考。",
    });
    setRow("system-timezone", {
      value: state.observations.timezone,
      tone: timezoneMismatch ? "warn" : "good",
      result: timezoneMismatch ? "与出口主流国家不一致" : "未发现明确时区冲突",
      evidence: "系统时区来自浏览器 Intl API；出口主流国家为 " + countryLabel + "。",
      advice: "按真实所在地区与长期使用习惯核对，不建议为了单一网站频繁修改。",
    });
    setRow("browser-language", {
      value: state.observations.languages.join(" · "),
      tone: languageMismatch ? "warn" : "good",
      result: languageMismatch ? "首选语言地区与出口主流国家不同" : "未发现明确语言冲突",
      evidence: "浏览器实际报告语言：" + state.observations.languages.join(" · ") + "；出口主流国家：" + countryLabel + "。",
      advice: "语言应符合真实日常使用习惯，无地区后缀时不强行判定。",
    });
    setRow("emoji-rendering", {
      value: state.localSignals.canvasAvailable ? "Canvas 2D 可用" : "Canvas 2D 不可用",
      tone: state.localSignals.canvasAvailable ? "good" : "warn",
      result: "浏览器本地渲染能力已读取",
      evidence: "该项只报告 Canvas 2D 上下文是否可创建，不伪造具体 Emoji 像素结论。",
      advice: "渲染能力是弱信号，不应脱离网络与语言单独下结论。",
    });
    setRow("chinese-fonts", {
      value: state.localSignals.detectedFonts.length + " 个候选",
      tone: state.localSignals.detectedFonts.length ? "good" : "warn",
      result: state.localSignals.detectedFonts.length ? "浏览器报告候选字体可用" : "未读取到候选字体",
      evidence: state.localSignals.detectedFonts.length ? state.localSignals.detectedFonts.join(" · ") : "document.fonts 未报告预设候选字体。",
      advice: "字体存在本身不是风险，只作为本机环境弱信号。",
    });
    setRow("dns-leak", {
      value: state.dns.error ? "检测失败" : state.dns.running ? "检测中…" : dnsRecords.length + " 个解析器",
      tone: dnsTone,
      result: state.dns.error ? "本轮未取得权威 DNS 结果" : dnsRecords.length ? "已取得真实解析器记录" : "等待解析器回传",
      evidence: state.dns.error || (dnsRecords.length + " 个解析器来自 bash.ws 本轮权威 DNS 探针，没有固定填充。"),
      advice: "检测失败不等于没有泄漏；可重测或检查当前网络是否阻止第三方 DNS 探针。",
    });
    setRow("dns-region-consistency", {
      value: dnsRecords.length && country.value ? dnsCountryMatches + " / " + dnsRecords.length + " 与出口同国" : "证据不足",
      tone: dnsTone,
      result: dnsRecords.length ? "按真实解析器地区与出口逐项比较" : "尚无解析器地区可比较",
      evidence: country.value ? "出口主流国家 " + country.value + "；同国解析器 " + dnsCountryMatches + " 个。" : "尚未形成出口国家共识。",
      advice: "地区未知的解析器不计为一致，也不计为冲突。",
    });
    setRow("webrtc-leak", {
      value: webrtc.label,
      tone: webrtc.tone,
      result: webrtc.label,
      evidence: "10 个独立 STUN 节点中 " + webrtc.successes.length + " 个返回公网候选；同地址族分歧 " + webrtc.conflicts.length + " 个，另一地址族候选 " + webrtc.alternateFamily.length + " 个。",
      advice: "另一地址族候选常见于双栈网络；只有同地址族出现额外公网地址时才优先核对代理、TUN 与 WebRTC 设置。",
    });
    setRow("stun-nodes", {
      value: webrtc.successes.length + " / 10 响应",
      tone: webrtc.tone,
      result: webrtc.successes.length ? "成功节点候选种类：" + webrtc.ips.length : "本轮没有节点返回公网候选",
      evidence: "每个节点使用独立 RTCPeerConnection；超时和错误保留原状态，不借用其他节点数据。",
      advice: "响应过少可能与 UDP、代理规则或浏览器策略有关。",
    });
    setRow("majority-region", {
      value: country.value ? country.value + " · " + country.votes + " / 10 票" : "0 / 10 票",
      tone: country.value ? countryMajority.tone : "neutral",
      status: country.value ? countryMajority.label : "证据不足",
      result: country.value ? countryName(country.value) + "为本轮主流地区（" + countryMajority.label + "）" : "尚无主流地区",
      evidence: "10 家全部列出；仅 " + country.eligible + " 家真实返回可投票国家字段。",
      advice: "来源失败与字段缺失不会被填成多数结果。",
    });
    setRow("conflict-check", {
      value: conflictCount + " 项明确冲突",
      tone: conflictCount ? "bad" : conflictFieldCount ? "good" : "neutral",
      status: conflictCount ? "明确冲突" : conflictFieldCount ? "通过" : "字段不足",
      result: conflictCount
        ? "国家 " + countryConflict + "、ASN " + asnConflict + "、组织 " + organizationConflict + " 项明确冲突"
        : conflictFieldCount ? "可核对字段未发现明确冲突" : "没有可用于冲突比较的真实字段",
      evidence: "10 家来源逐行保留；本轮 " + conflictFieldCount + " 家至少提供国家、ASN 或组织字段。",
      advice: "字段缺失不视为冲突；明确分歧才需要进一步核对。",
    });
    setRow("network-label-consensus", {
      value: type.value ? type.value + " · " + type.votes + " 票" : "未形成类型共识",
      tone: type.value ? "good" : typeFieldCount ? "warn" : "neutral",
      result: "网络类型字段有效 " + typeFieldCount + " / 10",
      evidence: "逐家显示网络类型、组织、风险字段与失败状态。",
      advice: "单一标签不足以判断线路性质，应结合多源与实际运营商。",
    });
    setRow("ip-intel-sources", {
      value: "可用 " + intelSummary.usable + " / 10",
      tone: intelSummary.usable >= 6 ? "good" : intelSummary.usable ? "warn" : "neutral",
      result: "完整 " + intelSummary.complete + "、部分 " + intelSummary.partial + "、失败 " + intelSummary.failed,
      evidence: "固定展示 10 家真实 IP 情报服务，本轮实际请求 " + intelSummary.attempted + " / 10，不配置令牌、不填充兜底结果。",
      advice: "限流、超时和字段缺失均会保留并从相应票数中排除。",
    });
    setRow("route-registry-sources", {
      value: "可用 " + routeSummary.usable + " / 10",
      tone: routeSummary.usable >= 6 ? "good" : routeSummary.usable ? "warn" : "neutral",
      result: "完整 " + routeSummary.complete + "、部分 " + routeSummary.partial + "、失败 " + routeSummary.failed,
      evidence: "本轮实际请求 " + routeSummary.attempted + " / 10；IANA、权威 RIR RDAP、RIPEstat、Team Cymru、PeeringDB、IP.guide、HackerTarget 与 CAIDA 均为独立来源。",
      advice: "先用 IP 路由源发现真实 ASN，再执行依赖 ASN 的服务；仍未取得 ASN 时明确标记前置数据缺失。",
    });
    var networkSourceStatus = $("#network-source-status");
    if (networkSourceStatus) networkSourceStatus.textContent = "可用 " + intelSummary.usable + " / 10";
  }

  function updateSnapshot() {
    var country = evidenceApi.computeCountryConsensus(state.ipIntel);
    var asn = evidenceApi.computeAsnConsensus(state.ipIntel);
    var organization = evidenceApi.computeOrganizationConsensus(state.ipIntel);
    var type = simpleConsensus(state.ipIntel, "networkType");
    state.observations.countryCode = country.value;
    state.observations.countryName = countryName(country.value);
    state.observations.asn = asn.value;
    state.observations.organization = organization.value;
    state.observations.networkType = type.value;
    var cities = simpleConsensus(state.ipIntel, "city");
    state.observations.city = cities.value;
    setSensitiveValue($("#summary-exit-ip"), state.observations.exitIp || state.publicIp.status);
    setSensitiveValue($("#snapshot-exit-ip"), state.observations.exitIp || state.publicIp.status);
    $("#summary-location").textContent = country.value
      ? [countryName(country.value), cities.value].filter(Boolean).join(" · ")
      : "等待来源";
    $("#snapshot-location").textContent = $("#summary-location").textContent;
    $("#snapshot-asn").textContent = asn.value || "未形成共识";
    $("#snapshot-organization").textContent = organization.value || "未形成共识";
    $("#snapshot-network-type").textContent = type.value || "未形成共识";
    $("#snapshot-status").textContent = state.running ? "实时检测中" : state.observations.exitIp ? "实时结果" : "未取得出口";
  }

  function setToneText(node, text, tone) {
    if (!node) return;
    tone = tone || "neutral";
    node.textContent = text;
    node.classList.remove("good", "warn", "bad", "neutral");
    node.classList.add(tone);
    node.dataset.statusLabel = toneLabel(tone);
    node.setAttribute("aria-label", toneLabel(tone) + "：" + text);
  }

  function updateGroupSummaries() {
    var groups = $$(".signal-group");
    var byTitle = function (title) {
      return groups.find(function (group) {
        return group.querySelector(".signal-group-title")?.textContent.trim() === title;
      });
    };
    var intel = evidenceApi.summarizeSources(state.ipIntel);
    var routes = evidenceApi.summarizeSources(state.routes);
    var country = evidenceApi.computeCountryConsensus(state.ipIntel);
    var countryMajority = semanticsApi.evaluateMajority(
      Object.fromEntries(country.distribution.map(function (item) { return [item.value, item.votes]; })),
    );
    var asn = evidenceApi.computeAsnConsensus(state.ipIntel);
    var timezoneCountry = timezoneRegion(state.observations.timezone);
    var languageCountry = languageRegion(state.observations.languages[0]);
    var identityMismatch = Boolean(
      country.value &&
        ((timezoneCountry && timezoneCountry !== country.value) ||
          (languageCountry && languageCountry !== country.value)),
    );
    var webrtc = webrtcAssessment();
    var dnsMismatch = Boolean(
      state.dns.records.length &&
        country.value &&
        state.dns.records.some(function (record) {
          return record.countryCode && record.countryCode !== country.value;
        }),
    );
    var countryConflict = country.conflicts;
    var asnConflict = state.ipIntel.filter(function (record) {
      return sourceUsable(record) && asn.value && record.asn &&
        semanticsApi.normalizeAsn(record.asn) !== semanticsApi.normalizeAsn(asn.value);
    }).length;
    var typeFieldCount = state.ipIntel.filter(function (record) {
      return sourceUsable(record) && Boolean(record.networkType);
    }).length;

    var exitGroup = byTitle("出口 IP");
    setToneText(
      exitGroup?.querySelector(".signal-group-result"),
      state.running ? "实时检测中" : state.observations.exitIp ? "出口已读取 · 可用 " + intel.usable + " / 10" : "未取得出口",
      state.running ? "neutral" : state.observations.exitIp ? (intel.usable >= 6 ? "good" : "warn") : "bad",
    );
    var identityGroup = byTitle("身份信号");
    setToneText(
      identityGroup?.querySelector(".signal-group-result"),
      !country.value ? "等待地区共识" : identityMismatch ? "时区或语言不一致" : "未见明确不一致",
      !country.value ? "neutral" : identityMismatch ? "warn" : "good",
    );
    var leakGroup = byTitle("网络泄漏");
    var leakNeedsReview = webrtc.conflicts.length || webrtc.alternateFamily.length || dnsMismatch || state.dns.error;
    var leakEvidenceMissing = !state.running && (!webrtc.successes.length || !state.dns.records.length);
    setToneText(
      leakGroup?.querySelector(".signal-group-result"),
      state.running ? "实时检测中" : leakNeedsReview ? "发现需核对信号" : leakEvidenceMissing ? "泄漏证据不足" : "未发现明确泄漏",
      state.running ? "neutral" : leakNeedsReview || leakEvidenceMissing ? "warn" : "good",
    );
    var multiGroup = byTitle("多源互证");
    var sourceConflicts = countryConflict + asnConflict;
    var multiSummary = countryMajority.tone === "good"
      ? "主流结果一致" + (sourceConflicts ? " · 少数差异 " + sourceConflicts : "")
      : sourceConflicts ? sourceConflicts + " 项来源分歧" : "多源未见明确分歧";
    setToneText(
      multiGroup?.querySelector(".signal-group-result"),
      state.running ? "多源核对中" : multiSummary,
      state.running ? "neutral" : sourceConflicts && countryMajority.tone !== "good" ? "warn" : intel.usable || routes.usable ? "good" : "neutral",
    );

    var subsection = function (label) {
      return document.querySelector('.signal-subsection[aria-label="' + label + '"] .signal-subsection-status');
    };
    setToneText(subsection("位置一致性"), !country.value ? "等待" : identityMismatch ? "部分匹配" : "未见冲突", !country.value ? "neutral" : identityMismatch ? "warn" : "good");
    setToneText(subsection("网络类型"), "有效 " + typeFieldCount + " / 10", typeFieldCount >= 6 ? "good" : typeFieldCount ? "warn" : "neutral");
    setToneText(subsection("时区"), !country.value ? "等待" : timezoneCountry && timezoneCountry !== country.value ? "不一致" : "未见冲突", !country.value ? "neutral" : timezoneCountry && timezoneCountry !== country.value ? "warn" : "good");
    setToneText(subsection("语言"), !country.value ? "等待" : languageCountry && languageCountry !== country.value ? "不一致" : "未见冲突", !country.value ? "neutral" : languageCountry && languageCountry !== country.value ? "warn" : "good");
    setToneText(subsection("DNS"), state.dns.running ? "检测中" : state.dns.error ? "检测失败" : dnsMismatch ? "地区分歧" : state.dns.records.length ? "已取得结果" : "无结果", state.dns.running ? "neutral" : state.dns.error || dnsMismatch ? "warn" : state.dns.records.length ? "good" : "neutral");
    setToneText(subsection("WebRTC"), webrtc.label, webrtc.tone);
    setToneText(subsection("地理交叉"), country.value ? country.votes + " / 10 票" : "等待", country.value ? countryMajority.tone : "neutral");
    setToneText(subsection("网络标签"), "有效 " + typeFieldCount + " / 10", typeFieldCount >= 6 ? "good" : typeFieldCount ? "warn" : "neutral");
  }

  function browserLabel() {
    var ua = navigator.userAgent || "";
    var browser = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "浏览器";
    return browser + " · " + state.localSignals.platform;
  }

  function updateOverview() {
    var intelSummary = evidenceApi.summarizeSources(state.ipIntel);
    var routeSummary = evidenceApi.summarizeSources(state.routes);
    var stunSummary = evidenceApi.summarizeSources(state.stun);
    var stunSuccess = stunSummary.usable;
    var evidenceCount = intelSummary.usable + routeSummary.usable + stunSuccess;
    var coverage = Math.round(((intelSummary.usable + routeSummary.usable + stunSuccess) / 30) * 100);
    var country = evidenceApi.computeCountryConsensus(state.ipIntel);
    var timezoneCountry = timezoneRegion(state.observations.timezone);
    var languageCountry = languageRegion(state.observations.languages[0]);
    var timezoneMismatch = Boolean(country.value && timezoneCountry && country.value !== timezoneCountry);
    var languageMismatch = Boolean(country.value && languageCountry && country.value !== languageCountry);
    var webrtc = webrtcAssessment();
    var complete = !state.running;
    var scoreAvailable = evidenceCount > 0;
    var score = Math.max(0, Math.min(100, 45 + Math.round(coverage * 0.45) - (timezoneMismatch ? 5 : 0) - (languageMismatch ? 5 : 0) - (webrtc.conflicts.length ? 15 : 0)));
    var scoreNode = $(".score-number");
    scoreNode.textContent = complete ? (scoreAvailable ? String(score) : "—") : "…";
    var ring = $(".score-ring");
    ring.style.background = complete && scoreAvailable
      ? "conic-gradient(var(--green) 0 " + score + "%, #dcebe1 " + score + "% 100%)"
      : "conic-gradient(var(--blue) 0 " + coverage + "%, #dcebe1 " + coverage + "% 100%)";
    ring.setAttribute("aria-label", complete ? (scoreAvailable ? "网络信号参考分 " + score + " 分，满分 100 分" : "证据不足，未生成网络参考分") : "实时检测进行中");
    $("#summary-browser").textContent = browserLabel();
    $("#summary-coverage").textContent = coverage + "%";
    var chips = [];
    chips.push({ tone: !country.value ? "neutral" : timezoneMismatch ? "warn" : "good", text: !country.value ? "时区等待地区证据" : timezoneMismatch ? "时区不一致" : "时区未见明确冲突" });
    chips.push({ tone: !country.value ? "neutral" : languageMismatch ? "warn" : "good", text: !country.value ? "语言等待地区证据" : languageMismatch ? "语言不一致" : "语言未见明确冲突" });
    chips.push({ tone: webrtc.tone, text: "WebRTC " + webrtc.label });
    var tagRow = $(".tag-row");
    tagRow.replaceChildren();
    chips.forEach(function (chip) {
      tagRow.append(makeTextElement("span", "chip " + chip.tone, chip.text));
    });
    var needsReview = timezoneMismatch || languageMismatch || webrtc.conflicts.length || webrtc.alternateFamily.length;
    var evidenceMissing = !scoreAvailable || !country.value || !webrtc.successes.length;
    var badge = $(".status-badge");
    badge.textContent = state.running ? "检测中" : needsReview ? "需要核对" : evidenceMissing || coverage < 50 ? "证据不足" : "状态稳定";
    badge.style.color = state.running ? "var(--blue)" : needsReview || evidenceMissing || coverage < 50 ? "var(--amber)" : "var(--green-deep)";
    badge.style.background = state.running ? "var(--blue-soft)" : needsReview || evidenceMissing || coverage < 50 ? "var(--amber-soft)" : "var(--green-soft)";
    $(".result-copy").textContent = state.running
      ? "正在逐家读取实时来源，已完成 " + coverage + "% 的多源证据。"
      : "固定配置 10 家 IP 情报、10 路路由注册和 10 个 STUN 节点；本轮实际请求 " + intelSummary.attempted + " / 10、" + routeSummary.attempted + " / 10、" + stunSummary.attempted + " / 10，未请求与失败来源均保留。";
    $("#result-run-state").textContent = state.running ? "正在实时检测" : "本次检测完成";
    if (state.completedAt) $("#run-time").textContent = formatRunTime(state.completedAt);
  }

  function updateWebrtcPanel() {
    var assessment = webrtcAssessment();
    var panelStatus = $("#webrtc-panel-status");
    var panelTone = state.running
      ? "neutral"
      : !assessment.successes.length
        ? "warn"
        : assessment.tone;
    var panelLabel = state.running
      ? "检测中"
      : !assessment.successes.length
        ? "证据不足"
        : assessment.tone === "good"
          ? "正常"
          : assessment.tone === "bad"
            ? "发现分歧"
            : "需核对";
    setToneText(panelStatus, panelLabel, panelTone);
    setSensitiveValue($("#webrtc-http-ip"), state.observations.exitIp || state.publicIp.status);
    setSensitiveValue($("#webrtc-public-ip"), assessment.ips.length ? assessment.ips.join(" / ") : "未取得");
    $("#webrtc-node-consensus").textContent = assessment.successes.length + " / 10 响应 · " + assessment.ips.length + " 种候选";
    $("#webrtc-panel-note").textContent = "本轮以 10 个独立 STUN 节点探测；" + assessment.successes.length + " 个返回公网候选，同地址族分歧 " + assessment.conflicts.length + " 个，另一地址族候选 " + assessment.alternateFamily.length + " 个。";
    [$("#webrtc-http-status"), $("#webrtc-public-status"), $("#webrtc-node-status")].forEach(function (node) {
      node.classList.remove("good", "warn", "bad");
    });
    $("#webrtc-http-status").textContent = state.observations.exitIp ? "已确认" : state.publicIp.status;
    $("#webrtc-http-status").classList.add(state.observations.exitIp ? "good" : "warn");
    $("#webrtc-public-status").textContent = assessment.label;
    $("#webrtc-public-status").classList.add(assessment.tone);
    $("#webrtc-node-status").textContent = assessment.successes.length ? "实时" : "无结果";
    $("#webrtc-node-status").classList.add(assessment.successes.length ? assessment.tone : "warn");
  }

  function render() {
    updateSnapshot();
    updateRowSummaries();
    updateGroupSummaries();
    updateOverview();
    updateWebrtcPanel();
    renderEvidenceLists();
    updateSensitiveValues();
  }

  function showToast(message) {
    var toast = $("#toast");
    toast.textContent = message;
    toast.classList.add("is-visible");
    clearTimeout(showToast.timer);
    showToast.timer = setTimeout(function () { toast.classList.remove("is-visible"); }, 2200);
  }

  var sectionNavigationScheduled = false;
  var alignedSectionId = null;
  var sectionNavigationObserver = null;
  var sectionNavigationStopTimer = null;

  function sectionNavigationOffset() {
    var headerHeight = $(".demo-header")?.getBoundingClientRect().height || 0;
    var navHeight = $(".module-tabs")?.getBoundingClientRect().height || 0;
    return headerHeight + navHeight + 16;
  }

  function scrollWindowImmediately(top) {
    var root = document.documentElement;
    var previousBehavior = root.style.scrollBehavior;
    root.style.scrollBehavior = "auto";
    window.scrollTo(0, Math.max(0, top));
    root.style.scrollBehavior = previousBehavior;
  }

  function alignCurrentSection() {
    if (!alignedSectionId) return;
    var target = document.getElementById(alignedSectionId);
    if (!target) return;
    var delta = target.getBoundingClientRect().top - sectionNavigationOffset();
    if (Math.abs(delta) > 2) scrollWindowImmediately(window.scrollY + delta);
    scheduleSectionNavigationUpdate();
  }

  function stopSectionNavigationAlignment() {
    alignedSectionId = null;
    clearTimeout(sectionNavigationStopTimer);
    if (sectionNavigationObserver) sectionNavigationObserver.disconnect();
    sectionNavigationObserver = null;
  }

  function beginSectionNavigationAlignment(target) {
    stopSectionNavigationAlignment();
    alignedSectionId = target.id;
    requestAnimationFrame(alignCurrentSection);
    if (typeof ResizeObserver === "function") {
      sectionNavigationObserver = new ResizeObserver(function () {
        requestAnimationFrame(alignCurrentSection);
      });
      var report = $("main") || document.body;
      sectionNavigationObserver.observe(report);
    }
    sectionNavigationStopTimer = setTimeout(function () {
      stopSectionNavigationAlignment();
      scheduleSectionNavigationUpdate();
    }, 9000);
  }

  function alignSectionFromLocationHash() {
    if (!location.hash || location.hash === "#main") return;
    var id;
    try {
      id = decodeURIComponent(location.hash.slice(1));
    } catch (error) {
      return;
    }
    var target = document.getElementById(id);
    if (target && target.matches("[data-panel]")) beginSectionNavigationAlignment(target);
  }

  function updateSectionNavigation() {
    var links = $$(".module-tab[href^='#']");
    var panels = $$('[data-panel]');
    if (!links.length || !panels.length) return;
    var headerHeight = $(".demo-header")?.getBoundingClientRect().height || 0;
    var navHeight = $(".module-tabs")?.getBoundingClientRect().height || 0;
    var activationLine = headerHeight + navHeight + 28;
    var activePanel = panels[0];
    panels.forEach(function (panel) {
      if (panel.getBoundingClientRect().top <= activationLine) activePanel = panel;
    });
    var nearBottom = window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4;
    if (nearBottom) activePanel = panels[panels.length - 1];
    if (alignedSectionId) {
      activePanel = document.getElementById(alignedSectionId) || activePanel;
    }
    links.forEach(function (link) {
      link.setAttribute("aria-current", String(link.getAttribute("href") === "#" + activePanel.id));
    });
  }

  function scheduleSectionNavigationUpdate() {
    if (sectionNavigationScheduled) return;
    sectionNavigationScheduled = true;
    requestAnimationFrame(function () {
      sectionNavigationScheduled = false;
      updateSectionNavigation();
    });
  }

  function fallbackCopy(text) {
    var textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.top = "-9999px";
    document.body.appendChild(textarea);
    textarea.select();
    var copied = false;
    try { copied = document.execCommand("copy"); } catch (error) {}
    textarea.remove();
    return copied;
  }

  function copyText(text, success) {
    function complete(copied) {
      showToast(copied ? success : "复制失败，请手动选择内容");
      return copied;
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text)
        .then(function () { return complete(true); })
        .catch(function () { return complete(fallbackCopy(text)); });
    }
    return Promise.resolve(complete(fallbackCopy(text)));
  }

  function currentScoreText() {
    var value = $(".score-number").textContent.trim();
    return /^\d+$/.test(value) ? value + " / 100" : "证据不足，未生成分数";
  }

  function summaryText() {
    var country = evidenceApi.computeCountryConsensus(state.ipIntel);
    var intelSummary = evidenceApi.summarizeSources(state.ipIntel);
    var routeSummary = evidenceApi.summarizeSources(state.routes);
    var webrtc = webrtcAssessment();
    return [
      "AI Signal Guard · 通用数字环境检测",
      PROJECT_URL,
      "网络参考分：" + currentScoreText(),
      "出口 IP：" + (state.privacy ? maskIpValue(state.observations.exitIp) : state.observations.exitIp || "未取得"),
      "主流地区：" + (country.value || "未形成") + " · " + country.votes + " / 10 票",
      "IP 情报：可用 " + intelSummary.usable + " / 10",
      "路由注册：可用 " + routeSummary.usable + " / 10",
      "STUN：响应 " + webrtc.successes.length + " / 10",
      "系统时区：" + state.observations.timezone,
      "浏览器语言：" + state.observations.languages.join(" · "),
      "结果在当前浏览器内整理；第三方来源可能看到本轮目标 IP。",
    ].join("\n");
  }

  function aiDiagnosticReportText() {
    var country = evidenceApi.computeCountryConsensus(state.ipIntel);
    var asn = evidenceApi.computeAsnConsensus(state.ipIntel);
    var organization = evidenceApi.computeOrganizationConsensus(state.ipIntel);
    var intelSummary = evidenceApi.summarizeSources(state.ipIntel);
    var routeSummary = evidenceApi.summarizeSources(state.routes);
    var webrtc = webrtcAssessment();
    var failedIntel = state.ipIntel.filter(function (record) { return !sourceUsable(record); }).map(function (record) { return record.name + "（" + record.status + "）"; });
    var failedRoutes = state.routes.filter(function (record) { return !sourceUsable(record); }).map(function (record) { return record.name + "（" + record.status + "）"; });
    return [
      "请作为网络环境与浏览器一致性诊断助手，分析以下 AI Signal Guard 检测结果。不要仅复述数据，请指出最值得核对的信号、可能原因和建议顺序。",
      "",
      "AI Signal Guard",
      "https://betaer.github.io/AiSignalGuard/",
      "",
      "【检测概览】",
      "环境画像：通用数字环境检测",
      "网络参考分：" + currentScoreText(),
      "隐私显示：" + (state.privacy ? "已隐藏敏感原值" : "显示原值"),
      "",
      "【网络出口】",
      "公网地址：" + (state.privacy ? maskIpValue(state.observations.exitIp) : state.observations.exitIp || "未取得"),
      "主流地区：" + (country.value || "未形成") + " · " + country.votes + " / 10 票（可投票 " + country.eligible + " 家）",
      "ASN：" + (asn.value || "未形成") + " · " + asn.votes + " / 10 票",
      "组织：" + (organization.value || "未形成") + " · " + organization.votes + " / 10 票",
      "",
      "【环境一致性】",
      "系统时区：" + state.observations.timezone,
      "浏览器语言：" + state.observations.languages.join(" · "),
      "",
      "【泄漏与多源互证】",
      "DNS：" + (state.dns.error || state.dns.records.length + " 个真实解析器记录"),
      "WebRTC：" + webrtc.label + "；" + webrtc.successes.length + " / 10 STUN 节点响应",
      "IP 情报：可用 " + intelSummary.usable + " / 10，完整 " + intelSummary.complete + "，部分字段 " + intelSummary.partial + "，失败 " + intelSummary.failed,
      "路由注册：可用 " + routeSummary.usable + " / 10，完整 " + routeSummary.complete + "，部分字段 " + routeSummary.partial + "，失败 " + routeSummary.failed,
      "IP 情报失败明细：" + (failedIntel.join("、") || "无"),
      "路由注册失败明细：" + (failedRoutes.join("、") || "无"),
      "",
      "【浏览器本地信号】",
      "本地稳定摘要：" + displayedFingerprint("v3"),
      "本地宽域摘要：" + displayedFingerprint("v2"),
      "JA3 / JA4：" + displayedFingerprint("tls"),
      "",
      "请按以下结构回答：",
      "1. 一句话结论",
      "2. 需要优先核对的信号及原因",
      "3. 已确认正常的信号",
      "4. 按优先级排列的调整建议",
      "5. 哪些结论受失败、超时或字段不完整的实时来源限制",
    ].join("\n");
  }

  function markCopyComplete(config) {
    var button = $("#" + config.buttonId);
    var label = $("#" + config.labelId);
    button.dataset.copyComplete = "true";
    button.setAttribute("aria-label", config.completeAria);
    label.textContent = config.completeLabel;
    clearTimeout(button.copyResetTimer);
    button.copyResetTimer = setTimeout(function () {
      button.dataset.copyComplete = "false";
      button.setAttribute("aria-label", config.idleAria);
      label.textContent = config.idleLabel;
    }, 1600);
  }

  async function copySummary() {
    var copied = await copyText(summaryText(), "摘要已复制 🤩");
    if (copied) markCopyComplete({ buttonId: "floating-copy", labelId: "floating-copy-label", idleLabel: "复制摘要", idleAria: "复制摘要", completeLabel: "摘要已复制", completeAria: "摘要已复制" });
  }

  async function copyAiReport() {
    var copied = await copyText(aiDiagnosticReportText(), "已复制，请发给AI协助排查解决问题 👨‍🔧");
    if (copied) markCopyComplete({ buttonId: "floating-ai-report", labelId: "floating-ai-label", idleLabel: "复制给 ChatGPT / Claude", idleAria: "复制给 ChatGPT 或 Claude 诊断", completeLabel: "AI 诊断已复制", completeAria: "AI 诊断内容已复制" });
  }

  function updateFingerprintView() {
    Object.entries(state.fingerprints).forEach(function (entry) {
      var type = entry[0];
      var data = entry[1];
      var label = document.querySelector('[data-fingerprint-label="' + type + '"]');
      var value = document.querySelector('[data-fingerprint-value="' + type + '"]');
      var description = document.querySelector('[data-fingerprint-description="' + type + '"]');
      if (label) label.textContent = data.label;
      if (value) value.textContent = displayedFingerprint(type);
      if (description) description.textContent = data.description;
    });
    var list = $("#fingerprint-evidence");
    list.replaceChildren();
    [
      ["平台", state.localSignals.platform],
      ["屏幕", state.localSignals.screen],
      ["CPU / 内存提示", (state.localSignals.hardwareConcurrency || "未知") + " 线程 · " + (state.localSignals.deviceMemory || "未知") + " GB"],
      ["Canvas / 字体", (state.localSignals.canvasAvailable ? "Canvas 可用" : "Canvas 不可用") + " · " + state.localSignals.detectedFonts.length + " 个字体候选"],
    ].forEach(function (entry) {
      var item = document.createElement("li");
      item.append(makeTextElement("strong", "", entry[0]));
      item.append(document.createTextNode(entry[1]));
      list.append(item);
    });
  }

  async function sha256(value) {
    if (!globalThis.crypto || !crypto.subtle || typeof TextEncoder === "undefined") return null;
    var buffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
    return Array.from(new Uint8Array(buffer)).map(function (byte) { return byte.toString(16).padStart(2, "0"); }).join("");
  }

  async function computeFingerprints() {
    var stableSource = JSON.stringify({
      platform: state.localSignals.platform,
      languages: state.observations.languages,
      timezone: state.observations.timezone,
      colorDepth: state.localSignals.colorDepth,
    });
    var broadSource = JSON.stringify({
      stable: stableSource,
      userAgent: state.localSignals.userAgent,
      screen: state.localSignals.screen,
      hardwareConcurrency: state.localSignals.hardwareConcurrency,
      deviceMemory: state.localSignals.deviceMemory,
      fonts: state.localSignals.detectedFonts,
    });
    try {
      var values = await Promise.all([sha256(stableSource), sha256(broadSource)]);
      state.fingerprints.v3.value = values[0] || "当前上下文不可计算";
      state.fingerprints.v2.value = values[1] || "当前上下文不可计算";
    } catch (error) {
      state.fingerprints.v3.value = "计算失败";
      state.fingerprints.v2.value = "计算失败";
    }
    updateFingerprintView();
  }

  function fetchWithTimeout(url, options) {
    var config = options || {};
    var controller = new AbortController();
    var timedOut = false;
    var externalSignal = config.signal;
    function abortFromExternal() { controller.abort(); }
    if (externalSignal) {
      if (externalSignal.aborted) abortFromExternal();
      else externalSignal.addEventListener("abort", abortFromExternal, { once: true });
    }
    var timer = setTimeout(function () { timedOut = true; controller.abort(); }, config.timeoutMs || 8000);
    return fetch(url, { cache: "no-store", mode: "cors", referrerPolicy: "no-referrer", signal: controller.signal })
      .catch(function (error) {
        if (timedOut) throw new Error("请求超时");
        throw error;
      })
      .finally(function () {
        clearTimeout(timer);
        if (externalSignal) externalSignal.removeEventListener("abort", abortFromExternal);
      });
  }

  function loadProbeImage(url, signal) {
    return new Promise(function (resolve) {
      var image = new Image();
      var settled = false;
      function finish() {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (signal) signal.removeEventListener("abort", finish);
        image.onload = null;
        image.onerror = null;
        image.src = "";
        resolve();
      }
      var timer = setTimeout(finish, 5000);
      image.onload = finish;
      image.onerror = finish;
      if (signal) signal.addEventListener("abort", finish, { once: true });
      image.referrerPolicy = "no-referrer";
      image.src = url;
    });
  }

  async function runDnsLeak(signal, runId) {
    state.dns = { state: "loading", running: true, records: [], error: null };
    render();
    try {
      var idResponse = await fetchWithTimeout("https://bash.ws/id", { timeoutMs: 8000, signal: signal });
      if (!idResponse.ok) throw new Error("bash.ws ID HTTP " + idResponse.status);
      var id = String(await idResponse.text()).trim();
      if (!/^[a-z0-9]{6,}$/i.test(id)) throw new Error("bash.ws 未返回有效检测 ID");
      var probes = [];
      for (var index = 1; index <= 10; index += 1) {
        probes.push(loadProbeImage("https://" + index + "." + id + ".bash.ws/logo.png", signal));
      }
      await Promise.all(probes);
      await new Promise(function (resolve) { setTimeout(resolve, 1200); });
      var resultResponse = await fetchWithTimeout("https://bash.ws/dnsleak/test/" + id + "?json", { timeoutMs: 9000, signal: signal });
      if (!resultResponse.ok) throw new Error("bash.ws 结果 HTTP " + resultResponse.status);
      var payload = await resultResponse.json();
      if (!Array.isArray(payload)) throw new Error("bash.ws 返回格式无效");
      if (runId !== state.runId || signal.aborted) return;
      var servers = payload.filter(function (item) { return item && item.type === "dns"; });
      state.dns = {
        state: "success",
        running: false,
        error: null,
        records: servers.map(function (server, index) {
          return {
            id: "dns-" + (index + 1),
            name: "解析器 " + (index + 1),
            state: "success",
            status: "已发现",
            voteEligible: true,
            attempted: true,
            observedIp: evidenceApi.normalizeIp(server.ip),
            countryCode: evidenceApi.normalizeCountryCode(server.country_code || server.country),
            countryName: stringValue(server.country_name || server.country),
            asn: evidenceApi.normalizeAsn(server.asn),
          };
        }),
      };
    } catch (error) {
      if (runId !== state.runId || signal.aborted) return;
      state.dns = { state: "network_error", running: false, records: [], error: "DNS 检测失败：" + (error.message || error) };
    }
    render();
  }

  function blockedRecords(registry, message) {
    return evidenceApi.createPendingRecords(registry).map(function (record) {
      return Object.assign(record, { state: "blocked", status: "缺少前置数据", detail: message });
    });
  }

  function isCurrentRun(runId, signal) {
    return runId === state.runId && !signal.aborted;
  }

  async function runLiveDetection(options) {
    var config = options || {};
    if (state.runController) state.runController.abort();
    var controller = new AbortController();
    var runId = state.runId + 1;
    state.runId = runId;
    state.runController = controller;
    state.running = true;
    state.completedAt = null;
    state.publicIp = { state: "loading", ip: null, status: "检测中" };
    state.observations.exitIp = null;
    state.ipIntel = evidenceApi.createPendingRecords(evidenceApi.IP_INTEL_SOURCES);
    state.routes = evidenceApi.createPendingRecords(evidenceApi.ROUTE_SOURCES);
    state.stun = evidenceApi.createPendingRecords(evidenceApi.STUN_NODES);
    state.dns = { state: "pending", running: false, records: [], error: null };
    setRecheckControls(true);
    render();

    var stunPromise = evidenceApi.runStunNodes({
      signal: controller.signal,
      concurrency: 5,
      timeoutMs: 5000,
      onUpdate: function (records) {
        if (!isCurrentRun(runId, controller.signal)) return;
        state.stun = records;
        render();
      },
    }).catch(function () { return state.stun; });
    var dnsPromise = runDnsLeak(controller.signal, runId);
    var publicIp = await evidenceApi.discoverPublicIp({ signal: controller.signal, timeoutMs: 7000 });
    if (!isCurrentRun(runId, controller.signal)) return false;
    state.publicIp = publicIp;
    state.observations.exitIp = publicIp.ip;
    render();
    if (typeof config.onPhase === "function") config.onPhase(1);

    if (publicIp.ip) {
      state.ipIntel = await evidenceApi.runIpIntel({
        targetIp: publicIp.ip,
        signal: controller.signal,
        timeoutMs: 7000,
        concurrency: 10,
        onUpdate: function (records) {
          if (!isCurrentRun(runId, controller.signal)) return;
          state.ipIntel = records;
          render();
        },
      });
      if (!isCurrentRun(runId, controller.signal)) return false;
      var asn = evidenceApi.computeAsnConsensus(state.ipIntel);
      if (typeof config.onPhase === "function") config.onPhase(2);
      state.routes = await evidenceApi.runRouteEvidence({
        targetIp: publicIp.ip,
        asn: asn.value,
        signal: controller.signal,
        timeoutMs: 7000,
        concurrency: 10,
        onUpdate: function (records) {
          if (!isCurrentRun(runId, controller.signal)) return;
          state.routes = records;
          render();
        },
      });
    } else {
      state.ipIntel = blockedRecords(evidenceApi.IP_INTEL_SOURCES, "未取得真实公网地址，无法构造查询");
      state.routes = blockedRecords(evidenceApi.ROUTE_SOURCES, "未取得真实公网地址，无法构造查询");
    }
    await Promise.allSettled([stunPromise, dnsPromise]);
    if (!isCurrentRun(runId, controller.signal)) return false;
    state.running = false;
    state.completedAt = new Date();
    state.runController = null;
    setRecheckControls(false);
    render();
    return true;
  }

  var loadingStages = [
    { title: "读取公网出口与浏览器信号", copy: "正在读取当前公网地址、时区、语言与本地浏览器能力。", progress: 18 },
    { title: "交叉核对 10 家 IP 情报", copy: "正在逐家读取国家、城市、ASN、组织、网络类型与风险字段。", progress: 52 },
    { title: "核对路由、DNS 与 WebRTC", copy: "正在等待 10 路注册来源、权威 DNS 探针和 10 个独立 STUN 节点。", progress: 82 },
  ];

  function formatRunTime(date) {
    function pad(value) { return String(value).padStart(2, "0"); }
    return date.getFullYear() + "." + pad(date.getMonth() + 1) + "." + pad(date.getDate()) + " " + pad(date.getHours()) + ":" + pad(date.getMinutes());
  }

  function renderLoadingStage(index, progressOverride) {
    var bounded = Math.max(0, Math.min(index, loadingStages.length - 1));
    var stage = loadingStages[bounded];
    var progress = typeof progressOverride === "number" ? progressOverride : stage.progress;
    $("#recheck-loading-title").textContent = progress >= 100 ? "实时检测已完成" : stage.title;
    $("#recheck-loading-copy").textContent = progress >= 100 ? "所有来源已结算，失败、超时与字段缺失均已如实保留。" : stage.copy;
    $("#recheck-progress-fill").style.width = progress + "%";
    $("#recheck-progress-value").textContent = progress + "%";
    $("#recheck-progress-track").setAttribute("aria-valuenow", String(progress));
    $$('[data-loading-step]').forEach(function (item, itemIndex) {
      item.classList.toggle("is-active", itemIndex <= bounded);
    });
  }

  function setRecheckControls(running) {
    var button = $("#floating-recheck");
    var label = running ? "检测中…" : "重新检测";
    button.disabled = running;
    button.dataset.running = String(running);
    button.setAttribute("aria-label", label);
    $("#floating-recheck-label").textContent = label;
  }

  async function runRecheck() {
    if (state.running) return;
    state.runCount += 1;
    var overlay = $("#recheck-loading");
    var reducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    document.body.dataset.recheckLoading = "true";
    overlay.hidden = false;
    renderLoadingStage(0);
    requestAnimationFrame(function () { overlay.classList.add("is-visible"); });
    window.scrollTo({ top: 0, behavior: reducedMotion ? "auto" : "smooth" });
    var minimumReveal = new Promise(function (resolve) { setTimeout(resolve, reducedMotion ? 100 : 1500); });
    var completed = await runLiveDetection({
      onPhase: function (phase) { renderLoadingStage(phase); },
    });
    await minimumReveal;
    if (!completed) return;
    renderLoadingStage(2, 100);
    await new Promise(function (resolve) { setTimeout(resolve, reducedMotion ? 0 : 320); });
    overlay.classList.remove("is-visible");
    await new Promise(function (resolve) { setTimeout(resolve, reducedMotion ? 0 : 240); });
    overlay.hidden = true;
    document.body.removeAttribute("data-recheck-loading");
    $("#floating-action-status").textContent = "实时检测完成，第 " + state.runCount + " 次结果已更新。";
    showToast("检测完成，结果已揭晓 🤩");
  }

  function closeStarSupportDialog() {
    state.pendingRecheck = false;
    var dialog = $("#star-support-dialog");
    if (dialog.open) dialog.close();
  }

  function continueStarSupport() {
    var shouldContinue = state.pendingRecheck;
    state.pendingRecheck = false;
    var dialog = $("#star-support-dialog");
    if (dialog.open) dialog.close();
    if (shouldContinue) runRecheck();
  }

  function requestRecheck() {
    if (state.running) return;
    if (!starPromptPolicy.shouldPrompt()) {
      runRecheck();
      return;
    }
    var dialog = $("#star-support-dialog");
    if (!dialog || typeof dialog.showModal !== "function") {
      runRecheck();
      return;
    }
    if (dialog.open) return;
    state.pendingRecheck = true;
    starPromptPolicy.remember();
    dialog.showModal();
  }

  function normalizeStarCount(value) {
    return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
  }

  function renderStarCount(count, starState) {
    var shortcut = $("#github-shortcut");
    var normalized = normalizeStarCount(count);
    var visible = normalized === null ? "Star" : String(normalized);
    $("#star-count").textContent = visible;
    $("#github-label").textContent = "GitHub · " + visible;
    shortcut.dataset.starState = starState;
  }

  function loadStars() {
    try {
      var cached = JSON.parse(localStorage.getItem(STAR_CACHE_KEY) || "null");
      if (cached && normalizeStarCount(cached.count) !== null && Date.now() - cached.savedAt < STAR_CACHE_TTL_MS) {
        renderStarCount(cached.count, "cached");
        return;
      }
    } catch (error) {}
    fetch("https://api.github.com/repos/" + GITHUB_REPO, { headers: { Accept: "application/vnd.github+json" } })
      .then(function (response) { if (!response.ok) throw new Error(); return response.json(); })
      .then(function (repository) {
        var count = normalizeStarCount(repository.stargazers_count);
        if (count === null) throw new Error();
        try { localStorage.setItem(STAR_CACHE_KEY, JSON.stringify({ count: count, savedAt: Date.now() })); } catch (error) {}
        renderStarCount(count, "loaded");
      })
      .catch(function () { renderStarCount(null, "fallback"); });
  }

  var backTopScheduled = false;
  function updateBackToTopVisibility() {
    var floatingTop = $("#floating-top");
    var visible = window.scrollY >= window.innerHeight;
    floatingTop.dataset.visible = String(visible);
    floatingTop.setAttribute("aria-hidden", String(!visible));
    floatingTop.tabIndex = visible ? 0 : -1;
  }

  function scheduleBackToTopUpdate() {
    if (backTopScheduled) return;
    backTopScheduled = true;
    requestAnimationFrame(function () {
      backTopScheduled = false;
      updateBackToTopVisibility();
    });
  }

  var lastScrollY = window.scrollY;
  var dockReadingTimer = 0;
  function updateFloatingDockReadingState() {
    var dock = $(".floating-tool-dock");
    if (!dock) return;
    var currentY = window.scrollY;
    var mobileLayout = window.matchMedia
      ? window.matchMedia("(max-width: 680px)").matches
      : window.innerWidth <= 680;
    if (!mobileLayout || currentY <= 96) {
      dock.dataset.reading = "false";
    } else if (currentY > lastScrollY + 8) {
      dock.dataset.reading = "true";
    } else if (currentY < lastScrollY - 8) {
      dock.dataset.reading = "false";
    }
    if (Math.abs(currentY - lastScrollY) > 8) lastScrollY = currentY;
    clearTimeout(dockReadingTimer);
    dockReadingTimer = setTimeout(function () {
      dock.dataset.reading = "false";
    }, 850);
  }

  function resetFloatingDockReadingState() {
    lastScrollY = window.scrollY;
    var dock = $(".floating-tool-dock");
    if (dock) dock.dataset.reading = "false";
  }

  validatePageContract();
  prepareSignalRows();
  $$(".signal-row-chevron, .row-status-dot").forEach(function (node) { node.setAttribute("aria-hidden", "true"); });
  $$(".module-tab").forEach(function (link) {
    link.addEventListener("click", function (event) {
      var target = document.querySelector(link.getAttribute("href"));
      if (!target) return;
      event.preventDefault();
      $$(".module-tab").forEach(function (candidate) { candidate.setAttribute("aria-current", "false"); });
      link.setAttribute("aria-current", "true");
      if (location.hash === link.hash) history.replaceState(null, "", link.hash);
      else history.pushState(null, "", link.hash);
      beginSectionNavigationAlignment(target);
    });
  });
  ["wheel", "touchstart", "pointerdown"].forEach(function (eventName) {
    window.addEventListener(eventName, stopSectionNavigationAlignment, { passive: true });
  });
  window.addEventListener("keydown", function (event) {
    if (["ArrowUp", "ArrowDown", "PageUp", "PageDown", "Home", "End", " "].includes(event.key)) {
      stopSectionNavigationAlignment();
    }
  });
  $("#privacy-toggle").addEventListener("click", function () { state.privacy = !state.privacy; updateSensitiveValues(); showToast(state.privacy ? "已开启隐私遮罩" : "已显示原始值"); });
  $("#floating-ai-report").addEventListener("click", copyAiReport);
  $("#floating-copy").addEventListener("click", copySummary);
  $("#floating-recheck").addEventListener("click", requestRecheck);
  $("#star-support-close").addEventListener("click", closeStarSupportDialog);
  $("#star-support-continue").addEventListener("click", continueStarSupport);
  $("#star-support-github").addEventListener("click", continueStarSupport);
  $("#star-support-dialog").addEventListener("cancel", function (event) { event.preventDefault(); });
  $$('[data-copy-fingerprint]').forEach(function (button) {
    button.addEventListener("click", function () {
      copyText(displayedFingerprint(button.dataset.copyFingerprint), "指纹摘要已复制");
    });
  });
  document.addEventListener("click", function (event) {
    $$(".info-tip[open]").forEach(function (tip) {
      if (!tip.contains(event.target)) tip.removeAttribute("open");
    });
  });
  window.addEventListener("scroll", function () {
    scheduleBackToTopUpdate();
    scheduleSectionNavigationUpdate();
    updateFloatingDockReadingState();
    $$(".info-tip[open]").forEach(positionInfoTip);
  }, { passive: true });
  window.addEventListener("resize", function () {
    scheduleBackToTopUpdate();
    scheduleSectionNavigationUpdate();
    resetFloatingDockReadingState();
    $$(".info-tip[open]").forEach(positionInfoTip);
  });
  window.addEventListener("hashchange", alignSectionFromLocationHash);
  window.addEventListener("popstate", alignSectionFromLocationHash);
  $$(".info-tip").forEach(setupInfoTip);
  updateBackToTopVisibility();
  updateSectionNavigation();
  updateFingerprintView();
  computeFingerprints();
  loadStars();
  render();
  runLiveDetection();
  alignSectionFromLocationHash();
})();
