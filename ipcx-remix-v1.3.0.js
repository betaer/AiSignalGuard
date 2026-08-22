(function bootstrapIpcxRemixV130() {
  "use strict";

  var evidenceApi = globalThis.AISGIpEvidence;
  if (!evidenceApi) {
    throw new Error("IPCX 实时证据模块加载失败");
  }

  var GITHUB_REPO = "betaer/AiSignalGuard";
  var PROJECT_URL = "https://betaer.github.io/AiSignalGuard/";
  var STAR_CACHE_KEY = "aisg-github-stars";
  var STAR_CACHE_TTL_MS = 30 * 60 * 1000;
  var MIN_SCORE_COVERAGE = 40;
  var MIN_SCORE_EVIDENCE_PER_DOMAIN = 3;
  var REMIX_DEFAULT_ROUTE = "#/overview";
  var REMIX_RESULT_ROUTES = ["overview", "network", "leaks", "paths", "browser"];
  var REMIX_TOOL_ROUTES = ["ip", "dns", "stun", "cdn", "split", "multi", "latency"];
  var pendingRouteFocusOrigin = "programmatic";
  var REMIX_ROUTE_LABELS = Object.freeze({
    overview: "总览",
    network: "网络身份",
    leaks: "泄漏与解析",
    paths: "路径与节点",
    browser: "浏览器环境",
    tools: "高级工具中心",
    "tool-ip": "任意 IP 洞察",
    "tool-dns": "DNS 出口矩阵",
    "tool-stun": "STUN 节点矩阵",
    "tool-cdn": "CDN 边缘节点",
    "tool-split": "网站分流矩阵",
    "tool-multi": "全球多出口扫描",
    "tool-latency": "延迟与稳定性",
  });
  var $ = function (selector) {
    return document.querySelector(selector);
  };
  var $$ = function (selector) {
    return Array.from(document.querySelectorAll(selector));
  };
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
    { id: "dns-leak", title: "DNS 泄漏", evidenceSet: "dnsResolverAddresses", evidenceTitle: "解析器明细" },
    { id: "dns-region-consistency", title: "DNS 地区一致性", evidenceSet: "dnsResolverRegions", evidenceTitle: "解析器地区" },
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

  function readTimezone() {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || "未知";
    } catch (error) {
      return "未知";
    }
  }

  function readLanguages() {
    return Array.isArray(navigator.languages) && navigator.languages.length
      ? navigator.languages.slice()
      : [navigator.language || "未知"];
  }

  var state = {
    privacy: false,
    running: false,
    runCount: 0,
    runId: 0,
    runController: null,
    completedAt: null,
    autoDisclosureRunId: 0,
    publicIp: { state: "pending", ip: null, status: "等待检测" },
    observations: {
      exitIp: null,
      timezone: readTimezone(),
      languages: readLanguages(),
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
    coreResults: {},
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

  function refreshLocalEnvironment() {
    state.observations.timezone = readTimezone();
    state.observations.languages = readLanguages();
    state.localSignals = collectLocalSignals();
    state.fingerprints.v3.value = "计算中…";
    state.fingerprints.v2.value = "计算中…";
    updateFingerprintView();
    updateSensitiveValues();
  }

  function invariant(condition, message) {
    if (!condition) throw new Error("[IPCX] " + message);
  }

  function validatePageContract() {
    invariant(evidenceApi.IP_INTEL_SOURCES.length === 10, "IP 情报来源必须是 10 家");
    invariant(evidenceApi.ROUTE_SOURCES.length === 10, "路由与注册来源必须是 10 路");
    invariant(evidenceApi.STUN_NODES.length === 10, "STUN 节点必须是 10 个");
    invariant(document.documentElement.dataset.remixVersion === "1.3.0", "Remix 页面版本必须是 1.3.0");
    invariant($$("[data-remix-view]").length === 13, "Remix 必须包含 13 个可路由视图");
    invariant($$(".module-tab[data-route]").length === REMIX_RESULT_ROUTES.length, "结果导航必须是 5 项");
    invariant($$(".advanced-tool-card[data-tool]").length === REMIX_TOOL_ROUTES.length, "高级工具必须是 7 项");
    var rows = $$(".signal-row");
    invariant(rows.length === rowDefinitions.length, "详情行数量与定义不一致");
    invariant(new Set(rows.map(function (row) { return row.dataset.rowId; })).size === rows.length, "详情行标识必须唯一");
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

  function sourceEligible(record) {
    return sourceUsable(record) && record.voteEligible === true;
  }

  function summarizeSourceProgress(records) {
    var summary = evidenceApi.summarizeSources(records);
    summary.pending = records.filter(function (record) {
      return record.state === "pending" || record.state === "loading";
    }).length;
    summary.failed = records.filter(function (record) {
      return record.attempted && !sourceUsable(record) && record.state !== "pending" && record.state !== "loading";
    }).length;
    summary.skipped = records.filter(function (record) {
      return !record.attempted && record.state !== "pending" && record.state !== "loading";
    }).length;
    return summary;
  }

  function sourceProgressLabel(summary) {
    var parts = ["完整 " + summary.complete, "部分 " + summary.partial];
    if (summary.pending) parts.push("进行中 " + summary.pending);
    if (summary.failed) parts.push("失败 " + summary.failed);
    if (summary.skipped) parts.push("未执行 " + summary.skipped);
    return parts.join("、");
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
    var conflicts = [];
    if (country && record.countryCode && record.countryCode !== country) conflicts.push("国家");
    if (asn && record.asn && record.asn !== asn) conflicts.push("ASN");
    if (
      organization &&
      record.organization &&
      record.organization.toLowerCase() !== organization.toLowerCase()
    ) conflicts.push("组织");
    return conflicts.length
      ? { label: conflicts.join(" / ") + "冲突", tone: "bad" }
      : { label: "无明确冲突", tone: record.state === "partial" ? "warn" : "good" };
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

  function isDnsAddressUsable(record) {
    return Boolean(record && record.observedIp);
  }

  function isDnsRegionComparable(record, exitCountry) {
    return Boolean(exitCountry && isDnsAddressUsable(record) && record.countryCode);
  }

  function assessDnsEvidence(exitCountry) {
    var records = state.dns.records;
    var addressRecords = records.filter(isDnsAddressUsable);
    var comparable = records.filter(function (record) {
      return isDnsRegionComparable(record, exitCountry);
    });
    var matches = comparable.filter(function (record) {
      return record.countryCode === exitCountry;
    });
    return {
      records: records,
      addressRecords: addressRecords,
      comparable: comparable,
      matches: matches,
      conflicts: comparable.length - matches.length,
      addressMissing: records.length - addressRecords.length,
      regionMissing: records.length - comparable.length,
      incomplete: !exitCountry || !comparable.length || comparable.length !== records.length,
    };
  }

  function dnsEvidence(mode, exitCountry) {
    var regionMode = mode === "region";
    if (state.dns.records.length) {
      return state.dns.records.map(function (record) {
        var addressAvailable = isDnsAddressUsable(record);
        var regionAvailable = isDnsRegionComparable(record, exitCountry);
        var item = {
          name: record.name,
          meta: [record.countryName || record.countryCode || "地区未知", record.asn || "ASN 未提供"]
            .join(" · "),
          metaSensitive: "network",
          value: record.observedIp || "未提供地址",
          status: record.status,
          tone: sourceTone(record),
          sensitive: record.observedIp ? "ip" : null,
          rawState: record.state,
          attempted: Boolean(record.attempted),
          usable: regionMode ? regionAvailable : addressAvailable,
        };
        if (regionMode) {
          if (!addressAvailable) {
            item.status = "地址缺失";
            item.tone = "warn";
          } else if (!record.countryCode) {
            item.status = "地区字段缺失";
            item.tone = "warn";
          } else if (!exitCountry) {
            item.status = "出口地区未确认";
            item.tone = "warn";
          } else {
            item.status = record.countryCode === exitCountry ? "地区一致" : "地区不同";
            item.tone = record.countryCode === exitCountry ? "good" : "bad";
          }
        }
        return item;
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
        { usable: Boolean(record.voteEligible && (record.asn || record.organization)) },
      );
    });
    var geoRows = intel.map(function (record) {
      var vote = record.voteEligible && record.countryCode && record.countryCode === country.value;
      var item = toEvidenceItem(
        record,
        [record.countryCode || record.countryName || "未提供国家", record.city || "未提供城市"].join(" · "),
        { usable: Boolean(record.voteEligible && (record.countryCode || record.countryName)) },
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
        {
          usable: Boolean(record.voteEligible && [record.proxy, record.vpn, record.tor, record.hosting]
            .some(function (value) { return value !== null; })),
        },
      );
    });
    var typeRows = intel.map(function (record) {
      return toEvidenceItem(
        record,
        "网络类型：" + (record.networkType || "未提供") + " · 组织：" + (record.organization || "未提供"),
        { usable: Boolean(record.voteEligible && record.networkType) },
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
        { usable: Boolean(record.voteEligible && (record.countryCode || record.asn || record.organization)) },
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
        { meta: (node ? node.url : "STUN") + " · " + latencyLabel(record), sensitive: record.observedIp ? "ip" : null, usable: Boolean(record.voteEligible && record.observedIp) },
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
      dnsResolverAddresses: dnsEvidence("address", country.value),
      dnsResolverRegions: dnsEvidence("region", country.value),
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
    if (!tip.open || window.innerWidth <= 480) return;
    var summary = tip.querySelector("summary");
    var bubble = tip.querySelector(".info-tip-bubble");
    if (!summary || !bubble) return;
    var summaryRect = summary.getBoundingClientRect();
    var bubbleRect = bubble.getBoundingClientRect();
    var viewportPadding = 12;
    var left = Math.min(
      Math.max(viewportPadding, summaryRect.right - bubbleRect.width),
      window.innerWidth - bubbleRect.width - viewportPadding,
    );
    var top = summaryRect.top - bubbleRect.height - 8;
    if (top < viewportPadding) top = summaryRect.bottom + 8;
    top = Math.min(
      Math.max(viewportPadding, top),
      window.innerHeight - bubbleRect.height - viewportPadding,
    );
    bubble.style.setProperty("--info-tip-left", Math.round(left) + "px");
    bubble.style.setProperty("--info-tip-top", Math.round(top) + "px");
  }

  function setupInfoTip(tip) {
    if (tip.dataset.infoTipReady === "true") return;
    tip.dataset.infoTipReady = "true";
    tip.addEventListener("toggle", function () {
      if (tip.open) requestAnimationFrame(function () { positionInfoTip(tip); });
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
    var sourceMetaNode = listItem.querySelector(".metric-evidence-source small");
    if (item.metaSensitive) {
      sourceMetaNode.dataset.sensitive = item.metaSensitive;
      sourceMetaNode.dataset.sensitiveValue = item.meta || "—";
      renderSensitive(sourceMetaNode);
    } else {
      delete sourceMetaNode.dataset.sensitive;
      delete sourceMetaNode.dataset.sensitiveValue;
      sourceMetaNode.textContent = item.meta || "—";
    }
    var value = listItem.querySelector(".metric-evidence-value");
    value.className = "metric-evidence-value";
    value.classList.add("sensitive-value");
    value.dataset.sensitive = item.sensitive || "evidence";
    value.dataset.sensitiveValue = item.value || "—";
    renderSensitive(value);
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
      row.open = Boolean(definition.evidenceSet);
      row.dataset.defaultVisibility = definition.evidenceSet ? "expanded" : "summary";

      var detailGrid = row.querySelector(".row-detail-grid");
      if (!detailGrid || detailGrid.dataset.prepared === "true") return;
      detailGrid.dataset.prepared = "true";
      var detailItems = Array.from(detailGrid.children).filter(function (child) {
        return child.classList.contains("row-detail-item");
      });
      var supportingItems = detailItems.slice(1);
      if (!supportingItems.length) return;

      var explanation = document.createElement("details");
      explanation.className = "row-explanation";
      var summary = document.createElement("summary");
      summary.textContent = "判读说明与建议";
      var explanationGrid = document.createElement("div");
      explanationGrid.className = "row-explanation-grid";
      supportingItems.forEach(function (item) { explanationGrid.append(item); });
      explanation.append(summary, explanationGrid);
      detailGrid.after(explanation);
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
      var ipv6Parts = text.split(":").filter(Boolean);
      if (!ipv6Parts.length || text.indexOf("::") === 0) return "IPv6:…";
      return ipv6Parts.slice(0, 2).join(":") + ":…";
    }
    return text;
  }

  function escapeSensitivePattern(value) {
    return String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function validIpv6Literal(value) {
    var candidate = String(value || "");
    if (candidate.indexOf(":") < 0) return false;
    try {
      var parsed = new URL("http://[" + candidate + "]/index");
      return parsed.hostname.indexOf(":") >= 0;
    } catch (error) {
      return false;
    }
  }

  function maskNetworkAddresses(value) {
    return String(value || "")
      .replace(/\b[0-9a-f]{8}-[0-9a-f-]{20,}\.local\b/gi, "••••••••.local")
      .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, function (address) { return maskIpValue(address); })
      .replace(/[0-9a-f:.]*:[0-9a-f:.]+/gi, function (address) {
        var trailingPunctuation = (address.match(/\.+$/) || [""])[0];
        var literal = trailingPunctuation ? address.slice(0, -trailingPunctuation.length) : address;
        return validIpv6Literal(literal) ? maskIpValue(literal) + trailingPunctuation : address;
      });
  }

  function replaceKnownSensitive(value, raw, replacement) {
    if (!raw || String(raw).length < 2) return value;
    return value.replace(new RegExp(escapeSensitivePattern(raw), "gi"), replacement);
  }

  function maskSensitiveValue(value, kind) {
    var text = String(value || "");
    if (!text || /^(?:读取中…?|检测中…?|未确认|未知|等待(?:来源|检测|回传)?|未取得|不可读取|—)$/.test(text)) {
      return text;
    }
    if (kind === "fingerprint") {
      return /^[0-9a-f]{16,}$/i.test(text) ? text.slice(0, 8) + "••••••••" : "本地摘要已隐藏";
    }
    if (kind === "device") return "本地设备信号已隐藏";
    if (kind === "evidence") return "敏感证据已隐藏";
    var masked = maskNetworkAddresses(text).replace(/\bAS\d+\b/gi, "AS••••");
    masked = replaceKnownSensitive(masked, state.observations.city, "••••");
    masked = replaceKnownSensitive(masked, state.observations.organization, "组织已隐藏");
    if (kind === "asn") return masked.replace(/\b\d{3,10}\b/g, "••••");
    if (kind === "organization") return "组织已隐藏";
    if (kind === "city") return masked === text ? "精确位置已隐藏" : masked;
    if (kind === "mdns") return masked === text ? "mDNS 候选已隐藏" : masked;
    return masked;
  }

  function renderSensitive(node) {
    if (!node) return;
    var raw = node.dataset.sensitiveValue;
    if (raw === undefined) {
      raw = node.textContent || "";
      node.dataset.sensitiveValue = raw;
    }
    node.textContent = state.privacy
      ? maskSensitiveValue(raw, node.dataset.sensitive || "network")
      : raw;
  }

  function setSensitiveValue(node, rawValue, kind) {
    if (!node) return;
    var value = rawValue || "未取得";
    node.dataset.sensitive = kind || node.dataset.sensitive || "ip";
    node.dataset.sensitiveValue = value;
    renderSensitive(node);
  }

  function displayedFingerprint(type) {
    var data = state.fingerprints[type || "v3"];
    if (!data) return "不可用";
    if (!state.privacy || !/^[0-9a-f]{16,}$/i.test(data.value)) return data.value;
    return data.value.slice(0, 8) + "••••••••";
  }

  function updateSensitiveValues() {
    $$('[data-sensitive]').forEach(renderSensitive);
    $$('[data-fingerprint-value]').forEach(function (node) {
      node.textContent = displayedFingerprint(node.dataset.fingerprintValue);
      node.dataset.sensitiveValue = state.fingerprints[node.dataset.fingerprintValue]?.value || node.textContent;
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
    var pending = state.running;
    return {
      successes: successes,
      ips: ips,
      conflicts: conflicts,
      alternateFamily: alternateFamily,
      tone: pending ? "neutral" : !successes.length ? "warn" : conflicts.length ? "bad" : alternateFamily.length ? "warn" : "good",
      label: pending
        ? successes.length ? "节点核对中" : "检测中"
        : !successes.length
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
    var tone = config.tone || "neutral";
    var definition = rowDefinitions.find(function (entry) { return entry.id === rowId; });
    var resultValue = config.result || config.value || "未确认";
    state.coreResults[rowId] = {
      id: rowId,
      title: definition ? definition.title : rowId,
      value: config.value || "未确认",
      result: resultValue,
      evidence: config.evidence || "本轮尚未取得可核对证据",
      advice: config.advice || "等待更多可核对证据。",
      tone: tone,
      rawState: tone === "bad" ? "failed" : tone === "warn" ? "warning" : tone === "neutral" ? "loading" : "success",
    };
    if (!row) return;
    var value = row.querySelector(".signal-row-value");
    var dot = row.querySelector(".row-status-dot");
    [value, dot].forEach(function (node) {
      if (!node) return;
      node.classList.remove("good", "warn", "bad");
      if (tone !== "neutral") node.classList.add(tone);
    });
    if (value) setSensitiveValue(value, config.value, "network");
    var details = row.querySelectorAll(".row-detail-item");
    var result = details[0] && details[0].querySelector("strong");
    var evidence = details[1] && details[1].querySelector("p");
    var advice = details[2] && details[2].querySelector("p");
    if (result && config.result) setSensitiveValue(result, config.result, "network");
    if (evidence && config.evidence) setSensitiveValue(evidence, config.evidence, "evidence");
    if (advice && config.advice) advice.textContent = config.advice;
  }

  function updateRowSummaries() {
    var intelSummary = summarizeSourceProgress(state.ipIntel);
    var routeSummary = summarizeSourceProgress(state.routes);
    var country = evidenceApi.computeCountryConsensus(state.ipIntel);
    var asn = evidenceApi.computeAsnConsensus(state.ipIntel);
    var organization = evidenceApi.computeOrganizationConsensus(state.ipIntel);
    var type = simpleConsensus(state.ipIntel, "networkType");
    var asnFieldCount = state.ipIntel.filter(function (record) {
      return sourceEligible(record) && Boolean(record.asn || record.organization);
    }).length;
    var typeFieldCount = state.ipIntel.filter(function (record) {
      return sourceEligible(record) && Boolean(record.networkType);
    }).length;
    var riskFieldCount = state.ipIntel.filter(function (record) {
      return sourceEligible(record) && [record.proxy, record.vpn, record.tor, record.hosting]
        .some(function (value) { return value !== null; });
    }).length;
    var conflictFieldCount = state.ipIntel.filter(function (record) {
      return sourceEligible(record) && Boolean(record.countryCode || record.asn || record.organization);
    }).length;
    var countryLabel = country.value || "待判定";
    var timezoneCountry = timezoneRegion(state.observations.timezone);
    var timezoneMismatch = Boolean(country.value && timezoneCountry && country.value !== timezoneCountry);
    var languageCountry = languageRegion(state.observations.languages[0]);
    var languageMismatch = Boolean(country.value && languageCountry && country.value !== languageCountry);
    var webrtc = webrtcAssessment();
    var riskFlags = state.ipIntel.filter(function (record) {
      return record.voteEligible === true && (
        record.proxy === true || record.vpn === true || record.tor === true || record.hosting === true
      );
    });
    var countryConflict = state.ipIntel.filter(function (record) {
      return sourceEligible(record) && country.value && record.countryCode && record.countryCode !== country.value;
    }).length;
    var asnConflict = state.ipIntel.filter(function (record) {
      return sourceEligible(record) && asn.value && record.asn && record.asn !== asn.value;
    }).length;
    var organizationConflict = state.ipIntel.filter(function (record) {
      return sourceEligible(record) && organization.value && record.organization &&
        record.organization.toLowerCase() !== organization.value.toLowerCase();
    }).length;
    var conflictCount = countryConflict + asnConflict + organizationConflict;
    var dnsAssessment = assessDnsEvidence(country.value);
    var dnsRecords = dnsAssessment.records;
    var dnsComparable = dnsAssessment.comparable;
    var dnsCountryMatches = dnsAssessment.matches.length;
    var dnsCountryConflicts = dnsAssessment.conflicts;
    var dnsCountryMissing = dnsAssessment.regionMissing;
    var dnsAddressMissing = dnsAssessment.addressMissing;
    var dnsEvidenceIncomplete = dnsAssessment.incomplete;
    var dnsTone = state.running || state.dns.running
      ? "neutral"
      : state.dns.error
        ? "bad"
        : !dnsRecords.length || dnsEvidenceIncomplete || dnsCountryConflicts
          ? "warn"
          : "good";

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
      tone: country.value ? (country.conflicts ? "warn" : "good") : "neutral",
      result: country.value ? countryName(country.value) + "获得 " + country.votes + " 票" : "尚无可用国家票",
      evidence: "固定列出 10 家地理来源；实际可投票 " + country.eligible + " 家，分歧 " + country.conflicts + " 家。",
      advice: "以国家级共识为主；超时、字段缺失和路径不同均不计票。",
    });
    setRow("exit-ip-quality", {
      value: state.observations.exitIp || state.publicIp.status,
      tone: state.observations.exitIp ? "good" : state.publicIp.state === "pending" || state.publicIp.state === "loading" ? "neutral" : "bad",
      result: state.observations.exitIp ? "公网出口已实时读取" : state.running ? "公网出口仍在检测中" : "未取得公网出口",
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
      tone: !country.value ? "neutral" : timezoneMismatch ? "warn" : "good",
      result: !country.value ? "等待出口地区证据" : timezoneMismatch ? "与出口主流国家不一致" : "未发现明确时区冲突",
      evidence: "系统时区来自浏览器 Intl API；出口主流国家为 " + countryLabel + "。",
      advice: "按真实所在地区与长期使用习惯核对，不建议为了单一网站频繁修改。",
    });
    setRow("browser-language", {
      value: state.observations.languages.join(" · "),
      tone: !country.value ? "neutral" : languageMismatch ? "warn" : "good",
      result: !country.value ? "等待出口地区证据" : languageMismatch ? "首选语言地区与出口主流国家不同" : "未发现明确语言冲突",
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
      value: state.dns.error
        ? "检测失败"
        : state.running || state.dns.running
          ? "检测中…"
          : dnsRecords.length
            ? dnsAssessment.addressRecords.length + " / " + dnsRecords.length + " 个地址可核对"
            : "证据不足",
      tone: dnsTone,
      result: state.dns.error
        ? "本轮未取得权威 DNS 结果"
        : dnsAddressMissing
          ? "解析器地址字段不完整，不能完成泄漏判断"
          : dnsRecords.length
            ? "已取得真实解析器地址"
            : state.running
              ? "解析器仍在检测中"
              : "等待解析器回传",
      evidence: state.dns.error || (dnsRecords.length + " 个解析器来自 bash.ws 本轮权威 DNS 探针；有效地址 " + dnsAssessment.addressRecords.length + " 个、地址缺失 " + dnsAddressMissing + " 个，没有固定填充。"),
      advice: "检测失败不等于没有泄漏；可重测或检查当前网络是否阻止第三方 DNS 探针。",
    });
    setRow("dns-region-consistency", {
      value: dnsComparable.length && country.value ? dnsCountryMatches + " / " + dnsRecords.length + " 与出口同国" : "证据不足",
      tone: dnsTone,
      result: !dnsRecords.length
        ? "尚无解析器地区可比较"
        : dnsEvidenceIncomplete
          ? "解析器地区字段不完整，不能判定一致"
          : dnsCountryConflicts
            ? "解析器地区与出口存在分歧"
            : "解析器地区与出口一致",
      evidence: country.value
        ? "出口主流国家 " + country.value + "；同国 " + dnsCountryMatches + " 个、异国 " + dnsCountryConflicts + " 个、地址缺失 " + dnsAddressMissing + " 个、地区不可比较 " + dnsCountryMissing + " 个。"
        : "尚未形成出口国家共识。",
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
      result: webrtc.successes.length
        ? "成功节点候选种类：" + webrtc.ips.length
        : state.running
          ? "STUN 节点仍在检测中"
          : "本轮没有节点返回公网候选",
      evidence: "每个节点使用独立 RTCPeerConnection；超时和错误保留原状态，不借用其他节点数据。",
      advice: "响应过少可能与 UDP、代理规则或浏览器策略有关。",
    });
    setRow("majority-region", {
      value: country.value ? country.value + " · " + country.votes + " / 10 票" : "0 / 10 票",
      tone: country.value ? (country.conflicts ? "warn" : "good") : "neutral",
      result: country.value ? countryName(country.value) + "为本轮主流地区" : "尚无主流地区",
      evidence: "10 家全部列出；仅 " + country.eligible + " 家真实返回可投票国家字段。",
      advice: "来源失败与字段缺失不会被填成多数结果。",
    });
    setRow("conflict-check", {
      value: conflictCount + " 项明确冲突",
      tone: conflictCount ? "bad" : conflictFieldCount ? "good" : "neutral",
      result: conflictFieldCount ? "国家 " + countryConflict + "、ASN " + asnConflict + "、组织 " + organizationConflict + " 项冲突" : "没有可用于冲突比较的真实字段",
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
      result: sourceProgressLabel(intelSummary),
      evidence: "固定展示 10 家真实 IP 情报服务，本轮实际请求 " + intelSummary.attempted + " / 10，不配置令牌、不填充兜底结果。",
      advice: "限流、超时和字段缺失均会保留并从相应票数中排除。",
    });
    setRow("route-registry-sources", {
      value: "可用 " + routeSummary.usable + " / 10",
      tone: routeSummary.usable >= 6 ? "good" : routeSummary.usable ? "warn" : "neutral",
      result: sourceProgressLabel(routeSummary),
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
    setSensitiveValue($("#summary-exit-ip"), state.observations.exitIp || state.publicIp.status, "ip");
    setSensitiveValue($("#snapshot-exit-ip"), state.observations.exitIp || state.publicIp.status, "ip");
    var locationValue = country.value
      ? [countryName(country.value), cities.value].filter(Boolean).join(" · ")
      : "等待来源";
    setSensitiveValue($("#summary-location"), locationValue, "city");
    setSensitiveValue($("#snapshot-location"), locationValue, "city");
    setSensitiveValue($("#snapshot-asn"), asn.value || "未形成共识", "asn");
    setSensitiveValue($("#snapshot-organization"), organization.value || "未形成共识", "organization");
    $("#snapshot-network-type").textContent = type.value || "未形成共识";
    $("#snapshot-status").textContent = state.running ? "实时检测中" : state.observations.exitIp ? "实时结果" : "未取得出口";
  }

  function setToneText(node, text, tone) {
    if (!node) return;
    node.textContent = text;
    node.classList.remove("good", "warn", "bad");
    if (tone && tone !== "neutral") node.classList.add(tone);
  }

  function updateGroupSummaries() {
    var groups = $$(".signal-group");
    var byTitle = function (title) {
      return groups.find(function (group) {
        return group.querySelector(".signal-group-title")?.textContent.trim() === title;
      });
    };
    var intel = summarizeSourceProgress(state.ipIntel);
    var routes = summarizeSourceProgress(state.routes);
    var country = evidenceApi.computeCountryConsensus(state.ipIntel);
    var asn = evidenceApi.computeAsnConsensus(state.ipIntel);
    var timezoneCountry = timezoneRegion(state.observations.timezone);
    var languageCountry = languageRegion(state.observations.languages[0]);
    var identityMismatch = Boolean(
      country.value &&
        ((timezoneCountry && timezoneCountry !== country.value) ||
          (languageCountry && languageCountry !== country.value)),
    );
    var webrtc = webrtcAssessment();
    var dnsAssessment = assessDnsEvidence(country.value);
    var dnsComparable = dnsAssessment.comparable;
    var dnsMismatch = dnsComparable.some(function (record) {
      return record.countryCode !== country.value;
    });
    var dnsCountryMissing = dnsAssessment.regionMissing;
    var dnsEvidenceIncomplete = Boolean(
      state.dns.records.length && dnsAssessment.incomplete,
    );
    var countryConflict = country.conflicts;
    var asnConflict = state.ipIntel.filter(function (record) {
      return sourceEligible(record) && asn.value && record.asn && record.asn !== asn.value;
    }).length;
    var typeFieldCount = state.ipIntel.filter(function (record) {
      return sourceEligible(record) && Boolean(record.networkType);
    }).length;
    var riskFlags = state.ipIntel.filter(function (record) {
      return record.voteEligible === true && (
        record.proxy === true || record.vpn === true || record.tor === true || record.hosting === true
      );
    });

    var exitGroup = byTitle("出口 IP");
    setToneText(
      exitGroup?.querySelector(".signal-group-result"),
      state.running ? "实时检测中" : state.observations.exitIp ? "出口已读取 · 可用 " + intel.usable + " / 10" : "未取得出口",
      state.running ? "neutral" : state.observations.exitIp ? (intel.usable >= 6 ? "good" : "warn") : "bad",
    );
    var identityGroup = byTitle("身份信号");
    setToneText(
      identityGroup?.querySelector(".signal-group-result"),
      !country.value || country.eligible < MIN_SCORE_EVIDENCE_PER_DOMAIN
        ? "地区证据不足"
        : identityMismatch
          ? "时区或语言不一致"
          : "未见明确不一致",
      !country.value || country.eligible < MIN_SCORE_EVIDENCE_PER_DOMAIN ? "neutral" : identityMismatch ? "warn" : "good",
    );
    var leakGroup = byTitle("网络泄漏");
    var leakNeedsReview = webrtc.conflicts.length || webrtc.alternateFamily.length || dnsMismatch || dnsEvidenceIncomplete || state.dns.error;
    var leakEvidenceMissing = !state.running && (!webrtc.successes.length || !state.dns.records.length || !dnsComparable.length);
    setToneText(
      leakGroup?.querySelector(".signal-group-result"),
      state.running
        ? "实时检测中"
        : leakNeedsReview
          ? dnsEvidenceIncomplete && !dnsMismatch
            ? dnsAssessment.addressMissing ? "DNS 地址证据不完整" : "DNS 地区证据不完整"
            : "发现需核对信号"
          : leakEvidenceMissing
            ? "泄漏证据不足"
            : "未发现明确泄漏",
      state.running ? "neutral" : leakNeedsReview || leakEvidenceMissing ? "warn" : "good",
    );
    var multiGroup = byTitle("多源互证");
    var sourceConflicts = countryConflict + asnConflict;
    var multiEvidenceReady = intel.usable >= MIN_SCORE_EVIDENCE_PER_DOMAIN && routes.usable >= MIN_SCORE_EVIDENCE_PER_DOMAIN;
    setToneText(
      multiGroup?.querySelector(".signal-group-result"),
      state.running
        ? "多源核对中"
        : sourceConflicts || riskFlags.length
          ? sourceConflicts + riskFlags.length + " 项需核对"
          : multiEvidenceReady
            ? "多源未见明确分歧"
            : "多源证据不足",
      state.running ? "neutral" : sourceConflicts || riskFlags.length ? "warn" : multiEvidenceReady ? "good" : "neutral",
    );

    var subsection = function (label) {
      return document.querySelector('.signal-subsection[aria-label="' + label + '"] .signal-subsection-status');
    };
    setToneText(subsection("位置一致性"), !country.value ? "等待" : identityMismatch ? "部分匹配" : "未见冲突", !country.value ? "neutral" : identityMismatch ? "warn" : "good");
    setToneText(subsection("网络类型"), "有效 " + typeFieldCount + " / 10", typeFieldCount >= 6 ? "good" : typeFieldCount ? "warn" : "neutral");
    setToneText(subsection("时区"), !country.value ? "等待" : timezoneCountry && timezoneCountry !== country.value ? "不一致" : "未见冲突", !country.value ? "neutral" : timezoneCountry && timezoneCountry !== country.value ? "warn" : "good");
    setToneText(subsection("语言"), !country.value ? "等待" : languageCountry && languageCountry !== country.value ? "不一致" : "未见冲突", !country.value ? "neutral" : languageCountry && languageCountry !== country.value ? "warn" : "good");
    setToneText(
      subsection("DNS"),
      state.dns.running
        ? "检测中"
        : state.dns.error
          ? "检测失败"
          : dnsMismatch
            ? "地区分歧"
            : dnsEvidenceIncomplete
              ? "地区字段不完整"
              : state.dns.records.length
                ? "已取得结果"
                : "无结果",
      state.dns.running
        ? "neutral"
        : state.dns.error || dnsMismatch || dnsEvidenceIncomplete
          ? "warn"
          : state.dns.records.length
            ? "good"
            : "neutral",
    );
    setToneText(subsection("WebRTC"), webrtc.label, webrtc.tone);
    setToneText(subsection("地理交叉"), country.value ? country.votes + " / 10 票" : "等待", country.value ? country.conflicts ? "warn" : "good" : "neutral");
    setToneText(subsection("网络标签"), "有效 " + typeFieldCount + " / 10", typeFieldCount >= 6 ? "good" : typeFieldCount ? "warn" : "neutral");
  }

  function browserLabel() {
    var ua = navigator.userAgent || "";
    var browser = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "浏览器";
    return browser + " · " + state.localSignals.platform;
  }

  function updateOverview() {
    var intelSummary = summarizeSourceProgress(state.ipIntel);
    var routeSummary = summarizeSourceProgress(state.routes);
    var stunSummary = summarizeSourceProgress(state.stun);
    var stunSuccess = stunSummary.usable;
    var evidenceCount = intelSummary.usable + routeSummary.usable + stunSuccess;
    var coverage = Math.round(((intelSummary.usable + routeSummary.usable + stunSuccess) / 30) * 100);
    var country = evidenceApi.computeCountryConsensus(state.ipIntel);
    var asn = evidenceApi.computeAsnConsensus(state.ipIntel);
    var organization = evidenceApi.computeOrganizationConsensus(state.ipIntel);
    var timezoneCountry = timezoneRegion(state.observations.timezone);
    var languageCountry = languageRegion(state.observations.languages[0]);
    var timezoneMismatch = Boolean(country.value && timezoneCountry && country.value !== timezoneCountry);
    var languageMismatch = Boolean(country.value && languageCountry && country.value !== languageCountry);
    var webrtc = webrtcAssessment();
    var dnsAssessment = assessDnsEvidence(country.value);
    var dnsComparable = dnsAssessment.comparable;
    var dnsCountryMissing = dnsAssessment.regionMissing;
    var dnsCountryConflicts = dnsAssessment.conflicts;
    var asnConflicts = state.ipIntel.filter(function (record) {
      return sourceEligible(record) && asn.value && record.asn && record.asn !== asn.value;
    }).length;
    var organizationConflicts = state.ipIntel.filter(function (record) {
      return sourceEligible(record) && organization.value && record.organization &&
        record.organization.toLowerCase() !== organization.value.toLowerCase();
    }).length;
    var sourceConflictCount = country.conflicts + asnConflicts + organizationConflicts;
    var riskFlags = state.ipIntel.filter(function (record) {
      return record.voteEligible === true && (
        record.proxy === true || record.vpn === true || record.tor === true || record.hosting === true
      );
    });
    var complete = Boolean(state.completedAt && !state.running);
    var scoreAvailable = Boolean(
      complete &&
      state.observations.exitIp &&
      coverage >= MIN_SCORE_COVERAGE &&
      evidenceCount >= Math.ceil((MIN_SCORE_COVERAGE / 100) * 30) &&
      intelSummary.usable >= MIN_SCORE_EVIDENCE_PER_DOMAIN &&
      routeSummary.usable >= MIN_SCORE_EVIDENCE_PER_DOMAIN &&
      stunSummary.usable >= MIN_SCORE_EVIDENCE_PER_DOMAIN &&
      country.eligible >= MIN_SCORE_EVIDENCE_PER_DOMAIN &&
      dnsComparable.length >= 1
    );
    var penalty =
      (timezoneMismatch ? 5 : 0) +
      (languageMismatch ? 5 : 0) +
      Math.min(20, webrtc.conflicts.length * 10) +
      (webrtc.alternateFamily.length ? 4 : 0) +
      Math.min(15, dnsCountryConflicts * 5) +
      Math.min(18, sourceConflictCount * 3) +
      Math.min(24, riskFlags.length * 6) +
      (dnsCountryMissing ? 3 : 0);
    var score = Math.max(0, Math.min(100, 50 + Math.round(coverage * 0.5) - penalty));
    var needsReview = Boolean(
      timezoneMismatch ||
      languageMismatch ||
      webrtc.conflicts.length ||
      webrtc.alternateFamily.length ||
      dnsCountryConflicts ||
      sourceConflictCount ||
      riskFlags.length
    );
    var scoreCaution = Boolean(
      needsReview ||
      dnsCountryMissing
    );
    var evidenceMissing = !scoreAvailable || !country.value || !webrtc.successes.length || !dnsComparable.length;
    var evidenceIncomplete = evidenceMissing || dnsCountryMissing > 0;
    var scoreNode = $(".score-number");
    scoreNode.textContent = state.running ? "…" : scoreAvailable ? String(score) : "—";
    var ring = $(".score-ring");
    var scoreColor = riskFlags.length || webrtc.conflicts.length ? "var(--red)" : scoreCaution ? "var(--amber)" : "var(--green)";
    ring.style.background = scoreAvailable
      ? "conic-gradient(" + scoreColor + " 0 " + score + "%, #dcebe1 " + score + "% 100%)"
      : "conic-gradient(var(--blue) 0 " + coverage + "%, #dcebe1 " + coverage + "% 100%)";
    ring.setAttribute(
      "aria-label",
      state.running
        ? "实时检测进行中"
        : scoreAvailable
          ? "网络信号参考分 " + score + " 分，满分 100 分"
          : "证据不足，未达到跨域门槛，未生成网络参考分",
    );
    $("#summary-browser").textContent = browserLabel();
    $("#summary-coverage").textContent = coverage + "%";
    var chips = [];
    chips.push({ tone: !country.value ? "neutral" : timezoneMismatch ? "warn" : "good", text: !country.value ? "时区等待地区证据" : timezoneMismatch ? "时区不一致" : "时区未见明确冲突" });
    chips.push({ tone: !country.value ? "neutral" : languageMismatch ? "warn" : "good", text: !country.value ? "语言等待地区证据" : languageMismatch ? "语言不一致" : "语言未见明确冲突" });
    chips.push({ tone: webrtc.tone, text: "WebRTC " + webrtc.label });
    chips.push({
      tone: !state.dns.records.length || !dnsComparable.length || dnsCountryMissing ? "warn" : dnsCountryConflicts ? "warn" : "good",
      text: !state.dns.records.length
        ? "DNS 证据不足"
        : !dnsComparable.length || dnsCountryMissing
          ? dnsAssessment.addressMissing ? "DNS 地址或地区字段不完整" : "DNS 地区字段不完整"
          : dnsCountryConflicts
            ? "DNS 地区不一致"
            : "DNS 地区一致",
    });
    var tagRow = $(".tag-row");
    tagRow.replaceChildren();
    chips.forEach(function (chip) {
      tagRow.append(makeTextElement("span", "chip " + chip.tone, chip.text));
    });
    var badge = $(".status-badge");
    badge.textContent = state.running
      ? "检测中"
      : !complete
        ? "等待检测"
        : needsReview
          ? "需要核对"
          : evidenceIncomplete
            ? "证据不足"
            : "状态稳定";
    badge.style.color = state.running || !complete ? "var(--blue)" : needsReview || evidenceIncomplete ? "var(--amber)" : "var(--green-deep)";
    badge.style.background = state.running || !complete ? "var(--blue-soft)" : needsReview || evidenceIncomplete ? "var(--amber-soft)" : "var(--green-soft)";
    $("#result-title").textContent = state.running
      ? "正在核对实时证据"
      : !complete
        ? "等待实时检测"
        : needsReview
          ? "发现需要核对的信号"
          : evidenceIncomplete
            ? "本轮证据不足，暂不下结论"
            : "本轮环境未见明确异常";
    $(".result-copy").textContent = state.running
      ? "正在逐家读取实时来源，当前有效覆盖 " + coverage + "%；进行中与未执行来源不会记作失败。"
      : !complete
        ? "检测尚未开始，页面不会用首帧占位生成结论。"
        : "本轮有效覆盖 " + coverage + "%；IP 情报、路由注册、STUN 与 DNS 必须跨域达到门槛才生成分数，失败、路径不同和字段缺失均不会补成成功。";
    $("#result-run-state").textContent = state.running ? "正在实时检测" : complete ? "本次检测完成" : "等待检测开始";
    if (state.completedAt) $("#run-time").textContent = formatRunTime(state.completedAt);
  }

  function updateRemixOverview() {
    [
      ["出口 IP", "#overview-network-state"],
      ["网络泄漏", "#overview-leaks-state"],
      ["身份信号", "#overview-browser-state"],
      ["多源互证", "#overview-sources-state"],
    ].forEach(function (entry) {
      var group = signalGroupByTitle(entry[0]);
      var result = group?.querySelector(".signal-group-result");
      var target = $(entry[1]);
      if (!result || !target) return;
      target.textContent = result.textContent;
      target.className = "overview-domain-state " + (result.classList.contains("bad")
        ? "bad"
        : result.classList.contains("warn")
          ? "warn"
          : result.classList.contains("good")
            ? "good"
            : "neutral");
    });
    var routeValue = $('.signal-row[data-row-id="route-registry-sources"] .signal-row-value');
    if ($("#overview-paths-state") && routeValue) {
      $("#overview-paths-state").textContent = routeValue.textContent;
      $("#overview-paths-state").className = "overview-domain-state " + toneFromNode(routeValue);
    }
    if (state.completedAt && state.autoDisclosureRunId !== state.runId) {
      $$(".signal-group").forEach(function (group) {
        if (group.dataset.userDisclosure === "true") return;
        var result = group.querySelector(".signal-group-result");
        group.open = !result || !result.classList.contains("good");
      });
      state.autoDisclosureRunId = state.runId;
    }
    updateCompactStatus();
  }

  function updateWebrtcPanel() {
    var assessment = webrtcAssessment();
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

  var CORE_RESULT_META = Object.freeze({
    "position-consistency": { group: "出口 IP", route: "#/network" },
    "asn-organization": { group: "出口 IP", route: "#/network" },
    "geo-cross-check": { group: "出口 IP", route: "#/network" },
    "exit-ip-quality": { group: "出口 IP", route: "#/network" },
    "network-type": { group: "出口 IP", route: "#/network" },
    "risk-proxy-labels": { group: "出口 IP", route: "#/network" },
    "system-timezone": { group: "身份信号", route: "#/browser" },
    "browser-language": { group: "身份信号", route: "#/browser" },
    "emoji-rendering": { group: "身份信号", route: "#/browser" },
    "chinese-fonts": { group: "身份信号", route: "#/browser" },
    "dns-leak": { group: "网络泄漏", route: "#/leaks" },
    "dns-region-consistency": { group: "网络泄漏", route: "#/leaks" },
    "webrtc-leak": { group: "网络泄漏", route: "#/leaks" },
    "stun-nodes": { group: "网络泄漏", route: "#/leaks" },
    "majority-region": { group: "多源互证", route: "#/network" },
    "conflict-check": { group: "多源互证", route: "#/network" },
    "network-label-consensus": { group: "多源互证", route: "#/network" },
    "ip-intel-sources": { group: "多源互证", route: "#/network" },
    "route-registry-sources": { group: "多源互证", route: "#/paths" },
  });

  function resultStateLabel(rawState) {
    return {
      success: "成功",
      warning: "需核对",
      failed: "失败",
      skipped: "未执行",
      "requires-server": "需服务器",
      loading: "检测中",
    }[rawState] || "等待";
  }

  function resultTone(rawState) {
    return rawState === "success" ? "good" : rawState === "failed" ? "bad" : rawState === "warning" ? "warn" : "neutral";
  }

  function renderOverviewResultIndex() {
    var rows = $$('[data-core-result-ref]');
    var complete = 0;
    rows.forEach(function (node) {
      var model = state.coreResults[node.dataset.coreResultRef] || {
        value: "未确认",
        result: "等待本轮检测",
        evidence: "检测尚未开始",
        rawState: "loading",
      };
      var meta = CORE_RESULT_META[node.dataset.coreResultRef] || {};
      var rawState = model.rawState || "loading";
      var value = node.querySelector("[data-result-value]");
      var status = node.querySelector("[data-result-state-label]");
      node.href = meta.route || node.getAttribute("href") || "#/overview";
      node.dataset.resultState = rawState;
      node.classList.remove("good", "warn", "bad", "neutral");
      node.classList.add(resultTone(rawState));
      if (value) setSensitiveValue(value, model.value || model.result, "network");
      if (status) {
        status.textContent = resultStateLabel(rawState);
        status.className = "result-index-state " + resultTone(rawState);
      }
      if (rawState === "success" || rawState === "warning" || rawState === "failed") complete += 1;
    });
    var statusNode = $("#overview-results-status");
    if (statusNode) statusNode.textContent = state.running ? "实时检测中 · " + complete + " / 19 已结算" : complete + " / 19 已结算";
  }

  function probeState(record) {
    if (!record) return "warning";
    if (record.state === "success") return "success";
    if (record.state === "partial" || record.state === "pending" || record.state === "loading") return "warning";
    if (record.state === "blocked" || record.state === "skipped") return "skipped";
    return "failed";
  }

  function probeModel(id, name, record, value, evidence, options) {
    var config = options || {};
    var rawState = config.rawState || probeState(record);
    return {
      id: id,
      name: name || record?.name || id,
      meta: config.meta || [record?.status, latencyLabel(record || {})].filter(Boolean).join(" · "),
      value: value || record?.observedIp || record?.detail || record?.status || "未取得",
      evidence: evidence || record?.detail || record?.status || "本轮未取得可核对证据",
      rawState: rawState,
      sensitive: config.sensitive || (record?.observedIp ? "ip" : null),
    };
  }

  function ipProbeModels() {
    return state.ipIntel.map(function (record, index) {
      return probeModel("ip-" + (record.id || index + 1), record.name, record,
        [record.observedIp, record.countryName || record.countryCode, record.asn, record.organization].filter(Boolean).join(" · ") || record.status,
        [intelFields(record), record.detail].filter(Boolean).join(" · "));
    });
  }

  function dnsProbeModels() {
    if (state.dns.records.length) {
      return state.dns.records.map(function (record, index) {
        return probeModel("dns-" + (record.id || index + 1), record.name || "解析器 " + (index + 1), record,
          [record.observedIp, record.countryName || record.countryCode, record.asn].filter(Boolean).join(" · ") || record.status,
          [record.countryName || record.countryCode || "地区未知", record.asn || "ASN 未提供"].join(" · "));
      });
    }
    return [probeModel("dns-bash-ws", "bash.ws DNS Leak Test", state.dns,
      state.dns.error || (state.dns.running ? "正在等待解析器回传" : "等待检测"),
      state.dns.error || "浏览器会直接请求 bash.ws；未返回解析器前不生成结论",
      { rawState: state.dns.error ? "failed" : state.dns.running ? "warning" : "warning", meta: "权威 DNS 探针" })];
  }

  function stunProbeModels() {
    return state.stun.map(function (record, index) {
      return probeModel("stun-" + (record.id || index + 1), record.name || "STUN 节点 " + (index + 1), record,
        record.observedIp || record.status,
        [latencyLabel(record), record.detail].filter(Boolean).join(" · "), { sensitive: record.observedIp ? "ip" : null });
    });
  }

  function boundaryModels(names, reason, prefix) {
    return names.map(function (name, index) {
      return {
        id: prefix + "-" + (index + 1), name: name, meta: "浏览器能力边界",
        value: "未执行", evidence: reason, rawState: "skipped", sensitive: null,
      };
    });
  }

  function splitProbeModels() {
    var models = state.ipIntel.map(function (record, index) {
      var model = probeModel("split-ip-" + (record.id || index + 1), record.name, record,
        record.observedIp || record.status,
        record.pathMismatch ? "与当前出口路径存在差异" : "使用现有 IP 情报来源作为分流基线");
      if (record.pathMismatch && model.rawState === "success") model.rawState = "warning";
      return model;
    });
    return models.concat(boundaryModels(["40 个分流目标", "回显端点"], "需用户主动确认并由服务器/第三方目标提供可比路径；单页本版未发起批量跨站请求。", "split"));
  }

  function multiProbeModels() {
    var models = [];
    state.ipIntel.forEach(function (record, index) { models.push(probeModel("multi-ip-" + (record.id || index + 1), record.name, record, record.observedIp || record.status, intelFields(record))); });
    state.routes.forEach(function (record, index) { models.push(probeModel("multi-route-" + (record.id || index + 1), record.name, record, [record.asn, record.organization, record.prefix].filter(Boolean).join(" · ") || record.status, record.detail || "路由与注册来源逐项结算")); });
    state.stun.forEach(function (record, index) { models.push(probeModel("multi-stun-" + (record.id || index + 1), record.name, record, record.observedIp || record.status, record.detail || latencyLabel(record))); });
    return models.concat([{ id: "multi-server", name: "全球远端节点调度", meta: "规划上限 1,648 节点", value: "未执行", evidence: "需要服务器调度、节点池和主动确认；纯静态单页不能声称已完成全球扫描。", rawState: "requires-server", sensitive: null }]);
  }

  function latencyProbeModels() {
    var models = [];
    if (state.publicIp.latencyMs !== undefined && state.publicIp.latencyMs !== null) {
      models.push(probeModel("latency-public-ip", "公网出口发现", state.publicIp, latencyLabel(state.publicIp), "发现公网出口时记录的单次请求耗时", { sensitive: null }));
    }
    state.ipIntel.forEach(function (record, index) { models.push(probeModel("latency-ip-" + (record.id || index + 1), record.name, record, latencyLabel(record), "IP 情报请求耗时；未执行来源不计入结论", { sensitive: null })); });
    state.routes.forEach(function (record, index) { models.push(probeModel("latency-route-" + (record.id || index + 1), record.name, record, latencyLabel(record), "路由与注册请求耗时；未执行来源不计入结论", { sensitive: null })); });
    state.stun.forEach(function (record, index) { models.push(probeModel("latency-stun-" + (record.id || index + 1), record.name, record, latencyLabel(record), "STUN 建连耗时；浏览器 WebRTC 测量", { sensitive: null })); });
    return models.concat([{ id: "latency-repeat-sampling", name: "重复采样与抖动", meta: "规划能力", value: "未执行", evidence: "本版仅展示已有 latencyMs；重复采样需要用户目标与后续请求确认。", rawState: "skipped", sensitive: null }]);
  }

  function renderProbeList(container, models) {
    if (!container) return;
    container.replaceChildren();
    var caption = document.createElement("div");
    caption.className = "tool-list-caption";
    caption.textContent = "本轮逐项明细 · " + models.length + " 项 · 成功、需核对、失败与未执行分开披露";
    container.append(caption);
    models.forEach(function (model, index) {
      var article = document.createElement("article");
      article.className = "tool-probe-card";
      article.dataset.probeId = model.id;
      article.dataset.probeState = model.rawState;
      var indexNode = document.createElement("span");
      indexNode.className = "tool-probe-index";
      indexNode.textContent = String(index + 1).padStart(2, "0");
      var nameNode = document.createElement("span");
      nameNode.className = "tool-probe-name";
      nameNode.dataset.probeName = "true";
      var strong = document.createElement("strong");
      strong.textContent = model.name;
      var small = document.createElement("small");
      small.textContent = model.meta || "本轮实时来源";
      nameNode.append(strong, small);
      var stateNode = document.createElement("span");
      stateNode.className = "tool-probe-state " + resultTone(model.rawState);
      stateNode.textContent = resultStateLabel(model.rawState);
      var evidenceNode = document.createElement("p");
      evidenceNode.className = "tool-probe-evidence";
      evidenceNode.dataset.probeEvidence = "true";
      evidenceNode.textContent = model.evidence || model.value || "未取得可核对证据";
      if (model.value && model.value !== model.evidence) {
        var valueNode = document.createElement("span");
        valueNode.className = "tool-probe-value";
        if (model.sensitive) setSensitiveValue(valueNode, model.value, model.sensitive);
        else valueNode.textContent = model.value;
        evidenceNode.prepend(valueNode, " · ");
      }
      article.append(indexNode, nameNode, stateNode, evidenceNode);
      container.append(article);
    });
  }

  function renderToolResultLists() {
    var builders = {
      ip: ipProbeModels,
      dns: dnsProbeModels,
      stun: stunProbeModels,
      cdn: function () { return boundaryModels(["Cloudflare Trace", "Fastly 响应头", "Akamai Edge", "Google CDN"], "普通页面无法跨域读取第三方响应头；本版未发起额外 CDN 请求。", "cdn"); },
      split: splitProbeModels,
      multi: multiProbeModels,
      latency: latencyProbeModels,
    };
    REMIX_TOOL_ROUTES.forEach(function (tool) {
      var container = document.querySelector('[data-tool-result-list="' + tool + '"]');
      if (container && builders[tool]) renderProbeList(container, builders[tool]());
    });
  }

  function render() {
    updateSnapshot();
    updateRowSummaries();
    updateGroupSummaries();
    updateOverview();
    updateWebrtcPanel();
    renderEvidenceLists();
    updateSensitiveValues();
    updateRemixOverview();
    renderOverviewResultIndex();
    renderToolResultLists();
  }

  function showToast(message) {
    var toast = $("#toast");
    toast.textContent = message;
    toast.classList.add("is-visible");
    clearTimeout(showToast.timer);
    showToast.timer = setTimeout(function () { toast.classList.remove("is-visible"); }, 2200);
  }

  function normalizeRemixRoute(hash) {
    var candidate = typeof hash === "string" ? hash : "";
    if (candidate === "#/tools") return candidate;
    if (candidate.indexOf("#/tools/") === 0 && REMIX_TOOL_ROUTES.includes(candidate.slice(8))) {
      return candidate;
    }
    if (candidate.indexOf("#/") === 0 && REMIX_RESULT_ROUTES.includes(candidate.slice(2))) {
      return candidate;
    }
    return REMIX_DEFAULT_ROUTE;
  }

  function routeViewName(route) {
    if (route === "#/tools") return "tools";
    if (route.indexOf("#/tools/") === 0) return "tool-" + route.slice(8);
    return route.slice(2);
  }

  function routeTitle(viewName) {
    return REMIX_ROUTE_LABELS[viewName] || REMIX_ROUTE_LABELS.overview;
  }

  function toneFromNode(node) {
    if (!node) return "neutral";
    if (node.classList.contains("bad")) return "bad";
    if (node.classList.contains("warn")) return "warn";
    if (node.classList.contains("good")) return "good";
    return "neutral";
  }

  function updateCompactEntry(domain, sourceNode, copy) {
    var stateNode = $("#" + domain + "-compact-state");
    var copyNode = $("#" + domain + "-compact-copy");
    if (!stateNode) return;
    stateNode.textContent = state.running
      ? "检测中"
      : state.completedAt
        ? sourceNode?.textContent.trim() || "证据不足"
        : "等待检测";
    stateNode.className = state.running || !state.completedAt ? "" : toneFromNode(sourceNode);
    if (copyNode && copy) copyNode.textContent = copy;
  }

  function updateCompactStatus() {
    var intelSummary = summarizeSourceProgress(state.ipIntel);
    var routeSummary = summarizeSourceProgress(state.routes);
    var webrtc = webrtcAssessment();
    var networkResult = signalGroupByTitle("出口 IP")?.querySelector(".signal-group-result");
    var leakResult = signalGroupByTitle("网络泄漏")?.querySelector(".signal-group-result");
    var browserResult = signalGroupByTitle("身份信号")?.querySelector(".signal-group-result");
    var routeValue = $('.signal-row[data-row-id="route-registry-sources"] .signal-row-value');
    updateCompactEntry(
      "network",
      networkResult,
      "IP 情报可用 " + intelSummary.usable + " / 10；路径不同、失败与缺失来源不参与共识。",
    );
    updateCompactEntry(
      "leaks",
      leakResult,
      "DNS " + state.dns.records.length + " 个解析器记录；STUN " + webrtc.successes.length + " / 10 响应。",
    );
    updateCompactEntry(
      "paths",
      routeValue,
      "路由与注册可用 " + routeSummary.usable + " / 10；" + sourceProgressLabel(routeSummary) + "。",
    );
    updateCompactEntry(
      "browser",
      browserResult,
      "时区、语言与本地浏览器摘要已读取；网络一致性仍服从实时地理证据。",
    );
  }

  function focusActiveRoute(view, options) {
    if (!options.focus) return;
    var heading = view.querySelector('h2[tabindex="-1"]');
    if (!heading) return;
    heading.dataset.focusOrigin = options.focusOrigin === "keyboard" ? "keyboard" : "programmatic";
    heading.focus({ preventScroll: true });
    var headerHeight = $(".demo-header")?.getBoundingClientRect().height || 0;
    var navHeight = $(".module-tabs")?.getBoundingClientRect().height || 0;
    var top = heading.getBoundingClientRect().top + window.scrollY - headerHeight - navHeight - 20;
    var root = document.documentElement;
    var previousScrollBehavior = root.style.scrollBehavior;
    root.style.scrollBehavior = "auto";
    window.scrollTo({ top: Math.max(0, top), behavior: "auto" });
    root.style.scrollBehavior = previousScrollBehavior;
  }

  function ensureCurrentRouteVisible(link) {
    if (!link) return;
    var scroller = link.closest(".module-tabs");
    if (!scroller || scroller.scrollWidth <= scroller.clientWidth + 1) return;
    var scrollerRect = scroller.getBoundingClientRect();
    var linkRect = link.getBoundingClientRect();
    if (linkRect.left < scrollerRect.left) {
      scroller.scrollLeft -= scrollerRect.left - linkRect.left;
    } else if (linkRect.right > scrollerRect.right) {
      scroller.scrollLeft += linkRect.right - scrollerRect.right;
    }
  }

  function renderRemixRoute(options) {
    var config = options || {};
    var route = normalizeRemixRoute(location.hash);
    if (route !== location.hash) history.replaceState(null, "", route);
    var viewName = routeViewName(route);
    var activeView = null;
    var currentRouteLink = null;
    $$('[data-remix-view]').forEach(function (view) {
      var isActive = view.dataset.remixView === viewName;
      view.hidden = !isActive;
      if (isActive) activeView = view;
    });
    $$(".module-tab[data-route]").forEach(function (link) {
      if (link.getAttribute("href") === route) {
        link.setAttribute("aria-current", "page");
        currentRouteLink = link;
      } else link.removeAttribute("aria-current");
    });
    $$('[data-tools-entry]').forEach(function (link) {
      if (viewName === "tools" || viewName.indexOf("tool-") === 0) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
    document.body.dataset.remixRoute = viewName;
    updateCompactStatus();
    var announcer = $("#route-announcer");
    if (announcer) announcer.textContent = "已切换到" + routeTitle(viewName);
    if (activeView) {
      requestAnimationFrame(function () {
        ensureCurrentRouteVisible(currentRouteLink);
        focusActiveRoute(activeView, config);
      });
    }
  }

  function moveToSlot(node, slotSelector) {
    var slot = $(slotSelector);
    if (node && slot) slot.append(node);
  }

  function signalGroupByTitle(title) {
    return $$(".signal-group").find(function (group) {
      return group.querySelector(".signal-group-title")?.textContent.trim() === title;
    });
  }

  function organizeRemixPanels() {
    var staging = $("#remix-staging");
    if (!staging || staging.dataset.organized === "true") return;
    staging.dataset.organized = "true";

    moveToSlot($("#result-summary-card"), "#overview-summary-slot");
    moveToSlot(signalGroupByTitle("出口 IP"), "#network-signal-stack");
    moveToSlot(signalGroupByTitle("身份信号"), "#browser-signal-stack");
    moveToSlot(signalGroupByTitle("网络泄漏"), "#leaks-signal-stack");
    moveToSlot(signalGroupByTitle("多源互证"), "#network-signal-stack");

    var routeRow = $('.signal-row[data-row-id="route-registry-sources"]');
    moveToSlot(routeRow, "#route-registry-slot");
    moveToSlot($("#webrtc-view"), "#leaks-detail-slot");
    moveToSlot($("#fingerprint-view"), "#browser-detail-slot");
    moveToSlot($("#overview-view > .privacy-callout"), "#network-privacy-slot");

    $("#overview-view")?.remove();
    staging.remove();
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
      var message = copied ? success : "复制失败，请手动选择内容";
      showToast(message);
      $("#floating-action-status").textContent = message;
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
    var intelSummary = summarizeSourceProgress(state.ipIntel);
    var routeSummary = summarizeSourceProgress(state.routes);
    var webrtc = webrtcAssessment();
    return [
      "AI Signal Guard · IPCX Remix v1.3.0",
      PROJECT_URL,
      "网络参考分：" + currentScoreText(),
      "出口 IP：" + (state.privacy ? maskSensitiveValue(state.observations.exitIp || "未取得", "ip") : state.observations.exitIp || "未取得"),
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
    var intelSummary = summarizeSourceProgress(state.ipIntel);
    var routeSummary = summarizeSourceProgress(state.routes);
    var webrtc = webrtcAssessment();
    var failedIntel = state.ipIntel.filter(function (record) {
      return record.attempted && !sourceUsable(record) && record.state !== "pending" && record.state !== "loading";
    }).map(function (record) { return record.name + "（" + record.status + "）"; });
    var failedRoutes = state.routes.filter(function (record) {
      return record.attempted && !sourceUsable(record) && record.state !== "pending" && record.state !== "loading";
    }).map(function (record) { return record.name + "（" + record.status + "）"; });
    var reportAddress = state.privacy
      ? maskSensitiveValue(state.observations.exitIp || "未取得", "ip")
      : state.observations.exitIp || "未取得";
    var reportAsn = state.privacy
      ? maskSensitiveValue(asn.value || "未形成", "asn")
      : asn.value || "未形成";
    var reportOrganization = state.privacy
      ? maskSensitiveValue(organization.value || "未形成", "organization")
      : organization.value || "未形成";
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
      "公网地址：" + reportAddress,
      "主流地区：" + (country.value || "未形成") + " · " + country.votes + " / 10 票（可投票 " + country.eligible + " 家）",
      "ASN：" + reportAsn + " · " + asn.votes + " / 10 票",
      "组织：" + reportOrganization + " · " + organization.votes + " / 10 票",
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
      var value = makeTextElement("span", "fingerprint-evidence-value", entry[1]);
      value.dataset.sensitive = "device";
      value.dataset.sensitiveValue = entry[1];
      renderSensitive(value);
      item.append(value);
      list.append(item);
    });
  }

  async function sha256(value) {
    if (!globalThis.crypto || !crypto.subtle || typeof TextEncoder === "undefined") return null;
    var buffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
    return Array.from(new Uint8Array(buffer)).map(function (byte) { return byte.toString(16).padStart(2, "0"); }).join("");
  }

  async function computeFingerprints(runId) {
    var localSignals = state.localSignals;
    var observedLanguages = state.observations.languages.slice();
    var observedTimezone = state.observations.timezone;
    var stableSource = JSON.stringify({
      platform: localSignals.platform,
      languages: observedLanguages,
      timezone: observedTimezone,
      colorDepth: localSignals.colorDepth,
    });
    var broadSource = JSON.stringify({
      stable: stableSource,
      userAgent: localSignals.userAgent,
      screen: localSignals.screen,
      hardwareConcurrency: localSignals.hardwareConcurrency,
      deviceMemory: localSignals.deviceMemory,
      fonts: localSignals.detectedFonts,
    });
    var stableValue;
    var broadValue;
    try {
      var values = await Promise.all([sha256(stableSource), sha256(broadSource)]);
      stableValue = values[0] || "当前上下文不可计算";
      broadValue = values[1] || "当前上下文不可计算";
    } catch (error) {
      stableValue = "计算失败";
      broadValue = "计算失败";
    }
    if (typeof runId === "number" && runId !== state.runId) return false;
    state.fingerprints.v3.value = stableValue;
    state.fingerprints.v2.value = broadValue;
    updateFingerprintView();
    updateSensitiveValues();
    return true;
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
    refreshLocalEnvironment();
    setRecheckControls(true);
    render();

    var fingerprintPromise = computeFingerprints(runId);

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
    await Promise.allSettled([stunPromise, dnsPromise, fingerprintPromise]);
    if (!isCurrentRun(runId, controller.signal)) return false;
    state.running = false;
    state.completedAt = new Date();
    state.runController = null;
    if (!config.deferControlsReset) setRecheckControls(false);
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
    button.setAttribute("aria-busy", String(running));
    button.setAttribute("aria-label", label);
    $("#floating-recheck-label").textContent = label;
  }

  function setRecheckBackgroundInert(inert) {
    [$(".skip-link"), $(".demo-header"), $("#main"), $(".floating-tool-dock")]
      .filter(Boolean)
      .forEach(function (node) { node.inert = inert; });
  }

  async function runRecheck() {
    if (state.running) return;
    state.runCount += 1;
    var overlay = $("#recheck-loading");
    var restoreFocus = document.activeElement;
    var reducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    document.body.dataset.recheckLoading = "true";
    setRecheckBackgroundInert(true);
    overlay.hidden = false;
    overlay.setAttribute("aria-busy", "true");
    renderLoadingStage(0);
    requestAnimationFrame(function () { overlay.classList.add("is-visible"); });
    overlay.focus({ preventScroll: true });
    window.scrollTo({ top: 0, behavior: reducedMotion ? "auto" : "smooth" });
    var minimumReveal = new Promise(function (resolve) { setTimeout(resolve, reducedMotion ? 100 : 1500); });
    var completed = false;
    try {
      completed = await runLiveDetection({
        deferControlsReset: true,
        onPhase: function (phase) { renderLoadingStage(phase); },
      });
      await minimumReveal;
      if (completed) {
        renderLoadingStage(2, 100);
        await new Promise(function (resolve) { setTimeout(resolve, reducedMotion ? 0 : 320); });
      }
    } finally {
      overlay.classList.remove("is-visible");
      await new Promise(function (resolve) { setTimeout(resolve, reducedMotion ? 0 : 240); });
      overlay.hidden = true;
      overlay.setAttribute("aria-busy", "false");
      document.body.removeAttribute("data-recheck-loading");
      setRecheckBackgroundInert(false);
      setRecheckControls(false);
      if (restoreFocus && restoreFocus.isConnected && typeof restoreFocus.focus === "function") {
        restoreFocus.focus({ preventScroll: true });
      }
    }
    if (completed) {
      $("#floating-action-status").textContent = "实时检测完成，第 " + state.runCount + " 次结果已更新。";
      showToast("检测完成，结果已揭晓 🤩");
    }
  }

  function requestRecheck() {
    if (state.running) return;
    $("#floating-action-status").textContent = "正在重新检测，旧结果将在完成后更新。";
    runRecheck();
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
  organizeRemixPanels();
  prepareSignalRows();
  $$(".signal-group > summary").forEach(function (summary) {
    summary.addEventListener("click", function () {
      var group = summary.closest(".signal-group");
      if (group) group.dataset.userDisclosure = "true";
    });
  });
  $$(".signal-row-chevron, .row-status-dot").forEach(function (node) { node.setAttribute("aria-hidden", "true"); });
  $("#privacy-toggle").addEventListener("click", function () {
    state.privacy = !state.privacy;
    updateSensitiveValues();
    var message = state.privacy
      ? "隐私遮罩已开启，网络地址、位置、ASN、组织与指纹原值已隐藏。"
      : "隐私遮罩已关闭，当前页面显示实时原值。";
    $("#floating-action-status").textContent = message;
    showToast(message);
  });
  $("#floating-ai-report")?.addEventListener("click", copyAiReport);
  $("#floating-copy").addEventListener("click", copySummary);
  $("#floating-recheck").addEventListener("click", requestRecheck);
  $("#floating-top")?.addEventListener("click", function (event) {
    event.preventDefault();
    window.scrollTo({ top: 0, behavior: "smooth" });
  });
  $(".skip-link")?.addEventListener("click", function (event) {
    event.preventDefault();
    var main = $("#main");
    main?.focus({ preventScroll: true });
    main?.scrollIntoView({ block: "start" });
  });
  $$('[data-copy-fingerprint]').forEach(function (button) {
    button.addEventListener("click", function () {
      copyText(displayedFingerprint(button.dataset.copyFingerprint), "指纹摘要已复制");
    });
  });
  document.addEventListener("click", function (event) {
    var routeLink = event.target.closest('a[href^="#/"]');
    if (routeLink) pendingRouteFocusOrigin = event.detail === 0 ? "keyboard" : "programmatic";
    if (routeLink && routeLink.hash === location.hash) {
      event.preventDefault();
      renderRemixRoute({ focus: true, focusOrigin: pendingRouteFocusOrigin });
      pendingRouteFocusOrigin = "programmatic";
    }
    $$(".info-tip[open]").forEach(function (tip) {
      if (!tip.contains(event.target)) tip.removeAttribute("open");
    });
  });
  window.addEventListener("scroll", function () {
    scheduleBackToTopUpdate();
    updateFloatingDockReadingState();
    $$(".info-tip[open]").forEach(positionInfoTip);
  }, { passive: true });
  window.addEventListener("resize", function () {
    scheduleBackToTopUpdate();
    resetFloatingDockReadingState();
    ensureCurrentRouteVisible($('.module-tab[data-route][aria-current="page"]'));
    $$(".info-tip[open]").forEach(positionInfoTip);
  });
  window.addEventListener("hashchange", function () {
    renderRemixRoute({ focus: true, focusOrigin: pendingRouteFocusOrigin });
    pendingRouteFocusOrigin = "programmatic";
  });
  $$(".info-tip").forEach(setupInfoTip);
  updateBackToTopVisibility();
  renderRemixRoute({ focus: true, focusOrigin: "programmatic" });
  loadStars();
  render();
  runLiveDetection();
})();
