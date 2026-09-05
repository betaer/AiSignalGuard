(function bootstrapSignalGuardV200() {
  "use strict";

  var evidenceApi = globalThis.AISGIpEvidence;
  var core = globalThis.AISGV2Core;
  var semanticsApi = globalThis.AISGIpSemantics;
  var starPolicyApi = globalThis.AISGStarPromptPolicy;
  if (!evidenceApi) {
    throw new Error("AI Signal Guard 实时证据模块加载失败");
  }
  if (!semanticsApi) {
    throw new Error("AI Signal Guard 状态语义模块加载失败");
  }

  var PROJECT_URL = "https://betaer.github.io/AiSignalGuard/";
  PROJECT_URL = document.querySelector('link[rel="canonical"]')?.href || PROJECT_URL;
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
    { id: "chinese-fonts", title: "字体接口", evidenceSet: "fontSignals", evidenceTitle: "字体接口" },
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
  var languages = ["未知"];

  var AUDIO_FINGERPRINT_RUNS = 3;
  var AUDIO_FINGERPRINT_TIMEOUT_MS = 4500;
  var AUDIO_FINGERPRINT_SAMPLE_RATE = 44100;
  var AUDIO_FINGERPRINT_FRAME_COUNT = 6000;
  var AUDIO_FINGERPRINT_SAMPLE_OFFSET = 4500;
  var pendingAudioFingerprintRenders = 0;

  function pendingPublicFamily(status) {
    return { state: "pending", status: status || "等待检测", ip: null, addresses: [], sources: [], probes: [] };
  }

  function pendingFamilyRecords(registry) {
    return {
      ipv4: evidenceApi.createPendingRecords(registry),
      ipv6: evidenceApi.createPendingRecords(registry),
    };
  }

  function pendingLocalSignals() {
    return {
      platform: "等待检测",
      userAgent: "等待检测",
      screen: "等待检测",
      hardwareConcurrency: null,
      deviceMemory: null,
      colorDepth: null,
      canvasAvailable: null,
      webglAvailable: null,
      fontApiAvailable: null,
    };
  }

  var state = {
    privacy: false,
    running: false,
    runCount: 0,
    runId: 0,
    runController: null,
    pendingDetection: null,
    completedAt: null,
    detectionError: null,
    localReady: false,
    aiServices: core.AI_SERVICES.map(function (service) { return Object.assign({}, service, { state: "pending", status: "等待检测", attempted: false }); }),
    publicIps: {
      state: "pending",
      status: "等待检测",
      ipv4: pendingPublicFamily(),
      ipv6: pendingPublicFamily(),
      probes: [],
    },
    observations: {
      exitIps: { ipv4: [], ipv6: [] },
      timezone: timezone,
      languages: languages,
      countryCode: null,
      countryName: null,
      city: null,
      asn: null,
      organization: null,
      networkType: null,
    },
    ipIntelByFamily: pendingFamilyRecords(evidenceApi.IP_INTEL_SOURCES),
    routesByFamily: pendingFamilyRecords(evidenceApi.ROUTE_SOURCES),
    webrtc: evidenceApi.createPendingRecords(evidenceApi.WEBRTC_LEAK_NODES),
    stun: evidenceApi.createPendingRecords(evidenceApi.STUN_NODES),
    dns: { state: "pending", running: false, records: [], error: null },
    fingerprints: {
      v3: {
        label: "LOCAL STABLE HASH",
        value: "等待检测",
        description: "本页未加载 FingerprintJS v3+ SDK；这里显示由当前浏览器本地稳定信号生成的摘要，并与官方 Visitor ID 区分展示。",
      },
      v2: {
        label: "LOCAL BROAD HASH",
        value: "等待检测",
        description: "本页未加载 FingerprintJS2；这里使用更宽的本地浏览器信号生成一次性摘要，并明确与官方算法区分。",
      },
      tls: {
        label: "JA3 / JA4",
        value: "浏览器端不可读取",
        description: "普通网页脚本无法直接读取 TLS ClientHello，因此不生成或伪造 JA3 / JA4 值。",
      },
    },
    audioFingerprint: {
      state: "idle",
      result: "等待开始检测",
      detail: "用户确认后将在本地离线运行",
      tone: "neutral",
      runs: [],
      durationMs: null,
    },
    localSignals: pendingLocalSignals(),
  };

  function familyKeys() { return ["ipv4", "ipv6"]; }
  function familyLabel(family) { return family === "ipv6" ? "IPv6" : "IPv4"; }
  function publicFamily(family) { return state.publicIps[family] || pendingPublicFamily("未取得"); }
  function exitAddresses(family) { return (state.observations.exitIps[family] || []).slice(); }
  function primaryExitIp(family) { return exitAddresses(family)[0] || null; }
  function activeFamilies() { return familyKeys().filter(function (family) { return Boolean(primaryExitIp(family)); }); }
  function primaryFamily() { return activeFamilies()[0] || "ipv4"; }
  function publicFamilyDisplay(family) {
    var addresses = exitAddresses(family);
    if (addresses.length) return addresses.join(" / ");
    var result = publicFamily(family);
    return result.state === "loading" || result.state === "pending" ? result.status : "未取得";
  }
  function familyRecords(recordMap, family) { return (recordMap[family] || []).slice(); }
  function combinedFamilyRecords(recordMap, onlyActive) {
    return familyKeys().flatMap(function (family) {
      if (onlyActive && !primaryExitIp(family)) return [];
      return familyRecords(recordMap, family).map(function (record) {
        return Object.assign({}, record, {
          family: family,
          name: familyLabel(family) + " · " + record.name,
        });
      });
    });
  }
  function familyAnalysis(family) {
    var intel = familyRecords(state.ipIntelByFamily, family);
    var routes = familyRecords(state.routesByFamily, family);
    return {
      family: family,
      label: familyLabel(family),
      active: Boolean(primaryExitIp(family)),
      addresses: exitAddresses(family),
      ip: primaryExitIp(family),
      intel: intel,
      routes: routes,
      intelSummary: evidenceApi.summarizeSources(intel),
      routeSummary: evidenceApi.summarizeSources(routes),
      country: evidenceApi.computeCountryConsensus(intel),
      asn: evidenceApi.computeAsnConsensus(intel),
      organization: evidenceApi.computeOrganizationConsensus(intel),
      networkType: simpleConsensus(intel, "networkType"),
      city: simpleConsensus(intel, "city"),
    };
  }
  function activeAnalyses() { return activeFamilies().map(familyAnalysis); }
  function combinedSummary(recordMap) {
    return evidenceApi.summarizeSources(combinedFamilyRecords(recordMap, true));
  }
  function expectedFamilySources() { return Math.max(1, activeFamilies().length) * 10; }
  function familyConsensusText(field, fallback) {
    var analyses = activeAnalyses();
    if (!analyses.length) return fallback || "等待来源";
    var values = analyses.map(function (analysis) { return analysis[field] && analysis[field].value; });
    if (values.length === 2 && values[0] && values[0] === values[1]) return values[0];
    return analyses.map(function (analysis, index) {
      return analysis.label + " " + (values[index] || "未形成");
    }).join(" · ");
  }

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
    var webglAvailable = false;
    try {
      var webglCanvas = document.createElement("canvas");
      webglAvailable = Boolean(webglCanvas.getContext("webgl2") || webglCanvas.getContext("webgl"));
    } catch (error) {}
    var fontApiAvailable = Boolean(document.fonts && typeof document.fonts.check === "function");
    return {
      platform: platform,
      userAgent: navigator.userAgent || "未知",
      screen: screenValue,
      hardwareConcurrency: navigator.hardwareConcurrency || null,
      deviceMemory: navigator.deviceMemory || null,
      colorDepth: typeof screen !== "undefined" ? screen.colorDepth : null,
      canvasAvailable: canvasAvailable,
      webglAvailable: webglAvailable,
      fontApiAvailable: fontApiAvailable,
    };
  }

  function refreshLocalEnvironmentSignals() {
    timezone = "未知";
    try {
      timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || "未知";
    } catch (error) {}
    languages = Array.isArray(navigator.languages) && navigator.languages.length
      ? navigator.languages.slice()
      : [navigator.language || "未知"];
    state.observations.timezone = timezone;
    state.observations.languages = languages.slice();
    state.localSignals = collectLocalSignals();
    state.localReady = true;
  }

  function invariant(condition, message) {
    if (!condition) throw new Error("[AI Signal Guard] " + message);
  }

  function validatePageContract() {
    invariant(evidenceApi.IP_INTEL_SOURCES.length === 10, "IP 情报来源必须是 10 家");
    invariant(evidenceApi.ROUTE_SOURCES.length === 10, "路由与注册来源必须是 10 路");
    invariant(evidenceApi.WEBRTC_LEAK_NODES.length === 10, "WebRTC 泄漏节点必须是 10 个");
    invariant(evidenceApi.STUN_NODES.length === 10, "STUN 节点必须是 10 个");
    var v2Nodes = evidenceApi.WEBRTC_LEAK_NODES.concat(evidenceApi.STUN_NODES);
    invariant(new Set(v2Nodes.map(function (node) { return node.id; })).size === 20, "20 个节点 ID 必须唯一");
    invariant(new Set(v2Nodes.map(function (node) { return node.url.toLowerCase(); })).size === 20, "20 个节点 URL 必须唯一");
    invariant(new Set(v2Nodes.map(function (node) { return node.platform.toLowerCase(); })).size === 20, "20 个节点平台必须唯一");
    var fingerprintSections = $$(".fingerprint-primary-section");
    invariant(fingerprintSections.length === 3, "浏览器指纹检测必须有 3 个一级栏目");
    invariant(fingerprintSections.every(function (section) { return !section.open; }), "浏览器指纹一级栏目必须默认收起");
    invariant(Boolean($("#audio-fingerprint-run")), "WebAudio 音频指纹必须保留手动重测按钮");
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
    return record.voteEligible === true && (record.state === "success" || record.state === "partial");
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
      usable: Boolean(record.voteEligible) && (config.usable === undefined || Boolean(config.usable)),
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
    var analyses = activeAnalyses();
    var primary = familyAnalysis(primaryFamily());
    var country = primary.country;
    var asn = primary.asn;
    var organization = primary.organization;
    var intel = combinedFamilyRecords(state.ipIntelByFamily, true);
    var route = combinedFamilyRecords(state.routesByFamily, true);
    var webrtcLeak = state.webrtc;
    var stun = state.stun;
    var position = familyKeys().map(function (family) {
      var analysis = familyAnalysis(family);
      var publicResult = publicFamily(family);
      return {
        name: familyLabel(family) + " 公网出口位置",
        meta: analysis.active ? ["该地址族 10 家 IP 情报的主流结果", analysis.country.value, analysis.city.value].filter(Boolean).join(" · ") : "该地址族本轮未取得 HTTP 出口",
        value: publicFamilyDisplay(family),
        status: analysis.country.value ? "已读取" : publicResult.status,
        tone: analysis.country.value ? "good" : publicResult.state === "loading" || publicResult.state === "pending" ? "neutral" : "warn",
        sensitive: analysis.active ? "ip" : null,
        rawState: publicResult.state,
        attempted: publicResult.state !== "pending",
        usable: Boolean(analysis.country.value),
      };
    }).concat([
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
    ]);

    var asnRows = intel.map(function (record) {
      return toEvidenceItem(
        record,
        (record.asn || "未提供 ASN") + " · " + (record.organization || "未提供组织"),
        { usable: Boolean(record.asn || record.organization) },
      );
    });
    var geoRows = intel.map(function (record) {
      var recordCountry = familyAnalysis(record.family).country;
      var vote = record.voteEligible && record.countryCode && record.countryCode === recordCountry.value;
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
      var analysis = familyAnalysis(record.family);
      var conflict = conflictState(record, analysis.country.value, analysis.asn.value, analysis.organization.value);
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
        { meta: "ASN / 前缀 / 注册组织", usable: Boolean(record.voteEligible), sensitive: "ip" },
      );
    });
    var stunRows = stun.map(function (record) {
      var node = evidenceApi.STUN_NODES.find(function (source) { return source.id === record.id; });
      return toEvidenceItem(
        record,
        core.candidateIps(record).join(" / ") || record.detail || "未返回公网候选",
        { meta: (node ? node.url : "STUN") + " · " + latencyLabel(record), sensitive: core.candidateIps(record).length ? "ip" : null, usable: core.candidateIps(record).length > 0 },
      );
    });
    var webrtcRows = webrtcLeak.map(function (record) {
      var node = evidenceApi.WEBRTC_LEAK_NODES.find(function (source) { return source.id === record.id; });
      return toEvidenceItem(
        record,
        core.candidateIps(record).join(" / ") || record.detail || "未返回公网候选",
        { meta: (node ? node.url : "WebRTC") + " · " + latencyLabel(record), sensitive: core.candidateIps(record).length ? "ip" : null, usable: core.candidateIps(record).length > 0 },
      );
    });
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
    var fontRows = [{
      name: "FontFaceSet API",
      meta: "document.fonts 能力",
      value: state.localSignals.fontApiAvailable
        ? "字体加载状态接口可用；不推断本机字体安装"
        : "字体加载状态接口不可用",
      status: state.localSignals.fontApiAvailable ? "可用" : "不可用",
      tone: state.localSignals.fontApiAvailable ? "neutral" : "warn",
      rawState: state.localSignals.fontApiAvailable ? "partial" : "error",
      attempted: true,
      usable: state.localSignals.fontApiAvailable,
    }];
    var languageRows = browserLanguageEvidence();
    if (!state.localReady) {
      position.slice(-2).concat(emojiRows, fontRows, languageRows).forEach(function (item) {
        Object.assign(item, { value: "等待检测", status: "等待检测", tone: "neutral", rawState: "pending", attempted: false, usable: false });
      });
    }

    return {
      aiServices: state.aiServices.map(function (record) {
        var usable = ["path_available", "reachable"].includes(record.state);
        return { name: record.name, meta: record.url, value: [record.observedIp, record.countryCode, record.detail].filter(Boolean).join(" · ") || "等待检测", status: record.status, rawState: record.state, attempted: Boolean(record.attempted), usable: usable, sensitive: record.observedIp ? "ip" : null, tone: usable ? "good" : record.state === "pending" || record.state === "loading" ? "neutral" : "warn" };
      }),
      positionConsistency: position,
      asnOrganization: asnRows,
      geoVotes: geoRows,
      exitQualitySources: coverageRows,
      networkTypeSources: typeRows,
      riskSourceRecords: riskRows,
      languageSignals: languageRows,
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

  var hoverTooltipState = { layer: null, trigger: null, previousDescription: null };

  function hoverTooltipTriggerFrom(target) {
    if (!target || target.nodeType !== 1) return null;
    return target.closest(".row-help-tip > summary, .info-tip > summary");
  }

  function hoverTooltipCopy(trigger) {
    var source = trigger ? trigger.nextElementSibling : null;
    return source && source.matches(".row-help-bubble, .info-tip-bubble") ? source.textContent.trim() : "";
  }

  function positionHoverTooltip() {
    var layer = hoverTooltipState.layer;
    var trigger = hoverTooltipState.trigger;
    if (!layer || !trigger || !trigger.isConnected) return;
    layer.classList.remove("is-visible");
    layer.classList.add("is-measuring");
    var triggerRect = trigger.getBoundingClientRect();
    var layerRect = layer.getBoundingClientRect();
    var viewportPadding = 12;
    var viewportWidth = window.visualViewport ? window.visualViewport.width : document.documentElement.clientWidth;
    var viewportHeight = window.visualViewport ? window.visualViewport.height : document.documentElement.clientHeight;
    var left = triggerRect.left + (triggerRect.width - layerRect.width) / 2;
    left = Math.min(Math.max(viewportPadding, left), viewportWidth - layerRect.width - viewportPadding);
    var top = triggerRect.top - layerRect.height - 9;
    var placement = "top";
    if (top < viewportPadding) {
      top = triggerRect.bottom + 9;
      placement = "bottom";
    }
    top = Math.min(Math.max(viewportPadding, top), viewportHeight - layerRect.height - viewportPadding);
    layer.style.left = Math.round(left) + "px";
    layer.style.top = Math.round(top) + "px";
    layer.dataset.placement = placement;
    layer.classList.remove("is-measuring");
    layer.classList.add("is-visible");
  }

  function restoreHoverTooltipDescription() {
    var trigger = hoverTooltipState.trigger;
    if (!trigger) return;
    if (hoverTooltipState.previousDescription) trigger.setAttribute("aria-describedby", hoverTooltipState.previousDescription);
    else trigger.removeAttribute("aria-describedby");
  }

  function showHoverTooltip(trigger) {
    var copy = hoverTooltipCopy(trigger);
    if (!copy) return;
    var layer = hoverTooltipState.layer;
    if (!layer) return;
    if (hoverTooltipState.trigger !== trigger) {
      restoreHoverTooltipDescription();
      hoverTooltipState.trigger = trigger;
      hoverTooltipState.previousDescription = trigger.getAttribute("aria-describedby");
      var descriptions = [hoverTooltipState.previousDescription, layer.id].filter(Boolean);
      trigger.setAttribute("aria-describedby", descriptions.join(" "));
    }
    layer.textContent = copy;
    layer.setAttribute("aria-hidden", "false");
    positionHoverTooltip();
  }

  function hideHoverTooltip() {
    var layer = hoverTooltipState.layer;
    if (!layer) return;
    restoreHoverTooltipDescription();
    hoverTooltipState.trigger = null;
    hoverTooltipState.previousDescription = null;
    layer.classList.remove("is-visible", "is-measuring");
    layer.setAttribute("aria-hidden", "true");
  }

  function setupHoverTooltipPortal() {
    if (hoverTooltipState.layer) return;
    var layer = makeTextElement("div", "hover-tooltip-layer", "");
    layer.id = "hover-tooltip-layer";
    layer.setAttribute("role", "tooltip");
    layer.setAttribute("aria-hidden", "true");
    document.body.append(layer);
    hoverTooltipState.layer = layer;
    document.addEventListener("mouseover", function (event) {
      var trigger = hoverTooltipTriggerFrom(event.target);
      if (!trigger) return;
      if (event.relatedTarget && trigger.contains(event.relatedTarget)) return;
      showHoverTooltip(trigger);
    });
    document.addEventListener("mouseout", function (event) {
      var trigger = hoverTooltipTriggerFrom(event.target);
      if (!trigger || trigger !== hoverTooltipState.trigger) return;
      if (event.relatedTarget && trigger.contains(event.relatedTarget)) return;
      if (document.activeElement === trigger) return;
      hideHoverTooltip();
    });
    document.addEventListener("focusin", function (event) {
      var trigger = hoverTooltipTriggerFrom(event.target);
      if (trigger) showHoverTooltip(trigger);
    });
    document.addEventListener("focusout", function (event) {
      var trigger = hoverTooltipTriggerFrom(event.target);
      if (!trigger || trigger !== hoverTooltipState.trigger) return;
      requestAnimationFrame(function () {
        if (!trigger.matches(":hover") && document.activeElement !== trigger) hideHoverTooltip();
      });
    });
  }

  function setupHoverOnlyDetails(tip, readyKey) {
    if (tip.dataset[readyKey] === "true") return;
    tip.dataset[readyKey] = "true";
    var summary = tip.querySelector("summary");
    if (summary) {
      var pointerActivation = false;
      summary.addEventListener("pointerdown", function (event) {
        if (event.pointerType !== "mouse" && event.pointerType !== "pen") return;
        pointerActivation = true;
        event.preventDefault();
        tip.open = false;
        summary.blur();
      });
      summary.addEventListener("click", function (event) {
        if (!pointerActivation) return;
        pointerActivation = false;
        event.preventDefault();
        tip.open = false;
        summary.blur();
      });
      summary.addEventListener("pointercancel", function () {
        pointerActivation = false;
      });
    }
  }

  function setupRowHelpTip(tip) {
    setupHoverOnlyDetails(tip, "rowHelpReady");
  }

  function setupInfoTip(tip) {
    setupHoverOnlyDetails(tip, "infoTipReady");
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
    return core.maskSensitiveText(value);
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
      if (!raw) raw = "未取得";
      node.textContent = state.privacy ? maskIpValue(raw) : raw;
      if (node.dataset.sensitiveAriaLabel) node.setAttribute("aria-label", state.privacy ? maskIpValue(node.dataset.sensitiveAriaLabel) : node.dataset.sensitiveAriaLabel);
    });
    $$('#audio-fingerprint-runs code').forEach(function (node, index) {
      var run = state.audioFingerprint.runs[index];
      if (run) node.textContent = core.maskDigest(run.digest, state.privacy);
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

  function timezoneMismatchFor(country) {
    var countries = core.timezoneCountries(state.observations.timezone);
    return Boolean(country && countries.length && !countries.includes(country));
  }

  function languageRegion(language) {
    return core.languageRegion(language);
  }

  function assessWebrtcRecords(records) {
    return core.assessWebrtc(records, state.observations.exitIps);
  }

  function webrtcAssessment() {
    return assessWebrtcRecords(state.webrtc.concat(state.stun));
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
      if (value.matches('[data-sensitive="ip"]')) value.dataset.sensitiveValue = config.value;
      value.dataset.statusLabel = config.status || toneLabel(tone);
      value.setAttribute("aria-label", (config.status || toneLabel(tone)) + "：" + config.value);
      if (value.matches('[data-sensitive="ip"]')) value.dataset.sensitiveAriaLabel = value.getAttribute("aria-label");
    }
    row.dataset.tone = tone;
    row.dataset.statusLabel = config.status || toneLabel(tone);
    var result = row.querySelector('[data-detail-kind="result"] strong');
    var evidence = row.querySelector('[data-help-kind="evidence"] .row-help-bubble');
    var advice = row.querySelector('[data-help-kind="advice"] .row-help-bubble');
    if (result && config.result) result.textContent = config.result;
    if (evidence && config.evidence) evidence.textContent = config.evidence;
    if (advice && config.advice) advice.textContent = config.advice;
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

  function browserLabel() {
    var ua = state.localSignals.userAgent || "";
    var browser = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "浏览器";
    return browser + " · " + state.localSignals.platform;
  }

  function dualNetworkContext() {
    var analyses = activeAnalyses();
    var primary = analyses[0] || familyAnalysis("ipv4");
    var intel = combinedFamilyRecords(state.ipIntelByFamily, true);
    var routes = combinedFamilyRecords(state.routesByFamily, true);
    var intelSummary = evidenceApi.summarizeSources(intel);
    var routeSummary = evidenceApi.summarizeSources(routes);
    var expected = analyses.length * 10;
    var countryValues = analyses.map(function (item) { return item.country.value; }).filter(Boolean);
    var asnValues = analyses.map(function (item) { return item.asn.value; }).filter(Boolean);
    var crossCountryMismatch = countryValues.length > 1 && new Set(countryValues).size > 1;
    var crossAsnMismatch = asnValues.length > 1 && new Set(asnValues).size > 1;
    return {
      analyses: analyses,
      primary: primary,
      intel: intel,
      routes: routes,
      intelSummary: intelSummary,
      routeSummary: routeSummary,
      expected: expected,
      countryText: familyConsensusText("country", "等待来源"),
      asnText: familyConsensusText("asn", "未形成共识"),
      organizationText: familyConsensusText("organization", "未形成共识"),
      networkTypeText: familyConsensusText("networkType", "未形成共识"),
      cityText: familyConsensusText("city", ""),
      crossCountryMismatch: crossCountryMismatch,
      crossAsnMismatch: crossAsnMismatch,
    };
  }

  function familyVoteLine(analysis, field) {
    var consensus = analysis[field];
    return analysis.label + " " + (consensus.value || "未形成") + " · " + consensus.votes + " / 10 票";
  }

  function updateDualStackRowSummaries() {
    var context = dualNetworkContext();
    var primary = context.primary;
    var country = primary.country;
    var countryLabel = context.countryText;
    var expected = context.expected;
    var languageCountry = languageRegion(state.observations.languages[0]);
    var timezoneMismatch = timezoneMismatchFor(country.value);
    var languageMismatch = Boolean(country.value && languageCountry && country.value !== languageCountry);
    var asnFieldCount = context.intel.filter(function (record) { return sourceUsable(record) && Boolean(record.asn || record.organization); }).length;
    var typeFieldCount = context.intel.filter(function (record) { return sourceUsable(record) && Boolean(record.networkType); }).length;
    var riskFieldCount = context.intel.filter(function (record) {
      return sourceUsable(record) && [record.proxy, record.vpn, record.tor, record.hosting].some(function (value) { return value !== null; });
    }).length;
    var riskFlags = context.intel.filter(function (record) {
      return sourceUsable(record) && (record.proxy === true || record.vpn === true || record.tor === true || record.hosting === true);
    });
    var explicitConflicts = 0;
    context.analyses.forEach(function (analysis) {
      analysis.intel.forEach(function (record) {
        if (conflictState(record, analysis.country.value, analysis.asn.value, analysis.organization.value).tone === "bad") explicitConflicts += 1;
      });
    });
    var dnsRecords = state.dns.records;
    var dnsCountryMatches = country.value ? dnsRecords.filter(function (record) { return record.countryCode === country.value; }).length : 0;
    var dnsTone = state.dns.error ? "bad" : !dnsRecords.length ? "warn" : dnsCountryMatches === dnsRecords.length ? "good" : "warn";
    var primaryWebrtc = assessWebrtcRecords(state.webrtc);
    var supplementalStun = assessWebrtcRecords(state.stun);
    var addressDisplay = activeFamilies().map(function (family) { return publicFamilyDisplay(family); }).join(" / ") || "未取得公网出口";
    var countryLines = context.analyses.map(function (analysis) { return familyVoteLine(analysis, "country"); }).join("；") || "尚无可用国家票";
    var asnLines = context.analyses.map(function (analysis) { return familyVoteLine(analysis, "asn"); }).join("；") || "尚无 ASN 共识";

    setRow("position-consistency", {
      value: !country.value ? "等待地理来源" : timezoneMismatch || languageMismatch || context.crossCountryMismatch ? "存在差异" : "未见明确差异",
      tone: !country.value ? "neutral" : timezoneMismatch || languageMismatch || context.crossCountryMismatch ? "warn" : "good",
      result: context.crossCountryMismatch ? "IPv4 与 IPv6 的国家共识不同" : country.value ? "浏览器本地信号已与出口主流地区核对" : "尚无足够地理证据",
      evidence: "地址族结果：" + countryLines + "；系统时区 " + state.observations.timezone + "；浏览器语言 " + state.observations.languages.join(" · ") + "。",
      advice: "双栈分别形成共识；只有真实返回字段的差异才计为冲突。",
    });
    setRow("asn-organization", {
      value: context.asnText,
      tone: context.crossAsnMismatch ? "warn" : asnFieldCount ? "good" : "neutral",
      result: context.crossAsnMismatch ? "IPv4 与 IPv6 的 ASN 共识不同" : asnLines,
      evidence: "每个可用地址族各由 10 家来源独立投票，本轮有效 ASN / 组织字段 " + asnFieldCount + " / " + expected + "。",
      advice: "IPv4 与 IPv6 可能由不同 ASN 宣告；先核对是否符合运营商或代理的真实双栈架构。",
    });
    setRow("geo-cross-check", {
      value: context.countryText,
      tone: context.crossCountryMismatch ? "warn" : country.value ? "good" : "neutral",
      result: countryLines,
      evidence: "每个可用地址族分别列出 10 家来源，不把两族票数混成一个多数结果。",
      advice: "城市轻微差异常来自数据库；跨地址族国家差异需要优先核对。",
    });
    setRow("exit-ip-quality", {
      value: addressDisplay,
      tone: activeFamilies().length ? familyKeys().some(function (family) { return exitAddresses(family).length > 1; }) ? "warn" : "good" : state.running ? "neutral" : "bad",
      result: activeFamilies().length === 2 ? "IPv4 与 IPv6 公网出口均已读取" : activeFamilies().length ? "仅取得 " + familyLabel(activeFamilies()[0]) + " 公网出口" : "未取得公网出口",
      evidence: "已对每个可用地址族启动 10 家 IP 情报；本轮可用 " + context.intelSummary.usable + " / " + expected + "。同族多个回显地址会全部保留。",
      advice: "没有 IPv6 不等于异常；可能是当前网络、VPN 或系统未提供可用 IPv6 路径。",
    });
    setRow("network-type", {
      value: context.networkTypeText,
      tone: typeFieldCount ? "good" : "neutral",
      result: typeFieldCount ? "各地址族网络类型已分别统计" : "没有足够类型字段",
      evidence: "本轮 " + typeFieldCount + " / " + expected + " 家提供网络类型字段，未用组织名称猜测补填。",
      advice: "双栈可能出现不同标签，应结合 ASN、组织和实际线路理解。",
    });
    setRow("risk-proxy-labels", {
      value: riskFlags.length ? riskFlags.length + " 家标记风险" : riskFieldCount ? "未收到明确风险标记" : "证据不足",
      tone: riskFlags.length ? "bad" : riskFieldCount ? "good" : "neutral",
      result: riskFlags.length ? "存在明确 Proxy / VPN / Tor / Hosting 标记" : riskFieldCount ? "已返回风险字段的来源未给出明确标记" : "没有可判定字段",
      evidence: "仅统计明确返回 true 的字段；有效风险字段 " + riskFieldCount + " / " + expected + "。",
      advice: "公开接口的风险标签仅作参考，需按地址族查看具体来源。",
    });
    setRow("system-timezone", { value: state.observations.timezone, tone: timezoneMismatch ? "warn" : "good", result: timezoneMismatch ? "与主要出口国家不一致" : "未发现明确时区冲突", evidence: "主要地址族国家为 " + (country.value || "未形成") + "；双栈地区为 " + countryLabel + "。", advice: "按真实使用地区核对；无法映射的时区不强行判定。" });
    setRow("browser-language", { value: state.observations.languages.join(" · "), tone: languageMismatch ? "warn" : "good", result: languageMismatch ? "首选语言地区与主要出口不同" : "未发现明确语言冲突", evidence: "浏览器实际语言与 " + countryLabel + " 进行辅助比较。", advice: "语言是弱信号，应符合日常使用习惯。" });
    setRow("emoji-rendering", { value: state.localSignals.canvasAvailable ? "Canvas 2D 可用" : "Canvas 2D 不可用", tone: state.localSignals.canvasAvailable ? "good" : "warn", result: "浏览器本地渲染能力已读取", evidence: "只报告 Canvas 2D 上下文能力，不伪造像素结论。", advice: "渲染能力是弱信号。" });
    setRow("chinese-fonts", { value: state.localSignals.fontApiAvailable ? "API 可用" : "API 不可用", tone: state.localSignals.fontApiAvailable ? "neutral" : "warn", result: "只确认字体加载接口能力", evidence: "不扫描字体宽度，也不推断本机安装字体。", advice: "字体枚举具有较高区分度，本页不执行枚举。" });
    setRow("dns-leak", { value: state.dns.error ? "检测失败" : state.dns.running ? "检测中…" : dnsRecords.length + " 个解析器", tone: dnsTone, result: state.dns.error ? "本轮未取得权威 DNS 结果" : dnsRecords.length ? "已取得真实解析器记录" : "等待解析器回传", evidence: state.dns.error || (dnsRecords.length + " 个解析器来自本轮权威探针。"), advice: "检测失败不等于没有泄漏。" });
    setRow("dns-region-consistency", { value: dnsRecords.length && country.value ? dnsCountryMatches + " / " + dnsRecords.length + " 与主要出口同国" : "证据不足", tone: dnsTone, result: dnsRecords.length ? "按解析器地区与主要出口比较" : "尚无解析器地区", evidence: "主要出口国家 " + (country.value || "未形成") + "；同国解析器 " + dnsCountryMatches + " 个。", advice: "地区未知不计一致或冲突。" });
    setRow("webrtc-leak", { value: primaryWebrtc.successes.length + " / 10 响应", tone: primaryWebrtc.tone, result: primaryWebrtc.label, evidence: "主池同地址族分歧 " + primaryWebrtc.conflicts.length + " 个，缺少同族 HTTP 基准的候选 " + primaryWebrtc.unverified.length + " 个。", advice: "只在相同地址族内比较；待核对地址族不直接判为泄漏。" });
    setRow("stun-nodes", { value: supplementalStun.successes.length + " / 10 响应", tone: supplementalStun.tone, result: supplementalStun.label, evidence: "补充池 10 个独立节点；成功、超时和错误各自保留。", advice: "响应少可能来自 UDP、代理规则或浏览器策略。" });
    setRow("majority-region", { value: context.countryText, tone: context.crossCountryMismatch ? "warn" : country.value ? "good" : "neutral", result: countryLines, evidence: "每族 10 家独立投票；失败和缺失不计票。", advice: "不要把 IPv4 与 IPv6 的票数直接合并。" });
    setRow("conflict-check", { value: explicitConflicts + " 家明确冲突", tone: explicitConflicts ? "bad" : context.intelSummary.usable ? "good" : "neutral", result: explicitConflicts ? "逐地址族发现明确字段分歧" : "可核对字段未见明确冲突", evidence: "另外，跨地址族国家差异 " + (context.crossCountryMismatch ? "1" : "0") + " 项、ASN 差异 " + (context.crossAsnMismatch ? "1" : "0") + " 项。", advice: "字段缺失不算冲突；跨族差异需结合真实网络架构判断。" });
    setRow("network-label-consensus", { value: context.networkTypeText, tone: typeFieldCount ? "good" : "neutral", result: "网络类型字段有效 " + typeFieldCount + " / " + expected, evidence: "逐地址族显示网络类型、组织、风险与失败状态。", advice: "单一标签不足以判断线路性质。" });
    setRow("ip-intel-sources", { value: "可用 " + context.intelSummary.usable + " / " + expected, tone: context.intelSummary.usable >= Math.max(1, Math.ceil(expected * 0.6)) ? "good" : context.intelSummary.usable ? "warn" : "neutral", result: "完整 " + context.intelSummary.complete + "、部分 " + context.intelSummary.partial + "、失败 " + context.intelSummary.failed, evidence: "每个实际取得的地址族各请求 10 家服务；本轮实际请求 " + context.intelSummary.attempted + " / " + expected + "。", advice: "自适应调度只降低并发峰值，不减少应检来源。" });
    setRow("route-registry-sources", { value: "可用 " + context.routeSummary.usable + " / " + expected, tone: context.routeSummary.usable >= Math.max(1, Math.ceil(expected * 0.6)) ? "good" : context.routeSummary.usable ? "warn" : "neutral", result: "完整 " + context.routeSummary.complete + "、部分 " + context.routeSummary.partial + "、失败 " + context.routeSummary.failed, evidence: "每个可用地址族分别使用自身 ASN 运行 10 路注册与路由来源；实际请求 " + context.routeSummary.attempted + " / " + expected + "。", advice: "ASN 依赖来源在对应地址族共识形成后再启动。" });
    var networkSourceStatus = $("#network-source-status");
    if (networkSourceStatus) networkSourceStatus.textContent = "可用 " + context.intelSummary.usable + " / " + expected;
    if (!state.localReady) {
      ["system-timezone", "browser-language", "emoji-rendering", "chinese-fonts"].forEach(function (id) { setRow(id, { value: "等待检测", tone: "neutral", result: "尚未读取本地信号" }); });
    } else if (!country.value || !core.timezoneCountries(state.observations.timezone).length) {
      setRow("system-timezone", { value: state.observations.timezone, tone: "neutral", result: "时区或出口地区证据不足，未作一致性判断" });
    }
  }

  function updateDualStackSnapshot() {
    var context = dualNetworkContext();
    var primary = context.primary;
    state.observations.countryCode = primary.country.value;
    state.observations.countryName = countryName(primary.country.value);
    state.observations.city = primary.city.value;
    state.observations.asn = primary.asn.value;
    state.observations.organization = primary.organization.value;
    state.observations.networkType = primary.networkType.value;
    familyKeys().forEach(function (family) {
      var value = publicFamilyDisplay(family);
      setSensitiveValue($("#summary-exit-" + family), value);
      setSensitiveValue($("#snapshot-exit-" + family), value);
    });
    $("#summary-location").textContent = context.analyses.length ? context.analyses.map(function (analysis) {
      return analysis.label + " " + ([countryName(analysis.country.value), analysis.city.value].filter(Boolean).join(" · ") || "等待来源");
    }).join("；") : "等待来源";
    $("#snapshot-location").textContent = context.countryText;
    $("#snapshot-asn").textContent = context.asnText;
    $("#snapshot-organization").textContent = context.organizationText;
    $("#snapshot-network-type").textContent = context.networkTypeText;
    $("#snapshot-status").textContent = state.running ? "实时检测中" : activeFamilies().length === 2 ? "双栈实时结果" : activeFamilies().length ? "单栈实时结果" : "未取得出口";
  }

  function updateDualStackGroupSummaries() {
    var context = dualNetworkContext();
    var groups = $$(".signal-group");
    function byTitle(title) { return groups.find(function (group) { return group.querySelector(".signal-group-title")?.textContent.trim() === title; }); }
    var primaryCountry = context.primary.country.value;
    var languageCountry = languageRegion(state.observations.languages[0]);
    var timezoneMismatch = timezoneMismatchFor(primaryCountry);
    var identityMismatch = timezoneMismatch || Boolean(primaryCountry && languageCountry && languageCountry !== primaryCountry) || context.crossCountryMismatch;
    var webrtc = webrtcAssessment();
    var dnsMismatch = Boolean(state.dns.records.length && primaryCountry && state.dns.records.some(function (record) { return record.countryCode && record.countryCode !== primaryCountry; }));
    var exitText = activeFamilies().length === 2 ? "双栈出口已读取" : activeFamilies().length ? familyLabel(activeFamilies()[0]) + " 出口已读取" : "未取得出口";
    setToneText(byTitle("出口 IP")?.querySelector(".signal-group-result"), state.running ? "实时检测中" : exitText + " · 可用 " + context.intelSummary.usable + " / " + context.expected, state.running ? "neutral" : activeFamilies().length ? "good" : "bad");
    setToneText(byTitle("环境信号")?.querySelector(".signal-group-result"), !primaryCountry ? "等待地区共识" : identityMismatch ? "存在地区差异" : "未见明确不一致", !primaryCountry ? "neutral" : identityMismatch ? "warn" : "good");
    var leakNeedsReview = webrtc.conflicts.length || webrtc.unverified.length || webrtc.httpDisagreements.length || webrtc.incomplete.length || webrtc.missingFamilies.length || dnsMismatch || state.dns.error;
    var leakMissing = !state.running && (!webrtc.successes.length || !state.dns.records.length);
    setToneText(byTitle("网络泄漏")?.querySelector(".signal-group-result"), state.running ? "实时检测中" : leakNeedsReview ? "发现需核对信号" : leakMissing ? "泄漏证据不足" : "未发现明确泄漏", state.running ? "neutral" : leakNeedsReview || leakMissing ? "warn" : "good");
    setToneText(byTitle("多源互证")?.querySelector(".signal-group-result"), state.running ? "多源核对中" : context.crossCountryMismatch || context.crossAsnMismatch ? "IPv4 / IPv6 结果存在差异" : context.intelSummary.usable || context.routeSummary.usable ? "各地址族已独立核对" : "证据不足", state.running ? "neutral" : context.crossCountryMismatch || context.crossAsnMismatch ? "warn" : context.intelSummary.usable || context.routeSummary.usable ? "good" : "neutral");
    function subsection(label) { return document.querySelector('.signal-subsection[aria-label="' + label + '"] .signal-subsection-status'); }
    var typeCount = context.intel.filter(function (record) { return sourceUsable(record) && record.networkType; }).length;
    setToneText(subsection("位置一致性"), !primaryCountry ? "等待" : identityMismatch ? "部分匹配" : "未见冲突", !primaryCountry ? "neutral" : identityMismatch ? "warn" : "good");
    setToneText(subsection("网络类型"), "有效 " + typeCount + " / " + context.expected, typeCount ? "good" : "neutral");
    setToneText(subsection("时区"), !primaryCountry || !core.timezoneCountries(state.observations.timezone).length ? "证据不足" : timezoneMismatch ? "不一致" : "未见冲突", !primaryCountry || !core.timezoneCountries(state.observations.timezone).length ? "neutral" : timezoneMismatch ? "warn" : "good");
    setToneText(subsection("语言"), !primaryCountry ? "等待" : languageCountry && languageCountry !== primaryCountry ? "不一致" : "未见冲突", !primaryCountry ? "neutral" : languageCountry && languageCountry !== primaryCountry ? "warn" : "good");
    setToneText(subsection("DNS"), state.dns.running ? "检测中" : state.dns.error ? "检测失败" : dnsMismatch ? "地区分歧" : state.dns.records.length ? "已取得结果" : "无结果", state.dns.running ? "neutral" : state.dns.error || dnsMismatch ? "warn" : state.dns.records.length ? "good" : "neutral");
    setToneText(subsection("WebRTC"), webrtc.label, webrtc.tone);
    setToneText(subsection("地理交叉"), context.countryText, context.crossCountryMismatch ? "warn" : primaryCountry ? "good" : "neutral");
    setToneText(subsection("网络标签"), "有效 " + typeCount + " / " + context.expected, typeCount ? "good" : "neutral");
  }

  function networkAssessment() {
    var context = dualNetworkContext();
    var primaryCountry = context.primary.country.value;
    var languageCountry = languageRegion(state.observations.languages[0]);
    return core.assessOverview({
      families: context.analyses, webrtc: webrtcAssessment(), dns: state.dns, aiServices: state.aiServices,
      timezoneMismatch: timezoneMismatchFor(primaryCountry),
      languageMismatch: Boolean(primaryCountry && languageCountry && primaryCountry !== languageCountry),
      crossCountryMismatch: context.crossCountryMismatch, crossAsnMismatch: context.crossAsnMismatch,
      fieldConflicts: context.analyses.some(function (analysis) { return [analysis.country, analysis.asn, analysis.organization].some(function (vote) { return vote.conflicts > 0; }); }),
    });
  }

  function updateDualStackOverview() {
    var context = dualNetworkContext();
    var webrtc = webrtcAssessment();
    var assessment = networkAssessment();
    var coverage = assessment.coverage;
    var score = assessment.score;
    var finished = Boolean(state.completedAt);
    $(".score-number").textContent = state.running ? "…" : finished && score !== null ? String(score) : "—";
    var ring = $(".score-ring");
    var tone = assessment.needsReview || assessment.evidenceMissing ? "var(--amber)" : "var(--green)";
    ring.style.background = !state.running && finished && score !== null ? "conic-gradient(" + tone + " 0 " + score + "%, #dcebe1 " + score + "% 100%)" : "conic-gradient(var(--blue) 0 " + coverage + "%, #dcebe1 " + coverage + "% 100%)";
    ring.setAttribute("aria-label", state.running ? "实时检测进行中" : finished && score !== null ? "网络信号参考分 " + score + " 分，满分 100 分" : "证据不足，未生成网络参考分");
    $("#summary-browser").textContent = state.localReady ? browserLabel() : "等待检测";
    $("#summary-coverage").textContent = coverage + "%";
    var chips = [
      { tone: activeFamilies().length === 2 ? "good" : "neutral", text: activeFamilies().length === 2 ? "双栈出口已取得" : activeFamilies().length ? "仅取得 " + familyLabel(activeFamilies()[0]) : "未取得 HTTP 出口" },
      { tone: webrtc.tone, text: "WebRTC " + webrtc.label },
      { tone: state.dns.running ? "neutral" : assessment.dnsMismatch || assessment.dnsMissing ? "warn" : "good", text: state.dns.running ? "DNS 检测中" : assessment.dnsMismatch ? "DNS 地区不同" : assessment.dnsMissing ? "DNS 证据不足" : "DNS 已核对" },
    ];
    var tagRow = $(".tag-row");
    tagRow.replaceChildren();
    chips.forEach(function (chip) { tagRow.append(makeTextElement("span", "chip " + chip.tone, chip.text)); });
    var badge = $(".status-badge");
    var needsReview = assessment.needsReview || Boolean(state.detectionError);
    var incomplete = assessment.evidenceMissing;
    badge.textContent = state.running ? "检测中" : !finished ? "等待检测" : needsReview ? "需要核对" : incomplete ? "证据不足" : "状态稳定";
    badge.style.color = state.running || !finished ? "var(--blue)" : needsReview || incomplete ? "var(--amber)" : "var(--green-deep)";
    badge.style.background = state.running || !finished ? "var(--blue-soft)" : needsReview || incomplete ? "var(--amber-soft)" : "var(--green-soft)";
    var explanation = assessment.reasons.join("；");
    $(".result-copy").textContent = state.running ? "正在分阶段读取实时来源，当前证据覆盖率 " + coverage + "%。" : !finished ? "确认开始后，将核对网络出口、泄漏、浏览器环境与 AI 服务路径。" : state.detectionError || explanation || (incomplete ? "部分关键证据缺失或服务响应不可核对，请展开明细查看。本轮不会把检测失败解释为安全。" : "本轮可观察信号未发现明确冲突；网络参考分不代表平台账号状态。");
    $("#result-run-state").textContent = state.running ? "正在实时检测" : finished ? state.detectionError ? "检测未完整结束" : "本次检测完成" : "尚未开始检测";
    if (state.completedAt) $("#run-time").textContent = formatRunTime(state.completedAt);
    var aiCompleted = state.aiServices.filter(function (record) { return !["pending", "loading"].includes(record.state); }).length;
    setToneText($("#ai-service-summary"), !state.runId ? "等待检测" : aiCompleted < core.AI_SERVICES.length ? aiCompleted + " / 3 已完成" : assessment.aiMissing ? "部分响应不可核对" : "3 项已核对", !state.runId || aiCompleted < 3 ? "neutral" : assessment.aiMissing || needsReview ? "warn" : "good");
  }

  function updateDualStackWebrtcPanel() {
    var assessment = webrtcAssessment();
    var panelTone = state.running ? "neutral" : !assessment.successes.length ? "warn" : assessment.tone;
    var panelLabel = state.running ? "检测中" : !assessment.successes.length ? "证据不足" : assessment.tone === "good" ? "正常" : assessment.tone === "bad" ? "发现分歧" : "需核对";
    setToneText($("#webrtc-panel-status"), panelLabel, panelTone);
    familyKeys().forEach(function (family) {
      var httpAddresses = exitAddresses(family);
      var candidates = Array.from(new Set(assessment.byFamily[family].map(function (record) { return record.observedIp; })));
      setSensitiveValue($("#webrtc-http-" + family), publicFamilyDisplay(family));
      setSensitiveValue($("#webrtc-public-" + family), candidates.length ? candidates.join(" / ") : "未取得");
      var httpStatus = $("#webrtc-http-" + family + "-status");
      var publicStatus = $("#webrtc-public-" + family + "-status");
      var familyConflicts = assessment.conflicts.filter(function (record) { return (record.observedIp.indexOf(":") >= 0 ? "ipv6" : "ipv4") === family; });
      var familyUnverified = assessment.unverified.filter(function (record) { return (record.observedIp.indexOf(":") >= 0 ? "ipv6" : "ipv4") === family; });
      setToneText(httpStatus, httpAddresses.length > 1 ? "多出口" : httpAddresses.length ? "已确认" : publicFamily(family).status, httpAddresses.length > 1 ? "warn" : httpAddresses.length ? "good" : "warn");
      setToneText(publicStatus, familyConflicts.length ? "地址分歧" : familyUnverified.length ? "缺少 HTTP 基准" : candidates.length ? "已核对" : "无结果", familyConflicts.length ? "bad" : familyUnverified.length ? "warn" : candidates.length ? "good" : "warn");
    });
    $("#webrtc-node-consensus").textContent = assessment.successes.length + " / 20 响应 · IPv4 " + assessment.byFamily.ipv4.length + " 项 · IPv6 " + assessment.byFamily.ipv6.length + " 项";
    $("#webrtc-panel-note").textContent = "本轮 20 个不重复节点按地址族分别核对；同地址族分歧 " + assessment.conflicts.length + " 个，缺少同族 HTTP 基准 " + assessment.unverified.length + " 个，同族 HTTP 多出口 " + assessment.httpDisagreements.length + " 组。";
    setToneText($("#webrtc-node-status"), assessment.successes.length ? "实时" : "无结果", assessment.successes.length ? assessment.tone : "warn");
  }

  var renderScheduled = false;
  function requestRender() {
    if (renderScheduled) return;
    renderScheduled = true;
    requestAnimationFrame(function () {
      renderScheduled = false;
      render();
    });
  }

  function render() {
    updateDualStackSnapshot();
    updateDualStackRowSummaries();
    updateDualStackGroupSummaries();
    updateDualStackOverview();
    updateDualStackWebrtcPanel();
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

  function audioFingerprintReportText() {
    var audio = state.audioFingerprint;
    if (audio.state === "idle") return "准备自动检测";
    if (audio.state === "running") return "检测中";
    return audio.result + "；" + audio.detail;
  }

  function reportFamilyIp(family) {
    var addresses = exitAddresses(family);
    if (!addresses.length) return "未取得";
    return addresses.map(function (ip) { return state.privacy ? maskIpValue(ip) : ip; }).join(" / ");
  }

  function reportConsensusLines(context, field) {
    if (!context.analyses.length) return ["未形成"];
    return context.analyses.map(function (analysis) {
      var consensus = analysis[field];
      return analysis.label + "：" + (consensus.value || "未形成") + " · " + consensus.votes + " / 10 票（可投票 " + consensus.eligible + " 家）";
    });
  }

  function aiServiceReportText() {
    var text = state.aiServices.map(function (record) {
      return record.name + "：" + record.status + "；" + [record.observedIp, record.countryCode, record.detail].filter(Boolean).join(" · ");
    }).join("\n");
    return state.privacy ? maskIpValue(text) : text;
  }

  function dnsReportText() {
    if (state.dns.error) return state.dns.error;
    if (state.dns.state !== "success" || !state.dns.records.length) return "未取得可核对解析器";
    var text = state.dns.records.map(function (record) { return [record.observedIp, record.countryCode || "地区未知"].join(" · "); }).join("；");
    return state.privacy ? maskIpValue(text) : text;
  }

  function summaryText() {
    var context = dualNetworkContext();
    var webrtc = webrtcAssessment();
    return [
      "AI Signal Guard · 通用数字环境检测",
      PROJECT_URL,
      "网络参考分：" + currentScoreText(),
      "需核对信号：" + (networkAssessment().reasons.join("；") || (networkAssessment().evidenceMissing ? "部分关键证据不足" : "未见明确冲突")),
      "出口 IPv4：" + reportFamilyIp("ipv4"),
      "出口 IPv6：" + reportFamilyIp("ipv6"),
      "主流地区：" + reportConsensusLines(context, "country").join("；"),
      "IP 情报：可用 " + context.intelSummary.usable + " / " + context.expected,
      "路由注册：可用 " + context.routeSummary.usable + " / " + context.expected,
      "WebRTC / STUN：响应 " + webrtc.successes.length + " / 20",
      "WebRTC 同地址族分歧：" + webrtc.conflicts.length + "；缺少 HTTP 同族基准：" + webrtc.unverified.length,
      "DNS：" + dnsReportText(),
      "AI 服务：\n" + aiServiceReportText(),
      "WebAudio 音频指纹：" + audioFingerprintReportText(),
      "系统时区：" + state.observations.timezone,
      "浏览器语言：" + state.observations.languages.join(" · "),
      "结果在当前浏览器内整理；第三方来源可能看到本轮目标 IP。",
    ].join("\n");
  }

  function aiDiagnosticReportText() {
    var context = dualNetworkContext();
    var webrtc = webrtcAssessment();
    var failedIntel = context.intel.filter(function (record) { return !sourceUsable(record); }).map(function (record) { return record.name + "（" + record.status + "）"; });
    var failedRoutes = context.routes.filter(function (record) { return !sourceUsable(record); }).map(function (record) { return record.name + "（" + record.status + "）"; });
    return [
      "请作为网络环境与浏览器一致性诊断助手，分析以下 AI Signal Guard 检测结果。不要仅复述数据，请指出最值得核对的信号、可能原因和建议顺序。",
      "",
      "AI Signal Guard",
      PROJECT_URL,
      "",
      "【检测概览】",
      "环境画像：通用数字环境检测",
      "网络参考分：" + currentScoreText(),
      "隐私显示：" + (state.privacy ? "已隐藏敏感原值" : "显示原值"),
      "需核对信号：" + (networkAssessment().reasons.join("；") || (networkAssessment().evidenceMissing ? "部分关键证据不足" : "未见明确冲突")),
      "代理 / 机房标签来源：" + (networkAssessment().riskRecords.map(function (record) { return record.name; }).join("、") || "未收到明确标记或证据不足"),
      "",
      "【网络出口】",
      "IPv4 公网地址：" + reportFamilyIp("ipv4"),
      "IPv6 公网地址：" + reportFamilyIp("ipv6"),
      "地区共识：" + reportConsensusLines(context, "country").join("；"),
      "ASN 共识：" + reportConsensusLines(context, "asn").join("；"),
      "组织共识：" + reportConsensusLines(context, "organization").join("；"),
      "跨地址族国家差异：" + (context.crossCountryMismatch ? "有" : "未见明确差异"),
      "跨地址族 ASN 差异：" + (context.crossAsnMismatch ? "有" : "未见明确差异"),
      "",
      "【环境一致性】",
      "系统时区：" + state.observations.timezone,
      "浏览器语言：" + state.observations.languages.join(" · "),
      "",
      "【泄漏与多源互证】",
      "DNS：" + dnsReportText(),
      "WebRTC：" + webrtc.label + "；" + webrtc.successes.length + " / 20 节点响应；同地址族分歧 " + webrtc.conflicts.length + "；待核对地址族 " + webrtc.unverified.length,
      "IP 情报：可用 " + context.intelSummary.usable + " / " + context.expected + "，完整 " + context.intelSummary.complete + "，部分字段 " + context.intelSummary.partial + "，失败 " + context.intelSummary.failed,
      "路由注册：可用 " + context.routeSummary.usable + " / " + context.expected + "，完整 " + context.routeSummary.complete + "，部分字段 " + context.routeSummary.partial + "，失败 " + context.routeSummary.failed,
      "IP 情报失败明细：" + (failedIntel.join("、") || "无"),
      "路由注册失败明细：" + (failedRoutes.join("、") || "无"),
      "",
      "【浏览器本地信号】",
      "本地稳定摘要：" + displayedFingerprint("v3"),
      "本地宽域摘要：" + displayedFingerprint("v2"),
      "WebAudio 音频指纹：" + audioFingerprintReportText(),
      "JA3 / JA4：" + displayedFingerprint("tls"),
      "",
      "【AI 服务路径】",
      aiServiceReportText(),
      "资源可达不等于对话或登录功能可用；无法读取的响应不判断为成功。",
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

  function setMiniStatusNode(node, text, tone) {
    if (!node) return;
    node.textContent = text;
    node.classList.remove("neutral", "good", "warn", "bad");
    node.classList.add(tone || "neutral");
  }

  function updateAudioFingerprintView() {
    var audio = state.audioFingerprint;
    var OfflineAudio = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    var button = $("#audio-fingerprint-run");
    var running = audio.state === "running";
    var waitingForRelease = pendingAudioFingerprintRenders > 0 && !running;
    var completedRuns = audio.runs.length;
    var apiText = OfflineAudio ? "OfflineAudioContext 可用" : "OfflineAudioContext 不可用";
    var consistencyText = "等待检测";
    if (running) consistencyText = completedRuns + " / " + AUDIO_FINGERPRINT_RUNS + " 轮完成";
    if (audio.state === "stable") consistencyText = AUDIO_FINGERPRINT_RUNS + " / " + AUDIO_FINGERPRINT_RUNS + " 输出一致";
    if (audio.state === "disturbed") consistencyText = audio.uniqueResults + " / " + AUDIO_FINGERPRINT_RUNS + " 种会话内结果";
    if (audio.state === "restricted") consistencyText = "未取得可比较输出";
    if (audio.state === "uncertain") consistencyText = "检测未完整结束";

    $("#audio-fingerprint-api").textContent = apiText;
    $("#audio-fingerprint-consistency").textContent = consistencyText;
    $("#audio-fingerprint-result").textContent = audio.detail;
    $("#audio-fingerprint-summary").textContent = audio.result;

    if (button) {
      button.disabled = running || waitingForRelease;
      button.setAttribute("aria-busy", String(running || waitingForRelease));
      button.textContent = running
        ? "正在离线检测 " + completedRuns + " / " + AUDIO_FINGERPRINT_RUNS
        : waitingForRelease
          ? "等待离线渲染释放"
          : (audio.state === "idle" ? "开始音频指纹检测" : "重新运行音频指纹检测");
    }
    $("#audio-fingerprint-facts").setAttribute("aria-busy", String(running || waitingForRelease));

    var countText = "未开始";
    if (running) countText = completedRuns + " / " + AUDIO_FINGERPRINT_RUNS;
    if (audio.state === "stable" || audio.state === "disturbed") countText = AUDIO_FINGERPRINT_RUNS + " 轮";
    if (audio.state === "restricted") countText = "受限";
    if (audio.state === "uncertain") countText = "不确定";
    $("#audio-fingerprint-count").textContent = countText;

    setMiniStatusNode($("#audio-fingerprint-summary-status"), running ? "检测中" : (audio.state === "idle" ? "未开始" : audio.result), running ? "neutral" : audio.tone);
    setMiniStatusNode($("#fingerprint-panel-status"), running ? "检测中" : (audio.state === "idle" ? "未开始" : audio.result), running ? "neutral" : audio.tone);

    var panelNote = "等待开始检测；尚未读取本地浏览器与 WebAudio 信号。";
    if (running) panelNote = "正在执行第 " + Math.min(completedRuns + 1, AUDIO_FINGERPRINT_RUNS) + " / " + AUDIO_FINGERPRINT_RUNS + " 轮离线音频渲染。";
    if (audio.state === "stable") panelNote = "三轮离线音频输出一致；本页观察到稳定结果，但这不等同于跨站可追踪。";
    if (audio.state === "disturbed") panelNote = "三轮离线音频输出存在差异；可能来自浏览器防护，也可能是正常计算波动。";
    if (audio.state === "restricted") panelNote = "浏览器未提供可比较的离线音频输出，可能已限制或阻止该指纹表面。";
    if (audio.state === "uncertain") panelNote = "离线音频检测未完整结束，当前结果不足以下结论。";
    if (waitingForRelease) panelNote = "上一轮离线渲染仍在释放；为避免并发堆积，暂时锁定重试按钮。";
    $("#fingerprint-panel-note").textContent = panelNote;

    var announcement = $("#audio-fingerprint-announcement");
    if (running) announcement.textContent = "WebAudio 音频指纹检测中，已完成 " + completedRuns + " / " + AUDIO_FINGERPRINT_RUNS + " 轮";
    else if (waitingForRelease) announcement.textContent = "离线音频渲染仍在释放，请稍候";
    else announcement.textContent = "WebAudio 音频指纹检测结果：" + (audio.state === "idle" ? "尚未开始" : audio.result + "；" + consistencyText);

    var runList = $("#audio-fingerprint-runs");
    runList.replaceChildren();
    audio.runs.forEach(function (run, index) {
      var item = document.createElement("li");
      var digestGroup = document.createElement("div");
      digestGroup.className = "audio-fingerprint-run-digest";
      var digestCode = makeTextElement("code", "", core.maskDigest(run.digest, state.privacy));
      var digestName = run.digest.length === 64 ? "SHA-256 音频摘要" : "本地备用音频摘要";
      digestCode.title = digestName;
      var copyButton = makeTextElement("button", "audio-fingerprint-copy", "复制");
      copyButton.type = "button";
      copyButton.setAttribute("aria-label", "复制第 " + (index + 1) + " 轮" + digestName);
      copyButton.addEventListener("click", function () {
        copyText(core.maskDigest(run.digest, state.privacy), "第 " + (index + 1) + " 轮音频摘要已复制");
      });
      digestGroup.append(digestCode, copyButton);
      item.append(makeTextElement("span", "audio-fingerprint-run-label", "第 " + (index + 1) + " 轮"));
      item.append(digestGroup);
      item.append(makeTextElement("span", "audio-fingerprint-run-meta", run.durationMs + "ms · RMS " + run.rms));
      runList.append(item);
    });
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
      ["色深", state.localSignals.colorDepth ? state.localSignals.colorDepth + " bit" : "不可读取"],
      ["Canvas / WebGL", (state.localSignals.canvasAvailable ? "Canvas 可用" : "Canvas 不可用") + " · " + (state.localSignals.webglAvailable ? "WebGL 可用" : "WebGL 不可用")],
      ["字体接口", state.localSignals.fontApiAvailable ? "FontFaceSet 可用 · 不推断已安装字体" : "FontFaceSet 不可用"],
      ["语言 / 时区", state.observations.languages.join(", ") + " · " + state.observations.timezone],
    ].forEach(function (entry) {
      var item = document.createElement("li");
      item.append(makeTextElement("strong", "", entry[0]));
      item.append(document.createTextNode(entry[1]));
      list.append(item);
    });
    var hashCount = [state.fingerprints.v3.value, state.fingerprints.v2.value].filter(function (value) { return /^[0-9a-f]{64}$/.test(value); }).length;
    $("#fingerprint-environment-summary").textContent = hashCount + " 份本地摘要 · 7 类环境信号";
    setMiniStatusNode($("#fingerprint-environment-status"), hashCount === 2 ? "已生成" : "摘要未就绪", hashCount === 2 ? "good" : "neutral");
  }

  async function sha256(value) {
    if (!globalThis.crypto || !crypto.subtle || typeof TextEncoder === "undefined") return null;
    var buffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
    return Array.from(new Uint8Array(buffer)).map(function (byte) { return byte.toString(16).padStart(2, "0"); }).join("");
  }

  function fallbackByteDigest(bytes) {
    var hashA = 2166136261;
    var hashB = 2246822519;
    for (var index = 0; index < bytes.length; index += 1) {
      hashA = Math.imul(hashA ^ bytes[index], 16777619);
      hashB = Math.imul(hashB ^ bytes[index], 3266489917);
    }
    return (hashA >>> 0).toString(16).padStart(8, "0") + (hashB >>> 0).toString(16).padStart(8, "0");
  }

  async function digestAudioSamples(samples) {
    var sampleCopy = new Float32Array(samples);
    var bytes = new Uint8Array(sampleCopy.buffer);
    try {
      if (globalThis.crypto && crypto.subtle) {
        var digest = await crypto.subtle.digest("SHA-256", bytes);
        return Array.from(new Uint8Array(digest)).map(function (byte) { return byte.toString(16).padStart(2, "0"); }).join("");
      }
      return fallbackByteDigest(bytes);
    } finally {
      sampleCopy.fill(0);
    }
  }

  function withAudioFingerprintTimeout(promise) {
    return new Promise(function (resolve, reject) {
      var settled = false;
      var timer = setTimeout(function () {
        if (settled) return;
        settled = true;
        var error = new Error("离线音频渲染超时");
        error.code = "AUDIO_FINGERPRINT_TIMEOUT";
        reject(error);
      }, AUDIO_FINGERPRINT_TIMEOUT_MS);
      promise.then(function (value) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(value);
      }, function (error) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(error);
      });
    });
  }

  function trackPendingAudioRender(promise) {
    pendingAudioFingerprintRenders += 1;
    var released = false;
    function release() {
      if (released) return;
      released = true;
      pendingAudioFingerprintRenders = Math.max(0, pendingAudioFingerprintRenders - 1);
      updateAudioFingerprintView();
    }
    promise.then(release, release);
    return promise;
  }

  async function renderOfflineAudioFingerprintRun() {
    var OfflineAudio = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (!OfflineAudio) {
      var unsupported = new Error("当前浏览器未提供 OfflineAudioContext");
      unsupported.name = "NotSupportedError";
      throw unsupported;
    }
    var startedAt = performance.now();
    var offlineContext = new OfflineAudio(1, AUDIO_FINGERPRINT_FRAME_COUNT, AUDIO_FINGERPRINT_SAMPLE_RATE);
    var oscillator = null;
    var compressor = null;
    var sampleWindow = null;
    try {
      oscillator = offlineContext.createOscillator();
      compressor = offlineContext.createDynamicsCompressor();
      oscillator.type = "triangle";
      oscillator.frequency.value = 10000;
      compressor.threshold.value = -50;
      compressor.knee.value = 40;
      compressor.ratio.value = 12;
      compressor.attack.value = 0;
      compressor.release.value = 0.25;
      oscillator.connect(compressor);
      compressor.connect(offlineContext.destination);
      oscillator.start(0);
      oscillator.stop(AUDIO_FINGERPRINT_FRAME_COUNT / AUDIO_FINGERPRINT_SAMPLE_RATE);
      var renderPromise = trackPendingAudioRender(offlineContext.startRendering());
      var renderedBuffer = await withAudioFingerprintTimeout(renderPromise);
      var channel = renderedBuffer.getChannelData(0);
      sampleWindow = channel.slice(AUDIO_FINGERPRINT_SAMPLE_OFFSET);
      var squareSum = 0;
      for (var index = 0; index < sampleWindow.length; index += 1) squareSum += sampleWindow[index] * sampleWindow[index];
      var rms = Math.sqrt(squareSum / Math.max(1, sampleWindow.length));
      var digest = await digestAudioSamples(sampleWindow);
      return {
        digest: digest,
        rms: rms.toFixed(6),
        durationMs: Math.max(1, Math.round(performance.now() - startedAt)),
      };
    } finally {
      if (sampleWindow) sampleWindow.fill(0);
      if (oscillator) {
        try { oscillator.disconnect(); } catch (error) {}
      }
      if (compressor) {
        try { compressor.disconnect(); } catch (error) {}
      }
    }
  }

  function classifyAudioFingerprintRuns(runs) {
    var uniqueResults = new Set(runs.map(function (run) { return run.digest; })).size;
    var hasSignal = runs.length > 0 && runs.every(function (run) { return Number(run.rms) > 0; });
    if (!hasSignal) {
      return {
        state: "restricted",
        result: "受限或阻止",
        detail: "离线渲染未产生可比较信号",
        tone: "good",
        uniqueResults: uniqueResults,
      };
    }
    if (uniqueResults === 1) {
      return {
        state: "stable",
        result: "稳定暴露",
        detail: "三轮输出一致 · 仍不能推断跨站可链接",
        tone: "warn",
        uniqueResults: uniqueResults,
      };
    }
    return {
      state: "disturbed",
      result: "检测到扰动",
      detail: uniqueResults + " 种会话内结果 · 可能存在随机化或噪声",
      tone: "good",
      uniqueResults: uniqueResults,
    };
  }

  async function runAudioFingerprintTest() {
    if (state.audioFingerprint.state === "running" || pendingAudioFingerprintRenders > 0) return;
    state.audioFingerprint = { state: "running", result: "正在检测", detail: "正在离线渲染", tone: "neutral", runs: [], durationMs: null };
    updateAudioFingerprintView();
    var startedAt = performance.now();
    try {
      for (var index = 0; index < AUDIO_FINGERPRINT_RUNS; index += 1) {
        state.audioFingerprint.runs.push(await renderOfflineAudioFingerprintRun());
        updateAudioFingerprintView();
      }
      var classification = classifyAudioFingerprintRuns(state.audioFingerprint.runs);
      state.audioFingerprint.state = classification.state;
      state.audioFingerprint.result = classification.result;
      state.audioFingerprint.detail = classification.detail;
      state.audioFingerprint.tone = classification.tone;
      state.audioFingerprint.uniqueResults = classification.uniqueResults;
      state.audioFingerprint.durationMs = Math.max(1, Math.round(performance.now() - startedAt));
    } catch (error) {
      var restrictedNames = ["NotSupportedError", "NotAllowedError", "SecurityError"];
      if (restrictedNames.includes(error && error.name)) {
        state.audioFingerprint.state = "restricted";
        state.audioFingerprint.result = "受限或阻止";
        state.audioFingerprint.detail = "浏览器未提供可比较的离线音频输出";
        state.audioFingerprint.tone = "good";
      } else {
        state.audioFingerprint.state = "uncertain";
        state.audioFingerprint.result = "结果不确定";
        state.audioFingerprint.detail = error && error.code === "AUDIO_FINGERPRINT_TIMEOUT" ? "离线渲染超时，请保持页面前台后重试" : "检测未完整结束，请重试";
        state.audioFingerprint.tone = "warn";
      }
      state.audioFingerprint.durationMs = Math.max(1, Math.round(performance.now() - startedAt));
    }
    updateAudioFingerprintView();
  }

  async function computeFingerprints(localRevision) {
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
    });
    try {
      var values = await Promise.all([sha256(stableSource), sha256(broadSource)]);
      if (localRevision !== state.localRevision) return;
      state.fingerprints.v3.value = values[0] || "当前上下文不可计算";
      state.fingerprints.v2.value = values[1] || "当前上下文不可计算";
    } catch (error) {
      if (localRevision !== state.localRevision) return;
      state.fingerprints.v3.value = "计算失败";
      state.fingerprints.v2.value = "计算失败";
    }
    updateFingerprintView();
  }

  function startLocalDetections() {
    state.localRevision = (state.localRevision || 0) + 1;
    refreshLocalEnvironmentSignals();
    updateFingerprintView();
    state.localDetectionPromise = Promise.allSettled([runAudioFingerprintTest(), computeFingerprints(state.localRevision)]);
    return state.localDetectionPromise;
  }

  async function fetchWithTimeout(url, options) {
    return (await core.request(fetch, url, options)).payload;
  }

  function adaptiveRequestConcurrency() {
    var connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    var effectiveType = connection && String(connection.effectiveType || "").toLowerCase();
    if (connection && connection.saveData) return 2;
    if (effectiveType === "slow-2g" || effectiveType === "2g") return 2;
    if (effectiveType === "3g") return 3;
    var hardwareConcurrency = Number(navigator.hardwareConcurrency) || 4;
    return hardwareConcurrency <= 4 ? 3 : hardwareConcurrency <= 8 ? 4 : 5;
  }

  function abortError() {
    try { return new DOMException("检测已取消", "AbortError"); }
    catch (error) { var fallback = new Error("检测已取消"); fallback.name = "AbortError"; return fallback; }
  }

  function createRequestScheduler(limit, signal) {
    var concurrency = Math.max(1, Math.min(6, Number(limit) || 3));
    var active = 0;
    var queue = [];
    var stopped = Boolean(signal && signal.aborted);
    function rejectQueue() {
      stopped = true;
      while (queue.length) queue.shift().reject(abortError());
    }
    if (signal && !signal.aborted) signal.addEventListener("abort", rejectQueue, { once: true });
    function drain() {
      if (stopped) return rejectQueue();
      while (active < concurrency && queue.length) {
        var job = queue.shift();
        active += 1;
        Promise.resolve().then(job.task).then(job.resolve, job.reject).finally(function () {
          active -= 1;
          drain();
        });
      }
    }
    return {
      limit: concurrency,
      run: function (task) {
        return new Promise(function (resolve, reject) {
          if (stopped || (signal && signal.aborted)) return reject(abortError());
          queue.push({ task: task, resolve: resolve, reject: reject });
          drain();
        });
      },
      stats: function () { return { limit: concurrency, active: active, queued: queue.length }; },
    };
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
      if (signal) {
        if (signal.aborted) return finish();
        signal.addEventListener("abort", finish, { once: true });
      }
      image.referrerPolicy = "no-referrer";
      image.src = url;
    });
  }

  async function runDnsLeak(signal, runId, schedule) {
    state.dns = { state: "loading", running: true, records: [], error: null };
    render();
    try {
      var idResponse = await (schedule ? schedule(function () { return fetchWithTimeout("https://bash.ws/id", { timeoutMs: 8000, signal: signal, responseType: "text" }); }) : fetchWithTimeout("https://bash.ws/id", { timeoutMs: 8000, signal: signal, responseType: "text" }));
      var id = String(idResponse).trim();
      if (!/^[a-z0-9]{6,}$/i.test(id)) throw new Error("bash.ws 未返回有效检测 ID");
      var probes = [];
      for (var index = 1; index <= 10; index += 1) {
        var probeUrl = "https://" + index + "." + id + ".bash.ws/logo.png";
        probes.push(schedule ? schedule(function (url) { return function () { return loadProbeImage(url, signal); }; }(probeUrl)) : loadProbeImage(probeUrl, signal));
      }
      await Promise.all(probes);
      await new Promise(function (resolve) { setTimeout(resolve, 1200); });
      var payload = await (schedule ? schedule(function () { return fetchWithTimeout("https://bash.ws/dnsleak/test/" + id + "?json", { timeoutMs: 9000, signal: signal }); }) : fetchWithTimeout("https://bash.ws/dnsleak/test/" + id + "?json", { timeoutMs: 9000, signal: signal }));
      if (!Array.isArray(payload)) throw new Error("bash.ws 返回格式无效");
      if (runId !== state.runId || signal.aborted) return;
      var servers = payload.filter(function (item) { return item && item.type === "dns" && evidenceApi.normalizeIp(item.ip); });
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

  async function runAiServices(signal, runId, schedule) {
    await Promise.all(core.AI_SERVICES.map(async function (service, index) {
      if (!isCurrentRun(runId, signal)) return;
      state.aiServices[index] = Object.assign({}, service, { state: "loading", status: "检测中", attempted: true });
      requestRender();
      var result = await core.probeAiService(service, { signal: signal, schedule: schedule });
      if (!isCurrentRun(runId, signal)) return;
      state.aiServices[index] = result;
      requestRender();
    }));
  }

  async function runLiveDetection(options) {
    var config = options || {};
    if (state.runController) state.runController.abort();
    var controller = new AbortController();
    var scheduler = createRequestScheduler(adaptiveRequestConcurrency(), controller.signal);
    var peerConcurrency = Math.max(2, Math.min(4, scheduler.limit));
    var runId = state.runId + 1;
    state.runId = runId;
    state.runController = controller;
    state.running = true;
    state.completedAt = null;
    state.detectionError = null;
    state.aiServices = core.AI_SERVICES.map(function (service) { return Object.assign({}, service, { state: "pending", status: "等待检测", attempted: false }); });
    state.publicIps = { state: "loading", status: "检测中", ipv4: pendingPublicFamily("检测中"), ipv6: pendingPublicFamily("检测中"), probes: [] };
    state.observations.exitIps = { ipv4: [], ipv6: [] };
    state.ipIntelByFamily = pendingFamilyRecords(evidenceApi.IP_INTEL_SOURCES);
    state.routesByFamily = pendingFamilyRecords(evidenceApi.ROUTE_SOURCES);
    state.webrtc = evidenceApi.createPendingRecords(evidenceApi.WEBRTC_LEAK_NODES);
    state.stun = evidenceApi.createPendingRecords(evidenceApi.STUN_NODES);
    state.dns = { state: "pending", running: false, records: [], error: null };
    setRecheckControls(true);
    render();

    try {
      var webrtcPromise = evidenceApi.runWebRtcLeakNodes({
        signal: controller.signal,
        concurrency: peerConcurrency,
        timeoutMs: 5000,
        onUpdate: function (records) {
          if (!isCurrentRun(runId, controller.signal)) return;
          state.webrtc = records;
          requestRender();
        },
      }).catch(function () { return state.webrtc; });
      var stunPromise = evidenceApi.runStunNodes({
        signal: controller.signal,
        concurrency: peerConcurrency,
        timeoutMs: 5000,
        onUpdate: function (records) {
          if (!isCurrentRun(runId, controller.signal)) return;
          state.stun = records;
          requestRender();
        },
      }).catch(function () { return state.stun; });
      var dnsPromise = runDnsLeak(controller.signal, runId, scheduler.run);
      var publicIps = await evidenceApi.discoverPublicIps({
        signal: controller.signal,
        timeoutMs: 7000,
        schedule: scheduler.run,
        probeConcurrency: 4,
        onUpdate: function (snapshot) {
          if (!isCurrentRun(runId, controller.signal)) return;
          state.publicIps = Object.assign({ state: "loading", status: "正在独立读取 IPv4 / IPv6" }, snapshot);
          state.observations.exitIps = {
            ipv4: (snapshot.ipv4 && snapshot.ipv4.addresses || []).slice(),
            ipv6: (snapshot.ipv6 && snapshot.ipv6.addresses || []).slice(),
          };
          requestRender();
        },
      });
      if (!isCurrentRun(runId, controller.signal)) return false;
      state.publicIps = publicIps;
      state.observations.exitIps = { ipv4: publicIps.ipv4.addresses.slice(), ipv6: publicIps.ipv6.addresses.slice() };
      render();
      var aiPromise = runAiServices(controller.signal, runId, scheduler.run);
      if (typeof config.onPhase === "function") config.onPhase(1);

      var families = activeFamilies();
      familyKeys().filter(function (family) { return families.indexOf(family) < 0; }).forEach(function (family) {
        state.ipIntelByFamily[family] = blockedRecords(evidenceApi.IP_INTEL_SOURCES, "本轮未取得 " + familyLabel(family) + " 公网地址，未发起该地址族情报请求");
        state.routesByFamily[family] = blockedRecords(evidenceApi.ROUTE_SOURCES, "本轮未取得 " + familyLabel(family) + " 公网地址，未发起该地址族路由请求");
      });
      await Promise.all(families.map(function (family) {
        return evidenceApi.runIpIntel({
          targetIp: primaryExitIp(family),
          signal: controller.signal,
          timeoutMs: 7000,
          concurrency: 10,
          schedule: scheduler.run,
          onUpdate: function (records) {
            if (!isCurrentRun(runId, controller.signal)) return;
            state.ipIntelByFamily[family] = records;
            requestRender();
          },
        }).then(function (records) { if (isCurrentRun(runId, controller.signal)) state.ipIntelByFamily[family] = records; });
      }));
      if (!isCurrentRun(runId, controller.signal)) return false;
      if (typeof config.onPhase === "function") config.onPhase(2);
      await Promise.all(families.map(function (family) {
        var asn = evidenceApi.computeAsnConsensus(state.ipIntelByFamily[family]);
        return evidenceApi.runRouteEvidence({
          targetIp: primaryExitIp(family),
          asn: asn.value,
          signal: controller.signal,
          timeoutMs: 7000,
          concurrency: 10,
          schedule: scheduler.run,
          onUpdate: function (records) {
            if (!isCurrentRun(runId, controller.signal)) return;
            state.routesByFamily[family] = records;
            requestRender();
          },
        }).then(function (records) { if (isCurrentRun(runId, controller.signal)) state.routesByFamily[family] = records; });
      }));
      await Promise.allSettled([webrtcPromise, stunPromise, dnsPromise, aiPromise, config.localPromise]);
      if (!isCurrentRun(runId, controller.signal)) return false;
      return true;
    } catch (error) {
      if (runId !== state.runId) return false;
      state.detectionError = "本轮检测未完整结束，请重新检测。已取得的结果会保留。";
      controller.abort();
      function settlePending(records) {
        return records.map(function (record) { return ["pending", "loading"].includes(record.state) ? Object.assign({}, record, { state: "aborted", status: "已取消", voteEligible: false }) : record; });
      }
      familyKeys().forEach(function (family) {
        state.ipIntelByFamily[family] = settlePending(state.ipIntelByFamily[family]);
        state.routesByFamily[family] = settlePending(state.routesByFamily[family]);
      });
      state.webrtc = settlePending(state.webrtc);
      state.stun = settlePending(state.stun);
      state.aiServices = settlePending(state.aiServices);
      if (state.dns.running) state.dns = { state: "aborted", running: false, records: [], error: "本轮已取消" };
      return false;
    } finally {
      if (runId === state.runId) {
        state.running = false;
        state.completedAt = new Date();
        state.runController = null;
        setRecheckControls(false);
        render();
      }
    }
  }

  var loadingStages = [
    { title: "独立读取 IPv4 与 IPv6 出口", copy: "正在通过地址族专用回显源读取双栈出口；不可用地址族不会启动后续无效请求。", progress: 18 },
    { title: "分地址族交叉核对 IP 情报", copy: "每个已取得的地址族各核对 10 家来源；全局自适应并发会平滑短时间请求峰值。", progress: 52 },
    { title: "核对路由、泄漏与 AI 服务路径", copy: "正在结算各地址族路由、DNS、20 个 WebRTC / STUN 节点与 3 个 AI 服务探针。", progress: 82 },
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

  function runInitialDetection() {
    if (state.running) return;
    runLiveDetection({ localPromise: startLocalDetections() });
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
    var localPromise = startLocalDetections();
    var minimumReveal = new Promise(function (resolve) { setTimeout(resolve, reducedMotion ? 100 : 1500); });
    var completed = await runLiveDetection({
      localPromise: localPromise,
      onPhase: function (phase) { renderLoadingStage(phase); },
    });
    await minimumReveal;
    if (completed) renderLoadingStage(2, 100);
    await new Promise(function (resolve) { setTimeout(resolve, reducedMotion ? 0 : 320); });
    overlay.classList.remove("is-visible");
    await new Promise(function (resolve) { setTimeout(resolve, reducedMotion ? 0 : 240); });
    overlay.hidden = true;
    document.body.removeAttribute("data-recheck-loading");
    $("#floating-action-status").textContent = "实时检测完成，第 " + state.runCount + " 次结果已更新。";
    showToast(completed ? "检测完成，结果已更新" : "本轮未完整结束，可重新检测");
  }

  function closeStarSupportDialog() {
    state.pendingDetection = null;
    var dialog = $("#star-support-dialog");
    if (dialog.open) dialog.close();
  }

  function startRequestedDetection(kind) {
    if (kind === "initial") {
      runInitialDetection();
      return;
    }
    if (kind === "recheck") runRecheck();
  }

  function continueStarSupport() {
    var kind = state.pendingDetection;
    state.pendingDetection = null;
    var dialog = $("#star-support-dialog");
    if (dialog.open) dialog.close();
    startRequestedDetection(kind);
  }

  function requestDetection(kind) {
    if (!kind || (kind === "recheck" && state.running)) return;
    if (!starPromptPolicy.shouldPrompt()) {
      startRequestedDetection(kind);
      return;
    }
    var dialog = $("#star-support-dialog");
    if (!dialog || typeof dialog.showModal !== "function") {
      startRequestedDetection(kind);
      return;
    }
    if (dialog.open) return;
    state.pendingDetection = kind;
    starPromptPolicy.remember();
    dialog.showModal();
  }

  function requestRecheck() {
    requestDetection("recheck");
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
  setupHoverTooltipPortal();
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
  $("#audio-fingerprint-run").addEventListener("click", runAudioFingerprintTest);
  document.addEventListener("click", function (event) {
    $$(".info-tip[open]").forEach(function (tip) {
      if (!tip.contains(event.target)) tip.removeAttribute("open");
    });
  });
  window.addEventListener("scroll", function () {
    scheduleBackToTopUpdate();
    scheduleSectionNavigationUpdate();
    updateFloatingDockReadingState();
    positionHoverTooltip();
  }, { passive: true });
  window.addEventListener("resize", function () {
    scheduleBackToTopUpdate();
    scheduleSectionNavigationUpdate();
    resetFloatingDockReadingState();
    positionHoverTooltip();
  });
  window.addEventListener("hashchange", alignSectionFromLocationHash);
  window.addEventListener("popstate", alignSectionFromLocationHash);
  $$(".info-tip").forEach(setupInfoTip);
  updateBackToTopVisibility();
  updateSectionNavigation();
  render();
  alignSectionFromLocationHash();
  requestDetection("initial");
})();
