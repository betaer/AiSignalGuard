(function exposeDetectionCore(root) {
  "use strict";

  function normalizeIp(value) {
    var text = String(value == null ? "" : value).trim().replace(/^\[|\]$/g, "").split("%")[0].toLowerCase();
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(text)) {
      var parts = text.split(".").map(Number);
      return parts.every(function (part) { return part >= 0 && part <= 255; }) ? parts.join(".") : null;
    }
    if (!text.includes(":") || !/^[0-9a-f:.]+$/.test(text)) return null;
    try { return new URL("http://[" + text + "]/").hostname.slice(1, -1); }
    catch (error) { return null; }
  }

  function ipFamily(ip) {
    var normalized = normalizeIp(ip);
    return normalized ? normalized.includes(":") ? "ipv6" : "ipv4" : null;
  }

  function uniqueIps(values) {
    return Array.from(new Set((values || []).map(normalizeIp).filter(Boolean)));
  }

  function maskIp(ip) {
    var normalized = normalizeIp(ip);
    if (!normalized) return ip;
    if (!normalized.includes(":")) return normalized.split(".").slice(0, 2).join(".") + ".x.x";
    var halves = normalized.split("::");
    var left = halves[0] ? halves[0].split(":") : [];
    var right = halves[1] ? halves[1].split(":") : [];
    var expanded = left.concat(Array(Math.max(0, 8 - left.length - right.length)).fill("0"), right);
    return expanded.slice(0, 3).join(":") + ":…";
  }

  function maskSensitiveText(value) {
    return String(value == null ? "" : value).replace(
      /(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]*(?:%[a-z0-9_.-]+)?|(?:\d{1,3}\.){3}\d{1,3}/gi,
      function (token) {
        if (normalizeIp(token)) return maskIp(token);
        // An adjacent label colon or sentence dot is not part of the address.
        var leading = /^:(?!:)/.test(token) ? ":" : "";
        var trailing = (token.match(/\.+$/) || [""])[0];
        var address = token.slice(leading.length, trailing ? -trailing.length : undefined);
        return normalizeIp(address) ? leading + maskIp(address) + trailing : token;
      },
    );
  }

  function maskDigest(digest, privacy) {
    return privacy && /^[0-9a-f]{16,}$/i.test(String(digest)) ? String(digest).slice(0, 8) + "••••••••" : digest;
  }

  function abortError() {
    var error = new Error("检测已取消");
    error.name = "AbortError";
    return error;
  }

  // The deadline and parent cancellation cover headers AND body consumption.
  async function request(fetchImpl, url, options) {
    var config = options || {};
    var controller = new AbortController();
    var timer;
    var onAbort;
    var stop = new Promise(function (_, reject) {
      onAbort = function () { controller.abort(); reject(abortError()); };
      if (config.signal) {
        if (config.signal.aborted) return onAbort();
        config.signal.addEventListener("abort", onAbort, { once: true });
      }
      timer = setTimeout(function () {
        var error = new Error("请求超时");
        error.name = "TimeoutError";
        reject(error);
        controller.abort();
      }, Math.max(1, Number(config.timeoutMs) || 8000));
    });
    var work = Promise.resolve().then(async function () {
      if (controller.signal.aborted) throw abortError();
      var response = await fetchImpl(url, {
        cache: "no-store", credentials: "omit", mode: config.mode || "cors",
        referrerPolicy: "no-referrer", signal: controller.signal,
      });
      if (response.type === "opaque") {
        return { type: "opaque", status: 0, payload: null };
      }
      if (!response.ok) {
        var error = new Error("HTTP " + response.status);
        error.httpStatus = response.status;
        if (response.body) response.body.cancel().catch(function () {});
        throw error;
      }
      var payload;
      if (config.responseType === "probe") {
        if (response.body) await response.body.cancel();
        payload = null;
      } else {
        payload = config.responseType === "text" ? await response.text() : await response.json();
      }
      return { type: response.type || "basic", status: response.status || 200, payload: payload };
    });
    try { return await Promise.race([stop, work]); }
    finally {
      clearTimeout(timer);
      if (config.signal) config.signal.removeEventListener("abort", onAbort);
    }
  }

  function consensus(records, field) {
    var counts = new Map();
    (records || []).forEach(function (record) {
      if (!record.voteEligible || record[field] == null) return;
      var value = String(record[field]).trim();
      var key = field === "organization" ? root.AISGIpSemantics.normalizeOrganization(value) : value;
      if (!key) return;
      var item = counts.get(key) || { value: value, votes: 0 };
      item.votes += 1;
      counts.set(key, item);
    });
    var ranked = Array.from(counts.values()).sort(function (a, b) { return b.votes - a.votes || a.value.localeCompare(b.value); });
    var eligible = ranked.reduce(function (sum, item) { return sum + item.votes; }, 0);
    var winner = ranked[0] || { value: null, votes: 0 };
    var runnerUp = ranked[1] ? ranked[1].votes : 0;
    var strong = eligible >= 3 && winner.votes / eligible >= 0.6 && winner.votes - runnerUp >= 2;
    return {
      value: strong ? winner.value : null, winner: winner.value, strong: strong,
      votes: winner.votes, eligible: eligible, conflicts: eligible - winner.votes, distribution: ranked,
    };
  }

  function timezoneCountries(timezone) {
    var table = root.AISGTimezoneCountries || {};
    return (table[timezone] || []).slice();
  }

  function languageRegion(language) {
    try { return new Intl.Locale(String(language).replaceAll("_", "-")).region || null; }
    catch (error) { return null; }
  }

  function candidateIps(record) {
    return uniqueIps((record.observedIps || []).concat(record.observedIp || []));
  }

  function assessWebrtc(records, exitIps) {
    var successes = records.filter(function (record) { return ["success", "partial"].includes(record.state) && candidateIps(record).length; });
    var byFamily = { ipv4: [], ipv6: [] };
    successes.forEach(function (record) {
      candidateIps(record).forEach(function (ip) {
        byFamily[ipFamily(ip)].push(Object.assign({}, record, { observedIp: ip }));
      });
    });
    var matches = [], conflicts = [], unverified = [];
    ["ipv4", "ipv6"].forEach(function (family) {
      var http = uniqueIps(exitIps[family]);
      byFamily[family].forEach(function (record) {
        if (!http.length) unverified.push(record);
        else if (http.includes(record.observedIp)) matches.push(record);
        else conflicts.push(record);
      });
    });
    var httpDisagreements = ["ipv4", "ipv6"].filter(function (family) { return uniqueIps(exitIps[family]).length > 1; });
    var incomplete = successes.filter(function (record) { return record.gatheringComplete === false; });
    var missingFamilies = ["ipv4", "ipv6"].filter(function (family) { return uniqueIps(exitIps[family]).length && !byFamily[family].length; });
    var needsReview = unverified.length || httpDisagreements.length || incomplete.length || missingFamilies.length;
    return {
      successes: successes, ips: uniqueIps(successes.flatMap(candidateIps)), byFamily: byFamily,
      matches: matches, conflicts: conflicts, unverified: unverified, httpDisagreements: httpDisagreements,
      incomplete: incomplete, missingFamilies: missingFamilies,
      tone: !successes.length ? "warn" : conflicts.length ? "bad" : needsReview ? "warn" : "good",
      label: !successes.length ? "证据不足" : conflicts.length ? "同地址族候选分歧" : httpDisagreements.length ? "HTTP 出口存在多地址" : unverified.length ? "存在待核对地址族" : missingFamilies.length ? "部分地址族缺少候选" : incomplete.length ? "候选收集未完整结束" : "已收集候选与出口一致",
    };
  }

  function assessOverview(input) {
    var families = input.families || [];
    var slots = Math.max(1, families.length) * 10;
    var usable = function (items) { return items.filter(function (item) { return item.voteEligible === true; }).length; };
    var intel = families.flatMap(function (family) { return family.intel; });
    var routes = families.flatMap(function (family) { return family.routes; });
    var webrtc = input.webrtc;
    var dns = input.dns;
    var dnsRecords = dns.records.filter(function (record) { return normalizeIp(record.observedIp); });
    var countries = families.map(function (family) { return family.country.value; }).filter(Boolean);
    var dnsMismatch = dnsRecords.some(function (record) { return record.countryCode && countries.length && !countries.includes(record.countryCode); });
    var dnsMissing = dns.state !== "success" || !dnsRecords.length || dnsRecords.some(function (record) { return !record.countryCode; });
    var riskRecords = intel.filter(function (record) { return record.voteEligible && [record.proxy, record.vpn, record.tor, record.hosting].some(function (value) { return value === true; }); });
    var riskKnown = intel.some(function (record) { return record.voteEligible && [record.proxy, record.vpn, record.tor, record.hosting].some(function (value) { return typeof value === "boolean"; }); });
    var ai = input.aiServices || [];
    var aiMismatch = ai.some(function (record) {
      if (record.state === "restricted" || record.state === "http_error") return true;
      var ip = normalizeIp(record.observedIp);
      if (!ip) return false;
      var family = families.find(function (item) { return item.family === ipFamily(ip); });
      return !family || !family.addresses.includes(ip) || Boolean(record.countryCode && family.country.value && record.countryCode !== family.country.value);
    });
    var aiMissing = ai.length !== 3 || ai.some(function (record) { return !["path_available", "reachable"].includes(record.state); });
    var aiCoverage = ai.reduce(function (sum, record) { return sum + (["path_available", "reachable", "restricted", "http_error"].includes(record.state) ? 1 : record.state === "unverified" ? 0.5 : 0); }, 0) / 3;
    var coverage = Math.round((families.length ? 10 : 0) + 25 * usable(intel) / slots + 20 * usable(routes) / slots + 20 * webrtc.successes.filter(function (record) { return record.gatheringComplete !== false; }).length / 20 + (dnsRecords.length ? dnsMissing ? 7.5 : 15 : 0) + 10 * aiCoverage);
    var scoreAvailable = families.length > 0 && families.every(function (family) { return family.country.strong && usable(family.intel) >= 3 && usable(family.routes) >= 1; }) && webrtc.successes.length > 0 && !webrtc.missingFamilies.length && !webrtc.unverified.length && !webrtc.incomplete.length && !dnsMissing && coverage >= 60;
    var reasons = [];
    if (webrtc.conflicts.length) reasons.push("WebRTC 候选与同族 HTTP 出口不同");
    if (dnsMismatch) reasons.push("DNS 解析器地区与已知出口不同");
    if (riskRecords.length) reasons.push("来源返回明确代理或机房标签");
    if (input.fieldConflicts) reasons.push("IP 情报来源存在字段分歧");
    if (input.timezoneMismatch) reasons.push("时区与出口地区不同");
    if (input.languageMismatch) reasons.push("语言地区与出口不同");
    if (input.crossCountryMismatch || input.crossAsnMismatch) reasons.push("双栈归属存在差异");
    if (webrtc.httpDisagreements.length) reasons.push("同族 HTTP 回显返回多个出口");
    if (aiMismatch) reasons.push("AI 服务返回受限状态或不同路径");
    var missing = !scoreAvailable || dnsMissing || !riskKnown || aiMissing;
    var penalties = (webrtc.conflicts.length ? 25 : 0) + (dnsMismatch ? 10 : 0) + (riskRecords.length ? 10 : 0) + (input.fieldConflicts ? 8 : 0) + (input.timezoneMismatch ? 5 : 0) + (input.languageMismatch ? 5 : 0) + (input.crossCountryMismatch ? 12 : 0) + (input.crossAsnMismatch ? 5 : 0) + (webrtc.httpDisagreements.length ? 8 : 0) + (aiMismatch ? 10 : 0);
    return { coverage: Math.min(100, coverage), score: scoreAvailable ? Math.max(0, coverage - penalties) : null, reasons: reasons, dnsMissing: dnsMissing, dnsMismatch: dnsMismatch, riskRecords: riskRecords, aiMissing: aiMissing, needsReview: reasons.length > 0 || webrtc.unverified.length > 0, evidenceMissing: missing };
  }

  var AI_SERVICES = Object.freeze([
    Object.freeze({ id: "chatgpt", name: "ChatGPT", url: "https://chatgpt.com/cdn-cgi/trace", fallback: "https://chatgpt.com/favicon.ico?aisg_probe=1", kind: "trace" }),
    Object.freeze({ id: "claude", name: "Claude", url: "https://claude.ai/cdn-cgi/trace", fallback: "https://claude.ai/favicon.ico?aisg_probe=1", kind: "trace" }),
    Object.freeze({ id: "gemini", name: "Gemini", url: "https://gemini.google.com/robots.txt", kind: "resource" }),
  ]);

  async function probeAiService(service, options) {
    var config = options || {};
    var started = Date.now();
    var base = { id: service.id, name: service.name, url: service.url, attempted: true, observedIp: null, countryCode: null };
    async function perform(url, mode, responseType) {
      var task = function () { return request(config.fetchImpl || fetch, url, { mode: mode, responseType: responseType, timeoutMs: config.timeoutMs || 6000, signal: config.signal }); };
      return config.schedule ? config.schedule(task) : task();
    }
    function done(fields) { return Object.assign(base, fields, { latencyMs: Date.now() - started }); }
    try {
      var response;
      try { response = await perform(service.url, "cors", service.kind === "trace" ? "text" : "probe"); }
      catch (error) {
        if (error.name !== "TypeError") throw error;
        response = null;
      }
      if (response && response.type !== "opaque") {
        if (service.kind === "resource") return done({ state: "reachable", status: "资源可达", detail: "已读取资源 HTTP " + response.status + "；该服务未提供出口地址回显" });
        var trace = Object.fromEntries(String(response.payload).split(/\r?\n/).filter(function (line) { return /^[a-z_]+=[^<>]*$/i.test(line); }).map(function (line) { var split = line.indexOf("="); return [line.slice(0, split), line.slice(split + 1)]; }));
        var ip = normalizeIp(trace.ip);
        if (ip) return done({ state: "path_available", status: "路径已读取", observedIp: ip, countryCode: /^[A-Z]{2}$/.test(trace.loc || "") ? trace.loc : null, detail: "目标站回显出口" + (trace.colo ? " · 节点 " + trace.colo : "") });
      }
      var fallback = await perform(service.fallback || service.url, "no-cors", "probe");
      return done({ state: "unverified", status: "响应不可核对", detail: fallback.type === "opaque" ? "收到不透明响应，浏览器不允许读取 HTTP 状态或出口；不能判断服务可用性" : "探针返回资源，但没有可验证的服务路径信息" });
    } catch (error) {
      if (error.name === "AbortError") return done({ state: "aborted", status: "已取消", detail: "本轮已取消" });
      if (error.name === "TimeoutError") return done({ state: "timeout", status: "超时", detail: "请求未在时限内完成，不能据此判断平台账号状态" });
      if (error.httpStatus) return done({ state: [401, 403, 429].includes(error.httpStatus) ? "restricted" : "http_error", status: "HTTP " + error.httpStatus, detail: "探针返回非成功状态，可能是访问策略、限流或服务异常" });
      return done({ state: "network_error", status: "无法读取", detail: "网络、跨源策略或浏览器拦截导致本轮无法核对" });
    }
  }

  root.AISGV2Core = Object.freeze({ normalizeIp: normalizeIp, ipFamily: ipFamily, uniqueIps: uniqueIps, maskSensitiveText: maskSensitiveText, maskDigest: maskDigest, request: request, consensus: consensus, timezoneCountries: timezoneCountries, languageRegion: languageRegion, candidateIps: candidateIps, assessWebrtc: assessWebrtc, assessOverview: assessOverview, AI_SERVICES: AI_SERVICES, probeAiService: probeAiService });
})(globalThis);
