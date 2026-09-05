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

  // Address scope, not a claim that an address is routed or reachable.
  function isPublicCandidate(value) {
    var ip = normalizeIp(value);
    if (!ip) return false;
    if (ip.startsWith("::ffff:")) {
      var words = ip.slice(7).split(":").map(function (word) { return parseInt(word, 16); });
      return isPublicCandidate([words[0] >> 8, words[0] & 255, words[1] >> 8, words[1] & 255].join("."));
    }
    if (ip.includes(":")) return /^[23][0-9a-f]{3}:/.test(ip);
    var parts = ip.split(".").map(Number), a = parts[0], b = parts[1];
    return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19)));
  }

  function compareIntel(record, baseline) {
    if (!record.voteEligible) return { comparable: 0, conflicts: [] };
    return root.AISGIpSemantics.compareComparableFields(record, baseline);
  }

  // Organization strings are descriptive labels, not proof of a different network.
  // All consumers use this assessment so weak votes cannot become top-level conflicts.
  function assessIntel(families) {
    var conflicts = [], organizationDifferences = [], missing = [];
    var assessments = families.map(function (family) {
      var country = consensus(family.intel, "countryCode");
      var asn = consensus(family.intel, "asn");
      var organization = consensus(family.intel, "organization");
      var label = family.family === "ipv6" ? "IPv6" : "IPv4";
      if (!country.strong) missing.push(label + " 国家未形成可靠共识");
      if (!asn.strong) missing.push(label + " ASN 未形成可靠共识");
      if (organization.conflicts) organizationDifferences.push(label + " 组织名称存在差异，仅作标签参考，不据此认定网络冲突");
      var records = family.intel.map(function (record) {
        var comparison = compareIntel(record, { countryCode: country.value, asn: asn.value });
        var fields = [];
        if (record.voteEligible && record.countryCode && country.value) fields.push("国家");
        if (record.voteEligible && record.asn && asn.value) fields.push("ASN");
        if (comparison.conflicts.length) conflicts.push({ record: record, family: family.family, fields: comparison.conflicts });
        var orgNote = record.organization && organization.conflicts ? "；组织名称仅作参考" : "";
        return {
          record: record, conflicts: comparison.conflicts, comparable: comparison.comparable,
          label: comparison.conflicts.length ? comparison.conflicts.join(" / ") + "冲突" : fields.length ? fields.join(" / ") + "一致" + orgNote : "国家 / ASN 待核对" + orgNote,
          tone: comparison.conflicts.length ? "bad" : !fields.length || orgNote ? "neutral" : "good",
        };
      });
      return { family: family.family, country: country, asn: asn, organization: organization, records: records };
    });
    return { families: assessments, conflicts: conflicts, organizationDifferences: organizationDifferences, missing: missing };
  }

  function assessEnvironment(families, timezone, language) {
    var timezoneRegions = timezoneCountries(timezone), languageCountry = languageRegion(language);
    var timezoneChecks = [], languageChecks = [];
    families.forEach(function (family) {
      var country = consensus(family.intel, "countryCode");
      var timezoneKnown = country.strong && timezoneRegions.length > 0;
      var languageKnown = country.strong && Boolean(languageCountry);
      timezoneChecks.push({ family: family.family, known: timezoneKnown, mismatch: timezoneKnown && !timezoneRegions.includes(country.value) });
      languageChecks.push({ family: family.family, known: languageKnown, mismatch: languageKnown && languageCountry !== country.value });
    });
    return { timezone: timezoneChecks, language: languageChecks };
  }

  function assessRisk(families) {
    var flags = [["proxy", "Proxy"], ["vpn", "VPN"], ["tor", "Tor"], ["hosting", "Hosting"]];
    return families.map(function (family) {
      var checks = flags.map(function (field) {
        var eligible = family.intel.filter(function (record) { return record.voteEligible && typeof record[field[0]] === "boolean"; });
        return { label: field[1], known: eligible.length > 0, flagged: eligible.some(function (record) { return record[field[0]] === true; }) };
      });
      return { family: family.family, checks: checks, missing: checks.filter(function (item) { return !item.known; }).map(function (item) { return item.label; }) };
    });
  }

  function assessDns(dns, families) {
    var records = dns.records.filter(function (record) { return normalizeIp(record.observedIp); });
    var countries = families.map(function (family) { return family.country.value; }).filter(Boolean);
    var matched = records.filter(function (record) { return record.countryCode && countries.includes(record.countryCode); });
    var conflicts = records.filter(function (record) { return record.countryCode && countries.length && !countries.includes(record.countryCode); });
    var missing = dns.state !== "success" || !records.length || !families.length || countries.length < families.length || records.some(function (record) { return !record.countryCode; });
    return { records: records, matched: matched, conflicts: conflicts, mismatch: conflicts.length > 0, missing: missing, tone: conflicts.length ? "warn" : missing ? "neutral" : "good", label: conflicts.length ? "地区分歧" : missing ? "证据不足" : "已核对" };
  }

  function assessRoutes(families) {
    var conflicts = [], invalid = [], multiOrigin = [], missingFamilies = [];
    families.forEach(function (family) {
      var baseline = (family.asn || consensus(family.intel, "asn")).value;
      var origins = family.routes.filter(function (record) { return record.voteEligible && record.routeScope !== "asn" && (record.asns || [record.asn]).filter(Boolean).length; });
      if (!baseline || !origins.length) missingFamilies.push(family.family);
      var common = null;
      origins.forEach(function (record) {
        var asns = record.asns || [record.asn];
        if (asns.length > 1) multiOrigin.push(record);
        if (baseline && !asns.includes(baseline)) conflicts.push(record);
        common = common === null ? asns : common.filter(function (asn) { return asns.includes(asn); });
      });
      if (origins.length > 1 && !common.length) origins.forEach(function (record) { if (!conflicts.includes(record)) conflicts.push(record); });
      family.routes.forEach(function (record) { if (record.state === "path_mismatch") invalid.push(record); });
    });
    return { conflicts: conflicts, invalid: invalid, multiOrigin: multiOrigin, missingFamilies: missingFamilies, needsReview: Boolean(conflicts.length || invalid.length || multiOrigin.length) };
  }

  function createConfirmationPolicy(options) {
    var config = options || {}, scope = config.scope || root, now = config.now || Date.now;
    var key = "aisg-v2-detection-confirmed-until", ttl = 12 * 60 * 60 * 1000, memoryUntil = 0;
    function valid(value) {
      var until = Number(value), current = now();
      return Number.isFinite(until) && until > current && until <= current + ttl ? until : 0;
    }
    return Object.freeze({
      shouldPrompt: function () {
        var until = valid(memoryUntil);
        try { until = Math.max(until, valid(scope.localStorage.getItem(key))); } catch (error) {}
        try {
          var cookie = scope.document.cookie.split(/;\s*/).find(function (entry) { return entry.startsWith(key + "="); });
          if (cookie) until = Math.max(until, valid(cookie.slice(key.length + 1)));
        } catch (error) {}
        return until === 0;
      },
      remember: function () {
        memoryUntil = now() + ttl;
        try { scope.localStorage.setItem(key, String(memoryUntil)); } catch (error) {}
        try { scope.document.cookie = key + "=" + memoryUntil + "; Max-Age=43200; Path=/; SameSite=Lax" + (scope.location.protocol === "https:" ? "; Secure" : ""); } catch (error) {}
        return memoryUntil;
      },
    });
  }

  function assessWebrtc(records, exitIps) {
    var successes = records.filter(function (record) { return ["success", "partial"].includes(record.state) && candidateIps(record).length; });
    var stunResponses = successes.filter(function (record) { return !record.srflxIps || record.srflxIps.length; });
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
    var needsReview = unverified.length || httpDisagreements.length || incomplete.length || missingFamilies.length || !stunResponses.length;
    return {
      successes: successes, stunResponses: stunResponses, hostIps: uniqueIps(successes.flatMap(function (record) { return record.hostIps || []; })), ips: uniqueIps(successes.flatMap(candidateIps)), byFamily: byFamily,
      matches: matches, conflicts: conflicts, unverified: unverified, httpDisagreements: httpDisagreements,
      incomplete: incomplete, missingFamilies: missingFamilies,
      tone: !successes.length ? "warn" : conflicts.length ? "bad" : needsReview ? "warn" : "good",
      label: !successes.length ? "证据不足" : conflicts.length ? "同地址族候选分歧" : httpDisagreements.length ? "HTTP 出口存在多地址" : unverified.length ? "存在待核对地址族" : missingFamilies.length ? "部分地址族缺少候选" : incomplete.length ? "候选收集未完整结束" : !stunResponses.length ? "仅有公网 host 候选，STUN 响应未确认" : "已收集候选与出口一致",
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
    var dnsAssessment = assessDns(dns, families);
    var dnsRecords = dnsAssessment.records;
    var dnsMismatch = dnsAssessment.mismatch;
    var dnsMissing = dnsAssessment.missing;
    var routeAssessment = assessRoutes(families);
    var riskRecords = intel.filter(function (record) { return record.voteEligible && [record.proxy, record.vpn, record.tor, record.hosting].some(function (value) { return value === true; }); });
    var ai = input.aiServices || [];
    var aiMismatch = ai.some(function (record) {
      if (record.state === "restricted" || record.state === "http_error") return true;
      var ip = normalizeIp(record.observedIp);
      if (!ip) return false;
      var family = families.find(function (item) { return item.family === ipFamily(ip); });
      return !family || !family.addresses.includes(ip) || Boolean(record.countryCode && family.country.value && record.countryCode !== family.country.value);
    });
    var aiMissing = ai.length !== 3 || ai.some(function (record) { return !["path_available", "reachable", "restricted", "http_error"].includes(record.state); });
    var aiCoverage = ai.reduce(function (sum, record) { return sum + (["path_available", "reachable", "restricted", "http_error"].includes(record.state) ? 1 : record.state === "unverified" ? 0.5 : 0); }, 0) / 3;
    var coverage = Math.round((families.length ? 10 : 0) + 25 * usable(intel) / slots + 20 * usable(routes) / slots + 20 * webrtc.stunResponses.filter(function (record) { return record.gatheringComplete !== false; }).length / 20 + (dnsRecords.length ? dnsMissing ? 7.5 : 15 : 0) + 10 * aiCoverage);
    var intelAssessment = assessIntel(families);
    var dimensions = [], missingReasons = intelAssessment.missing.slice(), scoreBlockers = [];
    function check(known, passed, missingReason) {
      if (!known && missingReason) missingReasons.push(missingReason);
      return { known: Boolean(known), passed: Boolean(passed) };
    }
    function dimension(id, label, weight, checks) {
      var unit = weight / Math.max(1, checks.length);
      var assessed = checks.filter(function (item) { return item.known; }).length * unit;
      var earned = checks.filter(function (item) { return item.known && item.passed; }).length * unit;
      dimensions.push({ id: id, label: label, weight: weight, assessedWeight: assessed, earnedWeight: earned, state: !assessed ? "unknown" : earned < assessed ? "review" : assessed < weight ? "partial" : "matched" });
    }
    var countryValues = intelAssessment.families.map(function (family) { return family.country.value; }).filter(Boolean);
    var asnValues = intelAssessment.families.map(function (family) { return family.asn.value; }).filter(Boolean);
    var crossCountry = new Set(countryValues).size > 1;
    var crossAsn = new Set(asnValues).size > 1;
    dimension("network", "IP 归属", 20, intelAssessment.families.flatMap(function (family) {
      var label = family.family === "ipv6" ? "IPv6" : "IPv4";
      var multipleExits = webrtc.httpDisagreements.includes(family.family);
      return [
        check(family.country.strong || multipleExits, !family.country.conflicts && !crossCountry && !multipleExits, label + " 国家未形成可靠共识"),
        check(family.asn.strong || multipleExits, !family.asn.conflicts && !crossAsn && !multipleExits, label + " ASN 未形成可靠共识"),
      ];
    }));
    dimension("routes", "路由归属", 15, families.map(function (family) {
      var result = assessRoutes([family]);
      return check(!result.missingFamilies.length || result.needsReview, !result.needsReview, family.family.toUpperCase().replace("IPV", "IPv") + " 路由起源缺少可核对证据");
    }));
    dimension("webrtc", "WebRTC", 25, families.map(function (family) {
      var candidates = webrtc.byFamily[family.family];
      var conflict = webrtc.conflicts.some(function (record) { return ipFamily(record.observedIp) === family.family; });
      // A conflict already observed remains adverse evidence even when gathering times out.
      var complete = candidates.some(function (record) { return record.gatheringComplete !== false; });
      return check(conflict || complete, !conflict, (family.family === "ipv6" ? "IPv6" : "IPv4") + " WebRTC 未取得完整可核对候选");
    }));
    if (webrtc.unverified.length) missingReasons.push("部分 WebRTC 候选缺少同地址族 HTTP 基准");
    if (webrtc.incomplete.length) missingReasons.push("部分 WebRTC 候选收集未完整结束，已观察到的分歧仍保留");
    if (!webrtc.stunResponses.length) missingReasons.push("STUN 服务器响应未确认");
    // Preserve the share comparable to known exit countries, without pretending the
    // other address family or an unknown resolver country has also been checked.
    if (dnsMissing) missingReasons.push("DNS 解析器或部分出口地区证据不足");
    dimension("dns", "DNS 地区", 10, families.flatMap(function (family) {
      return dnsRecords.map(function (record) {
        var known = Boolean(family.country.value && record.countryCode && (dns.state === "success" || dnsMismatch));
        return check(known, countryValues.includes(record.countryCode));
      });
    }));
    var risk = assessRisk(families);
    dimension("risk", "来源风险标签", 10, risk.flatMap(function (family) {
      if (family.missing.length) missingReasons.push((family.family === "ipv6" ? "IPv6" : "IPv4") + " 风险标签未取得：" + family.missing.join(" / "));
      return family.checks.map(function (item) { return check(item.known, !item.flagged); });
    }));
    var environment = assessEnvironment(families, input.timezone, input.language);
    var timezoneMismatch = environment.timezone.some(function (item) { return item.mismatch; });
    var languageMismatch = environment.language.some(function (item) { return item.mismatch; });
    dimension("timezone", "时区一致性", 5, environment.timezone.map(function (item) {
      return check(item.known, !item.mismatch, (item.family === "ipv6" ? "IPv6" : "IPv4") + " 时区与出口地区尚不可核对");
    }));
    dimension("language", "语言地区", 5, environment.language.map(function (item) {
      return check(item.known, !item.mismatch, (item.family === "ipv6" ? "IPv6" : "IPv4") + " 语言地区与出口尚不可核对");
    }));
    dimension("ai", "AI 服务路径", 10, AI_SERVICES.map(function (service) {
      var record = ai.find(function (item) { return item.id === service.id; });
      var known = record && ["path_available", "reachable", "restricted", "http_error"].includes(record.state);
      var ip = record && normalizeIp(record.observedIp);
      var family = ip && families.find(function (item) { return item.family === ipFamily(ip); });
      var mismatch = record && (["restricted", "http_error"].includes(record.state) || ip && (!family || !family.addresses.includes(ip) || record.countryCode && family.country.value && record.countryCode !== family.country.value));
      return check(known, !mismatch, service.name + " 响应不可核对");
    }));
    if (!families.length) missingReasons.unshift("未取得 HTTP 公网出口，无法按地址族核对");
    if (dnsMissing && dnsMismatch) missingReasons.push("部分 DNS 地区仍未知，已确认地区分歧不被忽略");
    var assessedWeight = dimensions.reduce(function (sum, item) { return sum + item.assessedWeight; }, 0);
    var earnedWeight = dimensions.reduce(function (sum, item) { return sum + item.earnedWeight; }, 0);
    var reliableBaseline = families.some(function (family, index) { return normalizeIp(family.ip) && intelAssessment.families[index].country.strong && usable(family.intel) >= 3; });
    if (!reliableBaseline) scoreBlockers.push("缺少 HTTP 出口及可靠国家共识（至少 3 个可用情报来源）");
    if (assessedWeight < 40) scoreBlockers.push("可核对权重不足 40 / 100，暂不评分");
    var scoreAvailable = scoreBlockers.length === 0;
    var reasons = [];
    if (webrtc.conflicts.length) reasons.push("WebRTC 候选与同族 HTTP 出口不同");
    if (dnsMismatch) reasons.push("DNS 解析器地区与已知出口不同");
    if (routeAssessment.conflicts.length) reasons.push("路由起源 ASN 与 IP 情报或其他路由来源不同");
    if (routeAssessment.invalid.length) reasons.push("路由响应与查询 IP、前缀或 ASN 不匹配");
    if (routeAssessment.multiOrigin.length) reasons.push("路由返回多个起源 ASN，需核对多起源公告");
    if (riskRecords.length) reasons.push("来源返回明确代理或机房标签");
    if (intelAssessment.conflicts.length) reasons.push("IP 情报存在国家 / ASN 明确冲突");
    if (timezoneMismatch) reasons.push("时区与出口地区不同");
    if (languageMismatch) reasons.push("语言地区与出口不同");
    if (crossCountry || crossAsn) reasons.push("双栈归属存在差异");
    if (webrtc.httpDisagreements.length) reasons.push("同族 HTTP 回显返回多个出口");
    if (aiMismatch) reasons.push("AI 服务返回受限状态或不同路径");
    missingReasons = Array.from(new Set(missingReasons));
    var missing = !scoreAvailable || missingReasons.length > 0;
    return {
      coverage: Math.min(100, coverage), score: scoreAvailable ? Math.round(100 * earnedWeight / assessedWeight) : null,
      scoreState: !scoreAvailable ? "unavailable" : missing ? "partial" : "complete", scoreBlockers: scoreBlockers,
      assessedWeight: assessedWeight, earnedWeight: earnedWeight, dimensions: dimensions, missingReasons: missingReasons,
      reasons: reasons, notes: intelAssessment.organizationDifferences, intel: intelAssessment, routes: routeAssessment,
      dnsMissing: dnsMissing, dnsMismatch: dnsMismatch, riskRecords: riskRecords, risk: risk, environment: environment, aiMissing: aiMissing, aiMismatch: aiMismatch,
      needsReview: reasons.length > 0 || webrtc.unverified.length > 0, evidenceMissing: missing,
    };
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

  root.AISGV2Core = Object.freeze({ normalizeIp: normalizeIp, ipFamily: ipFamily, uniqueIps: uniqueIps, maskSensitiveText: maskSensitiveText, maskDigest: maskDigest, request: request, consensus: consensus, timezoneCountries: timezoneCountries, languageRegion: languageRegion, candidateIps: candidateIps, isPublicCandidate: isPublicCandidate, compareIntel: compareIntel, assessIntel: assessIntel, assessEnvironment: assessEnvironment, assessRisk: assessRisk, assessDns: assessDns, assessRoutes: assessRoutes, createConfirmationPolicy: createConfirmationPolicy, assessWebrtc: assessWebrtc, assessOverview: assessOverview, AI_SERVICES: AI_SERVICES, probeAiService: probeAiService });
})(globalThis);
