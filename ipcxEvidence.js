(function attachIpEvidence(root, factory) {
  "use strict";

  var api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
  root.AISGIpEvidence = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function createIpEvidenceApi() {
  "use strict";

  var DEFAULT_TIMEOUT_MS = 8000;
  var DEFAULT_CONCURRENCY = 4;

  function immutableRegistry(entries) {
    return Object.freeze(
      entries.map(function (entry) {
        return Object.freeze(entry);
      }),
    );
  }

  var IP_INTEL_SOURCES = immutableRegistry([
    {
      id: "ipwho",
      name: "ipwho.is",
      endpoint: function (ip) {
        return "https://ipwho.is/" + encodeURIComponent(ip);
      },
    },
    {
      id: "ipsb",
      name: "ip.sb",
      endpoint: function (ip) {
        return "https://api.ip.sb/geoip/" + encodeURIComponent(ip);
      },
    },
    {
      id: "geojs",
      name: "GeoJS",
      endpoint: function (ip) {
        return (
          "https://get.geojs.io/v1/ip/geo/" + encodeURIComponent(ip) + ".json"
        );
      },
    },
    {
      id: "dbip",
      name: "DB-IP",
      endpoint: function () {
        return "https://api.db-ip.com/v2/free/self";
      },
      observesSelf: true,
    },
    {
      id: "ipapiis",
      name: "IPAPI.is",
      endpoint: function (ip) {
        return "https://api.ipapi.is/?q=" + encodeURIComponent(ip);
      },
    },
    {
      id: "ipinfo",
      name: "IPinfo",
      endpoint: function (ip) {
        return "https://ipinfo.io/" + encodeURIComponent(ip) + "/json";
      },
    },
    {
      id: "countryis",
      name: "country.is",
      endpoint: function () {
        return "https://api.country.is/";
      },
      observesSelf: true,
    },
    {
      id: "iplocation",
      name: "IPLocation.net",
      endpoint: function (ip) {
        return "https://api.iplocation.net/?ip=" + encodeURIComponent(ip);
      },
    },
    {
      id: "freeipapi",
      name: "FreeIPAPI",
      endpoint: function (ip) {
        return "https://free.freeipapi.com/api/json/" + encodeURIComponent(ip);
      },
    },
    {
      id: "ipguide",
      name: "IP.guide",
      endpoint: function (ip) {
        return "https://ip.guide/" + encodeURIComponent(ip);
      },
    },
  ]);

  var ROUTE_SOURCES = immutableRegistry([
    {
      id: "iana",
      name: "IANA RDAP Bootstrap",
      endpoint: function (context) {
        return context.targetIp.indexOf(":") >= 0
          ? "https://data.iana.org/rdap/ipv6.json"
          : "https://data.iana.org/rdap/ipv4.json";
      },
    },
    {
      id: "rir-rdap",
      name: "权威 RIR RDAP",
      endpoint: function (context) {
        return "https://rdap.org/ip/" + context.targetIp;
      },
    },
    {
      id: "ripe-network",
      name: "RIPEstat Network Info",
      endpoint: function (context) {
        return (
          "https://stat.ripe.net/data/network-info/data.json?resource=" +
          encodeURIComponent(context.targetIp)
        );
      },
    },
    {
      id: "ripe-whois",
      name: "RIPEstat Whois",
      endpoint: function (context) {
        return (
          "https://stat.ripe.net/data/whois/data.json?resource=" +
          encodeURIComponent(context.targetIp)
        );
      },
    },
    {
      id: "team-cymru",
      name: "Team Cymru IP-to-ASN",
      endpoint: function (context) {
        return (
          "https://dns.google/resolve?name=" +
          encodeURIComponent(cymruLookupName(context.targetIp)) +
          "&type=TXT"
        );
      },
    },
    {
      id: "peeringdb",
      name: "PeeringDB",
      needsAsn: true,
      endpoint: function (context) {
        return (
          "https://www.peeringdb.com/api/net?asn=" +
          encodeURIComponent(asnNumber(context.asn))
        );
      },
    },
    {
      id: "ipguide-network",
      name: "IP.guide Network",
      endpoint: function (context) {
        return "https://ip.guide/" + encodeURIComponent(context.targetIp);
      },
    },
    {
      id: "ripe-announced",
      name: "RIPEstat Announced Prefixes",
      needsAsn: true,
      endpoint: function (context) {
        return (
          "https://stat.ripe.net/data/announced-prefixes/data.json?resource=" +
          encodeURIComponent(context.asn)
        );
      },
    },
    {
      id: "hackertarget",
      name: "HackerTarget AS Lookup",
      responseType: "text",
      endpoint: function (context) {
        return (
          "https://api.hackertarget.com/aslookup/?q=" +
          encodeURIComponent(context.targetIp)
        );
      },
    },
    {
      id: "caida",
      name: "CAIDA AS Rank",
      needsAsn: true,
      endpoint: function (context) {
        return (
          "https://api.asrank.caida.org/v2/restful/asns/" +
          encodeURIComponent(asnNumber(context.asn))
        );
      },
    },
  ]);

  var STUN_NODES = immutableRegistry([
    { id: "google-0", name: "Google 0", url: "stun:stun.l.google.com:19302" },
    { id: "google-1", name: "Google 1", url: "stun:stun1.l.google.com:19302" },
    { id: "google-2", name: "Google 2", url: "stun:stun2.l.google.com:19302" },
    { id: "google-3", name: "Google 3", url: "stun:stun3.l.google.com:19302" },
    { id: "google-4", name: "Google 4", url: "stun:stun4.l.google.com:19302" },
    { id: "cloudflare", name: "Cloudflare", url: "stun:stun.cloudflare.com:3478" },
    { id: "twilio", name: "Twilio", url: "stun:global.stun.twilio.com:3478" },
    { id: "metered", name: "Metered", url: "stun:stun.relay.metered.ca:80" },
    { id: "nextcloud", name: "Nextcloud", url: "stun:stun.nextcloud.com:3478" },
    { id: "bilibili", name: "Bilibili", url: "stun:stun.chat.bilibili.com:3478" },
  ]);

  function nowMs() {
    return typeof performance !== "undefined" && performance.now
      ? performance.now()
      : Date.now();
  }

  function cloneRecords(records) {
    return records.map(function (record) {
      return Object.assign({}, record);
    });
  }

  function createPendingRecord(source) {
    return {
      id: source.id,
      name: source.name,
      state: "pending",
      status: "等待检测",
      latencyMs: null,
      observedIp: null,
      countryCode: null,
      countryName: null,
      region: null,
      city: null,
      asn: null,
      organization: null,
      networkType: null,
      proxy: null,
      vpn: null,
      tor: null,
      hosting: null,
      prefix: null,
      registry: null,
      detail: null,
      voteEligible: false,
      attempted: false,
    };
  }

  function createPendingRecords(registry) {
    return registry.map(createPendingRecord);
  }

  function stringValue(value) {
    if (value === null || value === undefined) return null;
    var text = String(value).trim();
    return text && text !== "-" && text.toLowerCase() !== "null" ? text : null;
  }

  function readPath(value, path) {
    var cursor = value;
    for (var index = 0; index < path.length; index += 1) {
      if (!cursor || typeof cursor !== "object") return undefined;
      cursor = cursor[path[index]];
    }
    return cursor;
  }

  function firstValue(payload, paths) {
    for (var index = 0; index < paths.length; index += 1) {
      var value = Array.isArray(paths[index])
        ? readPath(payload, paths[index])
        : payload && payload[paths[index]];
      var normalized = stringValue(value);
      if (normalized) return normalized;
    }
    return null;
  }

  function firstBoolean(payload, paths) {
    for (var index = 0; index < paths.length; index += 1) {
      var value = Array.isArray(paths[index])
        ? readPath(payload, paths[index])
        : payload && payload[paths[index]];
      if (typeof value === "boolean") return value;
      if (value === 1 || value === "1" || value === "true") return true;
      if (value === 0 || value === "0" || value === "false") return false;
    }
    return null;
  }

  function normalizeIp(value) {
    var text = stringValue(value);
    if (!text) return null;
    text = text.replace(/^\[|\]$/g, "").split("%")[0].toLowerCase();
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(text)) {
      var parts = text.split(".").map(Number);
      return parts.every(function (part) {
        return part >= 0 && part <= 255;
      })
        ? parts.join(".")
        : null;
    }
    return /^[0-9a-f:]+$/.test(text) && text.indexOf(":") >= 0 ? text : null;
  }

  function normalizeAsn(value) {
    var text = stringValue(value);
    if (!text) return null;
    var match = text.match(/(?:^|\b)AS\s*(\d+)|^(\d+)$/i);
    var digits = match && (match[1] || match[2]);
    return digits ? "AS" + String(Number(digits)) : null;
  }

  function asnNumber(value) {
    var normalized = normalizeAsn(value);
    return normalized ? normalized.slice(2) : "";
  }

  function normalizeCountryCode(value) {
    var text = stringValue(value);
    if (!text) return null;
    var upper = text.toUpperCase();
    return /^[A-Z]{2}$/.test(upper) ? upper : null;
  }

  function splitOrg(value) {
    var text = stringValue(value);
    if (!text) return { asn: null, organization: null };
    var match = text.match(/^AS?(\d+)\s+(.+)$/i);
    if (!match) return { asn: normalizeAsn(text), organization: text };
    return { asn: normalizeAsn(match[1]), organization: stringValue(match[2]) };
  }

  function normalizeIntelFields(sourceId, payload) {
    var fields = {};
    if (sourceId === "ipwho") {
      fields = {
        observedIp: payload.ip,
        countryCode: payload.country_code,
        countryName: payload.country,
        region: payload.region,
        city: payload.city,
        asn: readPath(payload, ["connection", "asn"]),
        organization:
          readPath(payload, ["connection", "org"]) ||
          readPath(payload, ["connection", "isp"]),
        networkType: readPath(payload, ["connection", "type"]),
        proxy: readPath(payload, ["security", "proxy"]),
        vpn: readPath(payload, ["security", "vpn"]),
        tor: readPath(payload, ["security", "tor"]),
        hosting: readPath(payload, ["security", "hosting"]),
      };
    } else if (sourceId === "ipsb") {
      fields = {
        observedIp: payload.ip,
        countryCode: payload.country_code,
        countryName: payload.country,
        region: payload.region,
        city: payload.city,
        asn: payload.asn,
        organization:
          payload.asn_organization || payload.organization || payload.isp,
        networkType: payload.type,
      };
    } else if (sourceId === "geojs") {
      fields = {
        observedIp: payload.ip,
        countryCode: payload.country_code,
        countryName: payload.country,
        region: payload.region,
        city: payload.city,
        asn: payload.asn,
        organization:
          payload.organization_name || payload.organization || payload.isp,
      };
    } else if (sourceId === "dbip") {
      fields = {
        observedIp: payload.ipAddress,
        countryCode: payload.countryCode,
        countryName: payload.countryName,
        region: payload.stateProv,
        city: payload.city,
      };
    } else if (sourceId === "ipapiis") {
      fields = {
        observedIp: payload.ip,
        countryCode:
          readPath(payload, ["location", "country_code"]) || payload.country_code,
        countryName:
          readPath(payload, ["location", "country"]) || payload.country,
        region: readPath(payload, ["location", "state"]),
        city: readPath(payload, ["location", "city"]),
        asn: readPath(payload, ["asn", "asn"]) || payload.asn,
        organization:
          readPath(payload, ["asn", "org"]) ||
          readPath(payload, ["company", "name"]),
        networkType: readPath(payload, ["asn", "type"]),
        proxy: payload.is_proxy,
        vpn: payload.is_vpn,
        tor: payload.is_tor,
        hosting: payload.is_datacenter,
      };
    } else if (sourceId === "ipinfo") {
      var org = splitOrg(payload.org);
      fields = {
        observedIp: payload.ip,
        countryCode: payload.country,
        countryName: readPath(payload, ["country_name"]),
        region: payload.region,
        city: payload.city,
        asn: org.asn,
        organization: org.organization,
        networkType: payload.type,
        hosting: readPath(payload, ["privacy", "hosting"]),
        proxy: readPath(payload, ["privacy", "proxy"]),
        vpn: readPath(payload, ["privacy", "vpn"]),
        tor: readPath(payload, ["privacy", "tor"]),
      };
    } else if (sourceId === "countryis") {
      fields = { observedIp: payload.ip, countryCode: payload.country };
    } else if (sourceId === "iplocation") {
      fields = {
        observedIp: payload.ip,
        countryCode: payload.country_code2 || payload.country_code,
        countryName: payload.country_name,
        region: payload.state_prov,
        city: payload.city,
        asn: payload.asn,
        organization: payload.organization || payload.isp,
      };
    } else if (sourceId === "freeipapi") {
      fields = {
        observedIp: payload.ipAddress,
        countryCode: payload.countryCode,
        countryName: payload.countryName,
        region: payload.regionName,
        city: payload.cityName,
        asn: payload.asNumber,
        organization: payload.asOrganization,
        proxy: payload.isProxy,
      };
    } else if (sourceId === "ipguide") {
      fields = {
        observedIp: payload.ip,
        countryCode:
          readPath(payload, ["location", "country_code"]) ||
          readPath(payload, ["location", "country", "alpha2"]),
        countryName:
          readPath(payload, ["location", "country"]) ||
          readPath(payload, ["location", "country", "name"]),
        region: readPath(payload, ["location", "state"]),
        city: readPath(payload, ["location", "city"]),
        asn:
          readPath(payload, ["network", "autonomous_system", "asn"]) ||
          readPath(payload, ["network", "asn"]),
        organization:
          readPath(payload, ["network", "autonomous_system", "organization"]) ||
          readPath(payload, ["network", "autonomous_system", "name"]) ||
          readPath(payload, ["network", "organization"]),
        networkType:
          readPath(payload, ["network", "autonomous_system", "type"]) ||
          readPath(payload, ["network", "type"]),
      };
    }
    return fields;
  }

  function normalizeIntelPayload(sourceId, payload, context) {
    var source = IP_INTEL_SOURCES.find(function (entry) {
      return entry.id === sourceId;
    });
    var record = createPendingRecord(
      source || { id: sourceId, name: sourceId },
    );
    var fields = normalizeIntelFields(sourceId, payload || {});
    var targetIp = normalizeIp(context && context.targetIp);
    var observedIp = normalizeIp(fields.observedIp);
    var countryCode = normalizeCountryCode(fields.countryCode);
    var asn = normalizeAsn(fields.asn);
    var organization = stringValue(fields.organization);
    var countryName = stringValue(fields.countryName);
    var region = stringValue(fields.region);
    var city = stringValue(fields.city);
    var networkType = stringValue(fields.networkType);
    var hasGeo = Boolean(countryCode || countryName || region || city);
    var hasNetwork = Boolean(asn || organization || networkType);

    Object.assign(record, {
      observedIp: observedIp,
      countryCode: countryCode,
      countryName: countryName,
      region: region,
      city: city,
      asn: asn,
      organization: organization,
      networkType: networkType,
      proxy: firstBoolean(fields, ["proxy"]),
      vpn: firstBoolean(fields, ["vpn"]),
      tor: firstBoolean(fields, ["tor"]),
      hosting: firstBoolean(fields, ["hosting"]),
    });

    if (payload && payload.success === false) {
      record.state = "invalid";
      record.status = "服务拒绝";
      record.detail = stringValue(payload.message) || "上游未返回有效结果";
      return record;
    }
    if (targetIp && observedIp && targetIp !== observedIp) {
      record.state = "path_mismatch";
      record.status = "路径不同";
      record.detail = "该来源观察到的出口地址与本轮目标地址不同";
      return record;
    }
    if (!hasGeo && !hasNetwork) {
      record.state = "invalid";
      record.status = "无有效字段";
      record.detail = "响应成功，但未提供可核对字段";
      return record;
    }
    record.voteEligible = true;
    record.state = countryCode && asn && organization ? "success" : "partial";
    record.status = record.state === "success" ? "可用" : "字段缺失";
    record.detail =
      record.state === "success"
        ? "国家、ASN 与组织字段可用于交叉核对"
        : "仅统计该来源真实返回的字段";
    return record;
  }

  function statusLabel(state, httpStatus) {
    var labels = {
      pending: "等待检测",
      loading: "检测中",
      success: "可用",
      partial: "字段缺失",
      path_mismatch: "路径不同",
      timeout: "超时",
      rate_limited: "限流",
      network_error: "网络错误",
      aborted: "已取消",
      blocked: "缺少前置数据",
      invalid: "响应不可用",
    };
    return labels[state] || (httpStatus ? "HTTP " + httpStatus : "检测失败");
  }

  function classifyFailure(error) {
    if (error && error.name === "AbortError") {
      return { state: "aborted", status: statusLabel("aborted") };
    }
    if (error && error.name === "TimeoutError") {
      return { state: "timeout", status: statusLabel("timeout") };
    }
    var httpStatus = error && Number(error.httpStatus);
    if (httpStatus === 429) {
      return {
        state: "rate_limited",
        status: statusLabel("rate_limited"),
        httpStatus: httpStatus,
      };
    }
    if (httpStatus) {
      return {
        state: "http_error",
        status: "HTTP " + httpStatus,
        httpStatus: httpStatus,
      };
    }
    return {
      state: "network_error",
      status: statusLabel("network_error"),
    };
  }

  function fetchWithTimeout(fetchImpl, url, options) {
    var config = options || {};
    var controller = new AbortController();
    var timeoutMs = Number(config.timeoutMs) || DEFAULT_TIMEOUT_MS;
    var timedOut = false;
    var externalSignal = config.signal;
    var abortFromExternal = function () {
      controller.abort(externalSignal && externalSignal.reason);
    };
    if (externalSignal) {
      if (externalSignal.aborted) abortFromExternal();
      else externalSignal.addEventListener("abort", abortFromExternal, { once: true });
    }
    var timer = setTimeout(function () {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
    return Promise.resolve(
      fetchImpl(url, {
        cache: "no-store",
        mode: "cors",
        referrerPolicy: "no-referrer",
        signal: controller.signal,
      }),
    )
      .catch(function (error) {
        if (timedOut) {
          var timeoutError = new Error("request timeout");
          timeoutError.name = "TimeoutError";
          throw timeoutError;
        }
        throw error;
      })
      .finally(function () {
        clearTimeout(timer);
        if (externalSignal) {
          externalSignal.removeEventListener("abort", abortFromExternal);
        }
      });
  }

  async function readResponse(response, responseType) {
    if (!response || !response.ok) {
      var httpError = new Error("HTTP " + (response ? response.status : 0));
      httpError.httpStatus = response ? response.status : 0;
      throw httpError;
    }
    if (responseType === "text") return response.text();
    return response.json();
  }

  async function runPool(items, limit, worker) {
    var nextIndex = 0;
    var workers = [];
    async function next() {
      while (nextIndex < items.length) {
        var current = nextIndex;
        nextIndex += 1;
        await worker(items[current], current);
      }
    }
    var workerCount = Math.min(Math.max(1, limit), items.length);
    for (var index = 0; index < workerCount; index += 1) {
      workers.push(next());
    }
    await Promise.all(workers);
  }

  function reportSnapshot(onUpdate, records) {
    if (typeof onUpdate === "function") onUpdate(cloneRecords(records));
  }

  async function discoverPublicIp(options) {
    var config = options || {};
    var fetchImpl = config.fetchImpl || fetch;
    var startedAt = nowMs();
    try {
      var response = await fetchWithTimeout(
        fetchImpl,
        "https://api64.ipify.org?format=json",
        config,
      );
      var payload = await readResponse(response, "json");
      var ip = normalizeIp(payload && payload.ip);
      if (!ip) throw new Error("public IP missing");
      return {
        state: "success",
        status: "已读取",
        ip: ip,
        latencyMs: Math.round(nowMs() - startedAt),
        source: "ipify",
      };
    } catch (error) {
      return Object.assign(
        {
          ip: null,
          latencyMs: Math.round(nowMs() - startedAt),
          source: "ipify",
          detail: stringValue(error && error.message),
        },
        classifyFailure(error),
      );
    }
  }

  async function runIpIntel(options) {
    var config = options || {};
    var targetIp = normalizeIp(config.targetIp);
    if (!targetIp) throw new TypeError("runIpIntel requires a valid targetIp");
    var fetchImpl = config.fetchImpl || fetch;
    var records = createPendingRecords(IP_INTEL_SOURCES);
    reportSnapshot(config.onUpdate, records);
    await runPool(
      IP_INTEL_SOURCES,
      config.concurrency || DEFAULT_CONCURRENCY,
      async function (source, index) {
        var startedAt = nowMs();
        records[index].state = "loading";
        records[index].status = statusLabel("loading");
        records[index].attempted = true;
        try {
          var response = await fetchWithTimeout(fetchImpl, source.endpoint(targetIp), {
            timeoutMs: config.timeoutMs,
            signal: config.signal,
          });
          var payload = await readResponse(response, source.responseType);
          var normalized = normalizeIntelPayload(source.id, payload, {
            targetIp: targetIp,
          });
          normalized.latencyMs = Math.round(nowMs() - startedAt);
          normalized.attempted = true;
          records[index] = normalized;
        } catch (error) {
          records[index] = Object.assign(createPendingRecord(source), classifyFailure(error), {
            latencyMs: Math.round(nowMs() - startedAt),
            detail: stringValue(error && error.message),
            attempted: true,
          });
        }
        reportSnapshot(config.onUpdate, records);
      },
    );
    return cloneRecords(records);
  }

  function respondedState(state) {
    return state === "success" || state === "partial";
  }

  function summarizeSources(records) {
    var result = {
      total: records.length,
      attempted: 0,
      responded: 0,
      usable: 0,
      complete: 0,
      partial: 0,
      failed: 0,
    };
    records.forEach(function (record) {
      if (record.attempted) result.attempted += 1;
      if (respondedState(record.state)) result.responded += 1;
      if (record.voteEligible) result.usable += 1;
      if (record.state === "success") result.complete += 1;
      if (record.state === "partial") result.partial += 1;
    });
    result.failed = result.total - result.responded;
    return result;
  }

  function computeConsensus(records, field) {
    var counts = new Map();
    records.forEach(function (record) {
      var value = record.voteEligible ? stringValue(record[field]) : null;
      if (!value) return;
      counts.set(value, (counts.get(value) || 0) + 1);
    });
    var ranked = Array.from(counts.entries()).sort(function (left, right) {
      return right[1] - left[1] || left[0].localeCompare(right[0]);
    });
    var eligible = ranked.reduce(function (sum, entry) {
      return sum + entry[1];
    }, 0);
    return {
      value: ranked.length ? ranked[0][0] : null,
      votes: ranked.length ? ranked[0][1] : 0,
      eligible: eligible,
      conflicts: ranked.length
        ? eligible - ranked[0][1]
        : 0,
      distribution: ranked.map(function (entry) {
        return { value: entry[0], votes: entry[1] };
      }),
    };
  }

  function computeCountryConsensus(records) {
    return computeConsensus(records, "countryCode");
  }

  function computeAsnConsensus(records) {
    return computeConsensus(records, "asn");
  }

  function computeOrganizationConsensus(records) {
    return computeConsensus(records, "organization");
  }

  function ipv4ToNumber(ip) {
    return ip.split(".").reduce(function (sum, part) {
      return (sum * 256 + Number(part)) >>> 0;
    }, 0);
  }

  function ipInIpv4Cidr(ip, cidr) {
    var parts = String(cidr).split("/");
    var network = normalizeIp(parts[0]);
    var prefixLength = Number(parts[1]);
    if (!network || network.indexOf(":") >= 0 || prefixLength < 0 || prefixLength > 32) {
      return false;
    }
    var mask = prefixLength === 0 ? 0 : (0xffffffff << (32 - prefixLength)) >>> 0;
    return (ipv4ToNumber(ip) & mask) === (ipv4ToNumber(network) & mask);
  }

  function expandIpv6(ip) {
    var halves = ip.split("::");
    var left = halves[0] ? halves[0].split(":") : [];
    var right = halves[1] ? halves[1].split(":") : [];
    var missing = 8 - left.length - right.length;
    return left
      .concat(Array(Math.max(0, missing)).fill("0"), right)
      .map(function (part) {
        return part.padStart(4, "0");
      });
  }

  function ipInIpv6Cidr(ip, cidr) {
    var parts = String(cidr).split("/");
    var network = normalizeIp(parts[0]);
    var prefixLength = Number(parts[1]);
    if (!network || network.indexOf(":") < 0 || prefixLength < 0 || prefixLength > 128) {
      return false;
    }
    var ipBits = expandIpv6(ip)
      .map(function (part) {
        return parseInt(part, 16).toString(2).padStart(16, "0");
      })
      .join("");
    var networkBits = expandIpv6(network)
      .map(function (part) {
        return parseInt(part, 16).toString(2).padStart(16, "0");
      })
      .join("");
    return ipBits.slice(0, prefixLength) === networkBits.slice(0, prefixLength);
  }

  function ipInCidr(ip, cidr) {
    return ip.indexOf(":") >= 0
      ? ipInIpv6Cidr(ip, cidr)
      : ipInIpv4Cidr(ip, cidr);
  }

  function cymruLookupName(ip) {
    if (ip.indexOf(":") >= 0) {
      return (
        expandIpv6(ip)
          .join("")
          .split("")
          .reverse()
          .join(".") + ".origin6.asn.cymru.com"
      );
    }
    return ip.split(".").reverse().join(".") + ".origin.asn.cymru.com";
  }

  function routeRecord(source, fields) {
    var record = createPendingRecord(source);
    Object.assign(record, fields || {});
    var hasRoute = Boolean(record.asn || record.prefix || record.registry || record.organization);
    record.voteEligible = hasRoute;
    record.state = hasRoute ? "success" : "partial";
    record.status = hasRoute ? "可用" : "字段缺失";
    return record;
  }

  function findWhoisValue(records, keyPattern) {
    if (!Array.isArray(records)) return null;
    for (var index = 0; index < records.length; index += 1) {
      var row = records[index];
      var key = stringValue(row && (row.key || row.name));
      if (key && keyPattern.test(key)) {
        return stringValue(row.value || row.details || row.description);
      }
    }
    return null;
  }

  function normalizeRoutePayload(source, payload, context) {
    if (source.id === "iana") {
      var services = Array.isArray(payload && payload.services) ? payload.services : [];
      for (var serviceIndex = 0; serviceIndex < services.length; serviceIndex += 1) {
        var ranges = Array.isArray(services[serviceIndex][0]) ? services[serviceIndex][0] : [];
        for (var rangeIndex = 0; rangeIndex < ranges.length; rangeIndex += 1) {
          if (ipInCidr(context.targetIp, ranges[rangeIndex])) {
            var endpoints = services[serviceIndex][1] || [];
            var hostname = endpoints[0] ? new URL(endpoints[0]).hostname : null;
            return routeRecord(source, {
              prefix: ranges[rangeIndex],
              registry: hostname,
              detail: "IANA Bootstrap 映射到权威 RDAP 服务",
            });
          }
        }
      }
      return routeRecord(source, { detail: "IANA 响应中未找到目标网段" });
    }
    if (source.id === "rir-rdap") {
      return routeRecord(source, {
        prefix:
          payload && payload.startAddress && payload.endAddress
            ? payload.startAddress + " – " + payload.endAddress
            : null,
        registry: payload && (payload.port43 || payload.handle),
        organization: payload && payload.name,
        detail: payload && payload.type ? "RDAP 类型：" + payload.type : null,
      });
    }
    if (source.id === "ripe-network") {
      return routeRecord(source, {
        asn: normalizeAsn(readPath(payload, ["data", "asns", 0])),
        prefix: readPath(payload, ["data", "prefix"]),
        detail: "RIPEstat RIS 路由可见结果",
      });
    }
    if (source.id === "ripe-whois") {
      var records = readPath(payload, ["data", "records"]);
      var flattened = Array.isArray(records)
        ? records.reduce(function (all, group) {
            return all.concat(Array.isArray(group) ? group : []);
          }, [])
        : [];
      return routeRecord(source, {
        asn: normalizeAsn(findWhoisValue(flattened, /^origin$/i)),
        prefix: findWhoisValue(flattened, /^(?:route|route6)$/i),
        organization: findWhoisValue(flattened, /^(?:org-name|descr)$/i),
        registry: findWhoisValue(flattened, /^source$/i),
      });
    }
    if (source.id === "team-cymru") {
      var answer = readPath(payload, ["Answer", 0, "data"]);
      var text = stringValue(answer);
      var columns = text ? text.replace(/^"|"$/g, "").split("|") : [];
      return routeRecord(source, {
        asn: normalizeAsn(columns[0]),
        prefix: stringValue(columns[1]),
        countryCode: normalizeCountryCode(columns[2]),
        registry: stringValue(columns[3]),
        detail: "Team Cymru DNS TXT 实时映射",
      });
    }
    if (source.id === "peeringdb") {
      var network = readPath(payload, ["data", 0]) || {};
      return routeRecord(source, {
        asn: normalizeAsn(network.asn),
        organization: network.name,
        networkType: network.info_type,
        detail: network.website,
      });
    }
    if (source.id === "ipguide-network") {
      return routeRecord(source, {
        asn: normalizeAsn(
          readPath(payload, ["network", "autonomous_system", "asn"]),
        ),
        organization:
          readPath(payload, ["network", "autonomous_system", "organization"]) ||
          readPath(payload, ["network", "autonomous_system", "name"]),
        prefix: readPath(payload, ["network", "cidr"]),
        networkType: readPath(payload, ["network", "autonomous_system", "type"]),
      });
    }
    if (source.id === "ripe-announced") {
      var prefixes = readPath(payload, ["data", "prefixes"]);
      var prefixValues = Array.isArray(prefixes)
        ? prefixes.map(function (entry) {
            return stringValue(entry && (entry.prefix || entry));
          }).filter(Boolean)
        : [];
      return routeRecord(source, {
        prefix: prefixValues.length
          ? prefixValues[0] + (prefixValues.length > 1 ? " 等 " + prefixValues.length + " 条" : "")
          : null,
        detail: prefixValues.length
          ? "RIPEstat 返回该 ASN 当前公告的 " + prefixValues.length + " 条前缀"
          : "RIPEstat 未返回公告前缀",
      });
    }
    if (source.id === "hackertarget") {
      var line = stringValue(payload) || "";
      var csvValues = [];
      line.replace(/"([^"]*)"/g, function (_, value) {
        csvValues.push(value);
        return _;
      });
      if (csvValues.length >= 4) {
        return routeRecord(source, {
          asn: normalizeAsn(csvValues[1]),
          prefix: stringValue(csvValues[2]),
          organization: stringValue(csvValues.slice(3).join(", ")),
          detail: "HackerTarget AS Lookup 实时 CSV 结果",
        });
      }
      var match = line.match(/^((?:AS)?\d+)\s+(.+)$/i);
      return routeRecord(source, {
        asn: normalizeAsn(match && match[1]),
        organization: stringValue(match && match[2]),
        detail: line || null,
      });
    }
    if (source.id === "caida") {
      var node = readPath(payload, ["data", "asn"]) || {};
      return routeRecord(source, {
        asn: normalizeAsn(node.asn),
        organization:
          readPath(node, ["organization", "orgName"]) || node.asnName,
        countryCode: normalizeCountryCode(node.country && node.country.iso),
        registry: node.source,
        detail: node.rank ? "AS Rank " + node.rank : null,
      });
    }
    return routeRecord(source, {});
  }

  async function runRouteEvidence(options) {
    var config = options || {};
    var targetIp = normalizeIp(config.targetIp);
    if (!targetIp) throw new TypeError("runRouteEvidence requires a valid targetIp");
    var context = { targetIp: targetIp, asn: normalizeAsn(config.asn) };
    var fetchImpl = config.fetchImpl || fetch;
    var records = createPendingRecords(ROUTE_SOURCES);
    reportSnapshot(config.onUpdate, records);
    async function runBatch(sources) {
      await runPool(
        sources,
        config.concurrency || DEFAULT_CONCURRENCY,
        async function (source) {
          var index = ROUTE_SOURCES.findIndex(function (entry) {
            return entry.id === source.id;
          });
        var startedAt = nowMs();
        if (source.needsAsn && !context.asn) {
          records[index] = Object.assign(createPendingRecord(source), {
            state: "blocked",
            status: statusLabel("blocked"),
            detail: "本轮没有可用于查询该服务的真实 ASN",
            latencyMs: 0,
            attempted: false,
          });
          reportSnapshot(config.onUpdate, records);
          return;
        }
        records[index].state = "loading";
        records[index].status = statusLabel("loading");
        records[index].attempted = true;
        try {
          var response = await fetchWithTimeout(fetchImpl, source.endpoint(context), {
            timeoutMs: config.timeoutMs,
            signal: config.signal,
          });
          var payload = await readResponse(response, source.responseType);
          var normalized = normalizeRoutePayload(source, payload, context);
          normalized.latencyMs = Math.round(nowMs() - startedAt);
          normalized.attempted = true;
          records[index] = normalized;
        } catch (error) {
          records[index] = Object.assign(createPendingRecord(source), classifyFailure(error), {
            latencyMs: Math.round(nowMs() - startedAt),
            detail: stringValue(error && error.message),
            attempted: true,
          });
        }
        reportSnapshot(config.onUpdate, records);
        },
      );
    }

    if (context.asn) {
      await runBatch(ROUTE_SOURCES);
    } else {
      await runBatch(ROUTE_SOURCES.filter(function (source) {
        return !source.needsAsn;
      }));
      context.asn = computeAsnConsensus(records).value;
      await runBatch(ROUTE_SOURCES.filter(function (source) {
        return source.needsAsn;
      }));
    }
    return cloneRecords(records);
  }

  function candidateAddress(candidate) {
    var direct = normalizeIp(candidate && candidate.address);
    if (direct) return direct;
    var text = stringValue(candidate && candidate.candidate);
    if (!text) return null;
    var parts = text.split(/\s+/);
    for (var index = 0; index < parts.length; index += 1) {
      var value = normalizeIp(parts[index]);
      if (value) return value;
    }
    return null;
  }

  function probeStunNode(node, options) {
    var config = options || {};
    var createPeerConnection =
      config.createPeerConnection ||
      function (rtcConfig) {
        return new RTCPeerConnection(rtcConfig);
      };
    var timeoutMs = Number(config.timeoutMs) || 5000;
    return new Promise(function (resolve) {
      var startedAt = nowMs();
      var settled = false;
      var peer;
      var timer;
      var signal = config.signal;

      function finish(fields) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (signal) signal.removeEventListener("abort", onAbort);
        try {
          if (peer) peer.close();
        } catch (error) {}
        resolve(
          Object.assign(createPendingRecord(node), fields, {
            latencyMs: Math.round(nowMs() - startedAt),
            attempted: true,
          }),
        );
      }

      function onAbort() {
        finish({ state: "aborted", status: statusLabel("aborted") });
      }

      try {
        peer = createPeerConnection({
          iceServers: [{ urls: node.url }],
          iceCandidatePoolSize: 0,
        });
        peer.addEventListener("icecandidate", function (event) {
          var candidate = event && event.candidate;
          if (!candidate) return;
          var type = candidate.type ||
            ((candidate.candidate || "").match(/\btyp\s+(\w+)/) || [])[1];
          if (type !== "srflx") return;
          var ip = candidateAddress(candidate);
          if (!ip) return;
          finish({
            state: "success",
            status: "已响应",
            observedIp: ip,
            voteEligible: true,
            detail: "该节点独立返回公网 srflx 候选",
          });
        });
        peer.createDataChannel("aisg-probe");
        timer = setTimeout(function () {
          finish({
            state: "timeout",
            status: statusLabel("timeout"),
            detail: "该节点在时限内未返回公网候选",
          });
        }, timeoutMs);
        if (signal) {
          if (signal.aborted) return onAbort();
          signal.addEventListener("abort", onAbort, { once: true });
        }
        Promise.resolve(peer.createOffer())
          .then(function (offer) {
            return peer.setLocalDescription(offer);
          })
          .catch(function (error) {
            finish({
              state: "network_error",
              status: statusLabel("network_error"),
              detail: stringValue(error && error.message),
            });
          });
      } catch (error) {
        finish({
          state: "network_error",
          status: statusLabel("network_error"),
          detail: stringValue(error && error.message),
        });
      }
    });
  }

  async function runStunNodes(options) {
    var config = options || {};
    var records = createPendingRecords(STUN_NODES);
    reportSnapshot(config.onUpdate, records);
    await runPool(
      STUN_NODES,
      config.concurrency || 3,
      async function (node, index) {
        records[index].state = "loading";
        records[index].status = statusLabel("loading");
        records[index].attempted = true;
        records[index] = await probeStunNode(node, config);
        reportSnapshot(config.onUpdate, records);
      },
    );
    return cloneRecords(records);
  }

  return Object.freeze({
    IP_INTEL_SOURCES: IP_INTEL_SOURCES,
    ROUTE_SOURCES: ROUTE_SOURCES,
    STUN_NODES: STUN_NODES,
    normalizeIp: normalizeIp,
    normalizeAsn: normalizeAsn,
    normalizeCountryCode: normalizeCountryCode,
    normalizeIntelPayload: normalizeIntelPayload,
    createPendingRecord: createPendingRecord,
    createPendingRecords: createPendingRecords,
    classifyFailure: classifyFailure,
    statusLabel: statusLabel,
    summarizeSources: summarizeSources,
    computeCountryConsensus: computeCountryConsensus,
    computeAsnConsensus: computeAsnConsensus,
    computeOrganizationConsensus: computeOrganizationConsensus,
    discoverPublicIp: discoverPublicIp,
    runIpIntel: runIpIntel,
    runRouteEvidence: runRouteEvidence,
    probeStunNode: probeStunNode,
    runStunNodes: runStunNodes,
  });
});
