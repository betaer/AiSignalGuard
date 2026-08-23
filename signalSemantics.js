(function exposeSignalGuardSemantics(root) {
  "use strict";

  function textValue(value) {
    return value === null || value === undefined ? "" : String(value).trim();
  }

  function normalizeCountry(value) {
    return textValue(value).toUpperCase();
  }

  function normalizeAsn(value) {
    return textValue(value).toUpperCase().replace(/^AS\s*/, "");
  }

  function normalizeOrganization(value) {
    return textValue(value)
      .normalize("NFKC")
      .toLowerCase()
      .replace(/[\s,，.。·•、'"`’‘()（）[\]{}]/g, "")
      .replace(/&/g, "and");
  }

  function comparableValue(field, value) {
    if (field === "countryCode") return normalizeCountry(value);
    if (field === "asn") return normalizeAsn(value);
    if (field === "organization") return normalizeOrganization(value);
    return textValue(value).toLowerCase();
  }

  function compareComparableFields(left, right) {
    var fields = [
      ["countryCode", "国家"],
      ["asn", "ASN"],
      ["organization", "组织"],
    ];
    var comparable = 0;
    var missing = 0;
    var conflicts = [];
    fields.forEach(function (entry) {
      var field = entry[0];
      var leftValue = comparableValue(field, left && left[field]);
      var rightValue = comparableValue(field, right && right[field]);
      if (!leftValue || !rightValue) {
        missing += 1;
        return;
      }
      comparable += 1;
      if (leftValue !== rightValue) conflicts.push(entry[1]);
    });
    return { comparable: comparable, missing: missing, conflicts: conflicts };
  }

  function evaluateMajority(counts) {
    var ranked = Object.entries(counts || {})
      .map(function (entry) { return { value: entry[0], votes: Number(entry[1]) || 0 }; })
      .filter(function (entry) { return entry.votes > 0; })
      .sort(function (left, right) { return right.votes - left.votes || left.value.localeCompare(right.value); });
    var eligible = ranked.reduce(function (sum, entry) { return sum + entry.votes; }, 0);
    var winner = ranked[0] || { value: null, votes: 0 };
    var runnerUp = ranked[1] ? ranked[1].votes : 0;
    var strongEnough = eligible >= 3 && winner.votes / eligible >= 0.6 && winner.votes - runnerUp >= 2;
    return {
      tone: strongEnough ? "good" : eligible >= 3 ? "warn" : "neutral",
      label: strongEnough ? "基本一致" : eligible >= 3 ? "票数分散" : "证据不足",
      winner: winner.value,
      votes: winner.votes,
      eligible: eligible,
    };
  }

  root.AISGIpSemantics = Object.freeze({
    normalizeCountry: normalizeCountry,
    normalizeAsn: normalizeAsn,
    normalizeOrganization: normalizeOrganization,
    compareComparableFields: compareComparableFields,
    evaluateMajority: evaluateMajority,
  });
})(globalThis);
