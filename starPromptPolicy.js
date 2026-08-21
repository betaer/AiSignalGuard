(function (root) {
  "use strict";

  var COOKIE_NAME = "aisg-star-prompt-until";
  var STORAGE_KEY = COOKIE_NAME;
  var TTL_MS = 12 * 60 * 60 * 1000;

  function normalizeUntil(value, now) {
    var parsed = Number(value);
    return Number.isFinite(parsed) && parsed > now ? parsed : 0;
  }

  function readCookie(scope) {
    try {
      var source = scope.document && typeof scope.document.cookie === "string" ? scope.document.cookie : "";
      var prefix = COOKIE_NAME + "=";
      var entries = source.split(/;\s*/);
      for (var index = 0; index < entries.length; index += 1) {
        if (entries[index].indexOf(prefix) === 0) {
          return decodeURIComponent(entries[index].slice(prefix.length));
        }
      }
    } catch (error) {}
    return "";
  }

  function readStorage(scope) {
    try {
      return scope.localStorage ? scope.localStorage.getItem(STORAGE_KEY) || "" : "";
    } catch (error) {
      return "";
    }
  }

  function writeCookie(scope, until) {
    try {
      if (!scope.document) return;
      var secure = scope.location && scope.location.protocol === "https:" ? "; Secure" : "";
      scope.document.cookie =
        COOKIE_NAME +
        "=" +
        encodeURIComponent(String(until)) +
        "; Max-Age=" +
        Math.floor(TTL_MS / 1000) +
        "; Path=/; SameSite=Lax" +
        secure;
    } catch (error) {}
  }

  function writeStorage(scope, until) {
    try {
      if (scope.localStorage) scope.localStorage.setItem(STORAGE_KEY, String(until));
    } catch (error) {}
  }

  function create(options) {
    var config = options || {};
    var scope = config.scope || root;
    var now = typeof config.now === "function" ? config.now : Date.now;

    function suppressedUntil() {
      var current = now();
      return Math.max(
        normalizeUntil(readCookie(scope), current),
        normalizeUntil(readStorage(scope), current)
      );
    }

    function remember() {
      var until = now() + TTL_MS;
      writeCookie(scope, until);
      writeStorage(scope, until);
      return until;
    }

    function shouldPrompt() {
      return suppressedUntil() === 0;
    }

    return Object.freeze({
      remember: remember,
      shouldPrompt: shouldPrompt,
      suppressedUntil: suppressedUntil,
    });
  }

  root.AISGStarPromptPolicy = Object.freeze({
    COOKIE_NAME: COOKIE_NAME,
    STORAGE_KEY: STORAGE_KEY,
    TTL_MS: TTL_MS,
    create: create,
    normalizeUntil: normalizeUntil,
  });
})(typeof globalThis !== "undefined" ? globalThis : this);
