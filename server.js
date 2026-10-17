#!/usr/bin/env node
// Quant Terminal server. Node 18+ and nothing else: no npm install, no build step.
//   node server.js            start on http://localhost:3777 (or the next free port)
//   node server.js --open     start and open your browser
//   PORT=4000 node server.js  pick a port

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import net from "node:net";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import * as data from "./lib/providers.js";
import * as info from "./lib/market-info.js";
import { BY_ID, registerIndicator } from "./public/lib/indicators.js";
import { conditionFn } from "./public/lib/backtest.js";
import { relaunchForProxy, proxyNote } from "./lib/proxy.js";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(ROOT, "public");
const CUSTOM = path.join(ROOT, "custom");
const VERSION = JSON.parse(
  fs.readFileSync(path.join(ROOT, "package.json"), "utf8"),
).version;
const PUBLIC_DEMO = process.env.PUBLIC_DEMO === "1";
const PUBLIC_HOST = PUBLIC_DEMO
  ? normalizeConfiguredHost(
      process.env.PUBLIC_HOST || process.env.QT_PUBLIC_HOST || "quant.sisengai.com",
    )
  : null;
// Public mode is deliberately loopback-only. Put Caddy or another TLS proxy in front of it.
const HOST = PUBLIC_DEMO ? "127.0.0.1" : process.env.HOST || "127.0.0.1";
const START_PORT = Number(process.env.PORT) || 3777;
const PUBLIC_RATE_WINDOW_MS = boundedNumber(
  process.env.PUBLIC_RATE_WINDOW_MS,
  60_000,
  1_000,
  3_600_000,
);
const PUBLIC_RATE_MAX = boundedNumber(process.env.PUBLIC_RATE_MAX, 60, 1, 10_000);
const PUBLIC_RATE_MAX_KEYS = boundedNumber(
  process.env.PUBLIC_RATE_MAX_KEYS,
  10_000,
  1,
  100_000,
);
const PUBLIC_CACHE_TTL_MS = boundedNumber(
  process.env.PUBLIC_CACHE_TTL_MS,
  5_000,
  250,
  300_000,
);
const PUBLIC_CACHE_MAX = boundedNumber(process.env.PUBLIC_CACHE_MAX, 128, 8, 2_000);
const PUBLIC_CACHE_MAX_BYTES = boundedNumber(
  process.env.PUBLIC_CACHE_MAX_BYTES,
  512 * 1024,
  16 * 1024,
  5 * 1024 * 1024,
);
const PUBLIC_MAX_URL = 8_192;
const PUBLIC_SCAN_MAX_BODY = 128 * 1024;
const PUBLIC_SCAN_MAX_SYMBOLS = 20;
const PUBLIC_SCAN_MAX_RULES = 5;
const PUBLIC_SCAN_MAX_INDICATORS = 20;
const PUBLIC_QUOTES_MAX_SYMBOLS = 20;
const PUBLIC_QUOTES_RATE_MAX = boundedNumber(
  process.env.PUBLIC_QUOTES_RATE_MAX,
  12,
  1,
  1_000,
);
const PUBLIC_QUOTES_WORK_MAX = boundedNumber(
  process.env.PUBLIC_QUOTES_WORK_MAX,
  120,
  1,
  10_000,
);

function boundedNumber(value, fallback, min, max) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.max(min, Math.min(max, n)) : fallback;
}

function normalizeConfiguredHost(value) {
  const raw = String(value || "").trim().toLowerCase();
  const hostValue = raw.replace(/^https?:\/\//, "");
  if (!hostValue || hostValue.includes("/") || hostValue.includes("@"))
    throw new Error("PUBLIC_HOST must be a hostname or IP address");
  const host = hostValue
    .replace(/^\[|\]$/g, "")
    .replace(/:\d+$/, "");
  if (
    !host ||
    (!net.isIP(host) &&
      !/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/.test(host))
  )
    throw new Error("PUBLIC_HOST must be a hostname or IP address");
  return host;
}

const alerts = PUBLIC_DEMO ? null : await import("./lib/alerts.js");
const store = PUBLIC_DEMO ? null : await import("./lib/store.js");
const ptq = PUBLIC_DEMO ? null : await import("./lib/ptq.js");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
};

// ---------- helpers ----------
const httpError = (status, message) => Object.assign(new Error(message), { status });

const publicResponseCache = new Map();
const publicRate = new Map();
const publicQuoteBudgets = new Map();

const SECURITY_HEADERS = {
  "Content-Security-Policy": [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'self'",
    "form-action 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: blob: https:",
    "connect-src 'self' wss://stream.binance.com:9443 wss://data-stream.binance.vision",
  ].join("; "),
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};

function cacheHeaders(isStr) {
  return {
    ...SECURITY_HEADERS,
    "Content-Type": isStr ? "text/plain; charset=utf-8" : "application/json",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "no-referrer",
  };
}

function prunePublicCache(now = Date.now()) {
  for (const [key, entry] of publicResponseCache) {
    if (entry.expiresAt <= now) publicResponseCache.delete(key);
  }
  while (publicResponseCache.size >= PUBLIC_CACHE_MAX) {
    const oldest = publicResponseCache.keys().next().value;
    if (oldest === undefined) break;
    publicResponseCache.delete(oldest);
  }
}

function replayPublicCache(res, entry, headers = {}) {
  res.writeHead(entry.status, {
    ...entry.headers,
    ...headers,
    "X-Qt-Cache": "HIT",
  });
  res.end(entry.body);
}

function send(res, status, body, headers = {}) {
  const isStr = typeof body === "string" || Buffer.isBuffer(body);
  const payload = isStr ? body : JSON.stringify(body);
  const responseHeaders = {
    ...cacheHeaders(isStr),
    ...headers,
  };
  const cacheKey = res.__qtPublicCacheKey;
  if (PUBLIC_DEMO && cacheKey && status === 200) {
    const bytes = Buffer.byteLength(payload);
    if (bytes <= PUBLIC_CACHE_MAX_BYTES) {
      prunePublicCache();
      responseHeaders["X-Qt-Cache"] = "MISS";
      publicResponseCache.set(cacheKey, {
        status,
        body: payload,
        headers: responseHeaders,
        expiresAt: Date.now() + PUBLIC_CACHE_TTL_MS,
      });
    }
  }
  res.writeHead(status, responseHeaders);
  res.end(payload);
}

function normalizeIp(value) {
  return String(value || "")
    .trim()
    .replace(/^\[|\]$/g, "")
    .replace(/^::ffff:/i, "");
}

function isLoopback(value) {
  const ip = normalizeIp(value);
  return ip === "localhost" || ip === "127.0.0.1" || ip === "::1";
}

function clientIp(req) {
  const remote = normalizeIp(req.socket.remoteAddress);
  // Only trust forwarded identity from the loopback reverse proxy. A direct remote caller
  // cannot choose its rate-limit bucket by sending a spoofed X-Forwarded-For header.
  if (isLoopback(remote)) {
    const forwarded = String(req.headers["x-forwarded-for"] || "")
      .split(",")
      .map(normalizeIp)
      .find((ip) => net.isIP(ip));
    if (forwarded) return forwarded;
    const real = normalizeIp(req.headers["x-real-ip"]);
    if (net.isIP(real)) return real;
  }
  return net.isIP(remote) ? remote : "unknown";
}

function publicRateLimit(req) {
  if (!PUBLIC_DEMO || !String(req.url || "").startsWith("/api/")) return null;
  const now = Date.now();
  const key = clientIp(req);
  let entry = publicRate.get(key);
  if (!entry || entry.resetAt <= now) {
    if (entry) publicRate.delete(key);
    while (publicRate.size >= PUBLIC_RATE_MAX_KEYS) {
      const oldest = publicRate.keys().next().value;
      if (oldest === undefined) break;
      publicRate.delete(oldest);
    }
    entry = { count: 0, resetAt: now + PUBLIC_RATE_WINDOW_MS };
    publicRate.set(key, entry);
  }
  entry.count += 1;
  const remaining = Math.max(0, PUBLIC_RATE_MAX - entry.count);
  return {
    limited: entry.count > PUBLIC_RATE_MAX,
    headers: {
      "X-RateLimit-Limit": String(PUBLIC_RATE_MAX),
      "X-RateLimit-Remaining": String(remaining),
      "X-RateLimit-Reset": String(Math.ceil(entry.resetAt / 1000)),
    },
  };
}

function publicQuoteBudget(req, symbolCount) {
  if (!PUBLIC_DEMO) return null;
  const now = Date.now();
  const key = clientIp(req);
  let entry = publicQuoteBudgets.get(key);
  if (!entry || entry.resetAt <= now) {
    if (entry) publicQuoteBudgets.delete(key);
    while (publicQuoteBudgets.size >= PUBLIC_RATE_MAX_KEYS) {
      const oldest = publicQuoteBudgets.keys().next().value;
      if (oldest === undefined) break;
      publicQuoteBudgets.delete(oldest);
    }
    entry = { requests: 0, work: 0, resetAt: now + PUBLIC_RATE_WINDOW_MS };
    publicQuoteBudgets.set(key, entry);
  }
  entry.requests += 1;
  entry.work += symbolCount;
  return {
    limited:
      entry.requests > PUBLIC_QUOTES_RATE_MAX ||
      entry.work > PUBLIC_QUOTES_WORK_MAX,
    headers: {
      "X-Qt-Route-Limit": `${PUBLIC_QUOTES_RATE_MAX} requests / ${PUBLIC_QUOTES_WORK_MAX} symbols`,
      "X-Qt-Route-Remaining": String(
        Math.max(0, PUBLIC_QUOTES_WORK_MAX - entry.work),
      ),
      "X-Qt-Route-Reset": String(Math.ceil(entry.resetAt / 1000)),
    },
  };
}

async function readBody(req, limit = 2e6) {
  let size = 0;
  const chunks = [];
  for await (const c of req) {
    size += c.length;
    if (size > limit)
      throw Object.assign(new Error("Request too large"), { status: 413 });
    chunks.push(c);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  if (!text) return {};
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    throw httpError(400, "The request body isn't valid JSON");
  }
  if (!body || typeof body !== "object" || Array.isArray(body))
    throw httpError(400, "The request body must be a JSON object");
  return body;
}

const PUBLIC_SCAN_PRICE_FIELDS = new Set([
  "open",
  "high",
  "low",
  "close",
  "volume",
  "hl2",
  "hlc3",
  "ohlc4",
  "hlcc4",
]);
const PUBLIC_SCAN_OPERATORS = new Set([
  ">",
  "<",
  ">=",
  "<=",
  "crossesAbove",
  "crossesBelow",
  "crosses",
]);
const PUBLIC_SCAN_INDICATOR_IDS = new Set(Object.keys(BY_ID));
const PUBLIC_SCAN_MAX_INT = 1_000;
const PUBLIC_SCAN_MAX_FLOAT = 1_000_000;
const PUBLIC_SCAN_MAX_NUMBER = 1e12;

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function invalidPublicScan(message) {
  throw httpError(400, `Invalid public scan: ${message}`);
}

function validatePublicScanOperand(value, indicators, label) {
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Math.abs(value) > PUBLIC_SCAN_MAX_NUMBER)
      invalidPublicScan(`${label} must be a finite number within the supported range`);
    return;
  }
  if (typeof value !== "string" || value.length === 0 || value.length > 128)
    invalidPublicScan(`${label} must be a supported price field, indicator output, or number`);
  if (PUBLIC_SCAN_PRICE_FIELDS.has(value)) return;
  const [key, output, ...extra] = value.split(".");
  if (
    extra.length ||
    !/^[A-Za-z0-9_-]{1,64}$/.test(key) ||
    ["__proto__", "constructor", "prototype"].includes(key)
  )
    invalidPublicScan(`${label} is not a valid indicator reference`);
  const spec = indicators[key];
  if (!spec) invalidPublicScan(`${label} references an unknown indicator`);
  const outputs = new Set((BY_ID[spec.id].outputs || []).map((o) => o.key));
  if (spec.id === "supertrend") outputs.add("direction");
  if (output && !outputs.has(output))
    invalidPublicScan(`${label} references an unknown indicator output`);
}

function validatePublicIndicator(id, params, label) {
  if (typeof id !== "string" || !PUBLIC_SCAN_INDICATOR_IDS.has(id))
    invalidPublicScan(`${label} must use a built-in indicator`);
  if (params == null) return {};
  if (!isPlainObject(params)) invalidPublicScan(`${label}.params must be an object`);
  const def = BY_ID[id];
  const inputs = new Map((def.inputs || []).map((input) => [input.key, input]));
  const keys = Object.keys(params);
  if (keys.length > inputs.size)
    invalidPublicScan(`${label}.params has too many parameters`);
  const safe = {};
  for (const key of keys) {
    const input = inputs.get(key);
    if (!input) invalidPublicScan(`${label}.params.${key} is not supported`);
    const value = params[key];
    if (input.type === "int") {
      const min = Number.isFinite(input.min) ? input.min : 1;
      const max = Math.min(
        Number.isFinite(input.max) ? input.max : PUBLIC_SCAN_MAX_INT,
        PUBLIC_SCAN_MAX_INT,
      );
      if (!Number.isSafeInteger(value) || value < min || value > max)
        invalidPublicScan(`${label}.params.${key} must be an integer from ${min} to ${max}`);
    } else if (input.type === "float") {
      const min = Number.isFinite(input.min) ? input.min : -PUBLIC_SCAN_MAX_FLOAT;
      const max = Math.min(
        Number.isFinite(input.max) ? input.max : PUBLIC_SCAN_MAX_FLOAT,
        PUBLIC_SCAN_MAX_FLOAT,
      );
      if (!Number.isFinite(value) || value < min || value > max)
        invalidPublicScan(`${label}.params.${key} must be a finite number from ${min} to ${max}`);
    } else if (input.type === "source") {
      if (typeof value !== "string" || !PUBLIC_SCAN_PRICE_FIELDS.has(value))
        invalidPublicScan(`${label}.params.${key} must be a supported price source`);
    } else if (input.type === "select") {
      if (typeof value !== "string" || !input.options?.includes(value))
        invalidPublicScan(`${label}.params.${key} must be one of the supported options`);
    } else if (input.type === "time") {
      if (!Number.isSafeInteger(value) || value < 0 || value > 4_102_444_800)
        invalidPublicScan(`${label}.params.${key} must be a bounded timestamp`);
    } else {
      invalidPublicScan(`${label}.params.${key} has an unsupported type`);
    }
    safe[key] = value;
  }
  return safe;
}

export function validatePublicScan(body) {
  if (!isPlainObject(body)) invalidPublicScan("the body must be an object");
  if (!Array.isArray(body.symbols)) invalidPublicScan("symbols must be an array");
  if (body.symbols.length > PUBLIC_SCAN_MAX_SYMBOLS)
    invalidPublicScan(`at most ${PUBLIC_SCAN_MAX_SYMBOLS} symbols are allowed`);
  const symbols = body.symbols.map((symbol, i) => {
    if (typeof symbol !== "string" || symbol.length === 0 || symbol.length > 128)
      invalidPublicScan(`symbols[${i}] must be a non-empty string of at most 128 characters`);
    return symbol;
  });
  const rules = body.rules ?? [];
  if (!Array.isArray(rules)) invalidPublicScan("rules must be an array");
  if (rules.length > PUBLIC_SCAN_MAX_RULES)
    invalidPublicScan(`at most ${PUBLIC_SCAN_MAX_RULES} rules are allowed`);
  const rawIndicators = body.indicators ?? {};
  if (!isPlainObject(rawIndicators)) invalidPublicScan("indicators must be an object");
  const indicatorKeys = Object.keys(rawIndicators);
  if (indicatorKeys.length > PUBLIC_SCAN_MAX_INDICATORS)
    invalidPublicScan(`at most ${PUBLIC_SCAN_MAX_INDICATORS} indicators are allowed`);
  const indicators = Object.create(null);
  for (const key of indicatorKeys) {
    if (
      !/^[A-Za-z0-9_-]{1,64}$/.test(key) ||
      ["__proto__", "constructor", "prototype"].includes(key)
    )
      invalidPublicScan("indicator keys must be short names");
    const spec = rawIndicators[key];
    if (!isPlainObject(spec)) invalidPublicScan(`indicators.${key} must be an object`);
    indicators[key] = {
      id: spec.id,
      params: validatePublicIndicator(spec.id, spec.params, `indicators.${key}`),
    };
  }
  for (const [i, rule] of rules.entries()) {
    if (!isPlainObject(rule) || !PUBLIC_SCAN_OPERATORS.has(rule.op))
      invalidPublicScan(`rules[${i}] has an unsupported operator`);
    validatePublicScanOperand(rule.left, indicators, `rules[${i}].left`);
    validatePublicScanOperand(rule.right, indicators, `rules[${i}].right`);
  }
  if (body.tf !== undefined && (typeof body.tf !== "string" || body.tf.length > 16))
    invalidPublicScan("tf must be a short timeframe string");
  return { symbols, rules, indicators, tf: body.tf || "1D" };
}

// The local app only answers to local/network hosts and requires the app header for writes.
// Public demo mode accepts exactly the configured reverse-proxy Host and only exposes its route
// allowlist below. Origin is checked when a browser supplies one; curl-style requests remain valid.
function allowed(req) {
  const host = (req.headers.host || "")
    .replace(/:\d+$/, "")
    .replace(/^\[|\]$/g, "")
    .toLowerCase();
  if (PUBLIC_DEMO) {
    if (host !== PUBLIC_HOST) return false;
    const origin = req.headers.origin;
    if (origin) {
      try {
        if (new URL(origin).host.replace(/:\d+$/, "").toLowerCase() !== PUBLIC_HOST)
          return false;
      } catch {
        return false;
      }
    }
    return true;
  }
  const okHosts = new Set(["localhost", "127.0.0.1", "::1", ...lanAddresses()]);
  if (!okHosts.has(host)) return false;
  if (req.method !== "GET" && req.method !== "HEAD") {
    if (req.headers["x-qt"] !== "1") return false;
    const origin = req.headers.origin;
    if (origin) {
      try {
        if (new URL(origin).host !== req.headers.host) return false;
      } catch {
        return false; // "null" and other opaque origins
      }
    }
  }
  return true;
}

function lanAddresses() {
  if (HOST === "127.0.0.1" || HOST === "localhost") return [];
  return Object.values(os.networkInterfaces())
    .flat()
    .filter(Boolean)
    .map((i) => i.address);
}

function serveStatic(res, baseDir, rel) {
  const file = path.normalize(path.join(baseDir, rel));
  if (!file.startsWith(baseDir + path.sep)) return send(res, 403, "Forbidden");
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) return send(res, 404, "Not found");
    if (PUBLIC_DEMO && baseDir === PUBLIC && rel === "index.html") {
      fs.readFile(file, "utf8", (readErr, text) => {
        if (readErr) return send(res, 404, "Not found");
        const html = text.replace(
          "window.QUANT_TERMINAL_PUBLIC_DEMO = false",
          "window.QUANT_TERMINAL_PUBLIC_DEMO = true",
        );
        res.writeHead(200, {
          ...cacheHeaders(true),
          "Content-Type": MIME[".html"],
          "Cache-Control": "no-cache",
        });
        res.end(html);
      });
      return;
    }
    res.writeHead(200, {
      ...cacheHeaders(true),
      "Content-Type": MIME[path.extname(file)] || "application/octet-stream",
      "Cache-Control": rel.startsWith("vendor/")
        ? "public, max-age=86400"
        : "no-cache",
    });
    fs.createReadStream(file).pipe(res);
  });
}

// ---------- custom indicators (your own "Pine scripts", as plain JS files in /custom) ----------
const slug = (s) =>
  String(s)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 60) || "indicator";
const customErrors = {};

function listCustom() {
  fs.mkdirSync(CUSTOM, { recursive: true });
  return fs
    .readdirSync(CUSTOM)
    .filter((f) => f.endsWith(".js"))
    .map((f) => ({
      file: f,
      id: `custom:${f.replace(/\.js$/, "")}`,
      mtime: fs.statSync(path.join(CUSTOM, f)).mtimeMs,
      error: customErrors[f] || null,
    }));
}

async function loadCustom(file) {
  try {
    const full = path.join(CUSTOM, file);
    const mod = await import(
      `${pathToFileURL(full).href}?v=${fs.statSync(full).mtimeMs}`
    );
    registerIndicator({
      ...mod.default,
      id: `custom:${file.replace(/\.js$/, "")}`,
    });
    delete customErrors[file];
  } catch (e) {
    customErrors[file] = e.message;
  }
}

// ---------- server-sent events (alerts pop up in the browser) ----------
const clients = new Set();
function broadcast(type, payload) {
  const msg = `event: ${type}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const res of clients) res.write(msg);
}
if (!PUBLIC_DEMO) alerts.onFire((e) => broadcast("alert", e));
if (!PUBLIC_DEMO) setInterval(() => {
  for (const res of clients) res.write(": keep-alive\n\n");
}, 25000).unref();

async function mapLimit(items, n, fn) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(n, items.length) }, async () => {
      while (i < items.length) {
        const k = i++;
        out[k] = await fn(items[k], k);
      }
    }),
  );
  return out;
}

// ---------- routes ----------
const PUBLIC_READ_ROUTES = new Set([
  "/api/health",
  "/api/resolve",
  "/api/search",
  "/api/spread",
  "/api/candles",
  "/api/quotes",
  "/api/calendar",
  "/api/earnings",
  "/api/dividends",
  "/api/news",
  "/api/financials",
  "/api/screener",
]);

function publicRouteAllowed(req, pathname) {
  if (PUBLIC_READ_ROUTES.has(pathname))
    return req.method === "GET" || req.method === "HEAD";
  if (pathname === "/api/scan") return req.method === "POST";
  return false;
}

async function handle(req, res) {
  if (!allowed(req))
    return send(
      res,
      403,
      "Forbidden: Quant Terminal only answers to this computer.",
    );
  if (PUBLIC_DEMO && String(req.url || "").length > PUBLIC_MAX_URL)
    return send(res, 414, { error: "Request URL is too long" });
  const rate = publicRateLimit(req);
  if (rate?.limited)
    return send(res, 429, { error: "Too many requests" }, {
      ...rate.headers,
      "Retry-After": String(Math.max(1, Math.ceil((Number(rate.headers["X-RateLimit-Reset"]) * 1000 - Date.now()) / 1000))),
    });
  const url = new URL(req.url, "http://localhost");
  let p;
  try {
    p = decodeURIComponent(url.pathname);
  } catch {
    return send(res, 400, "Bad URL");
  }
  const q = Object.fromEntries(url.searchParams);
  let responseHeaders = rate?.headers;
  let publicQuoteSymbols = null;
  if (PUBLIC_DEMO && p === "/api/quotes" && (req.method === "GET" || req.method === "HEAD")) {
    publicQuoteSymbols = [
      ...new Set(String(q.symbols || "").split(",").filter(Boolean)),
    ];
    if (publicQuoteSymbols.length > PUBLIC_QUOTES_MAX_SYMBOLS)
      return send(
        res,
        400,
        { error: `Public quotes allow at most ${PUBLIC_QUOTES_MAX_SYMBOLS} symbols` },
        responseHeaders,
      );
    const budget = publicQuoteBudget(req, publicQuoteSymbols.length);
    responseHeaders = { ...responseHeaders, ...budget.headers };
    if (budget.limited)
      return send(
        res,
        429,
        { error: "Quote route budget exceeded; retry later" },
        {
          ...responseHeaders,
          "Retry-After": String(
            Math.max(
              1,
              Math.ceil(
                (Number(budget.headers["X-Qt-Route-Reset"]) * 1000 - Date.now()) / 1000,
              ),
            ),
          ),
        },
      );
  }

  if (PUBLIC_DEMO && p.startsWith("/api/") && !publicRouteAllowed(req, p))
    return send(res, 403, { error: "This route is disabled in public demo mode" }, rate?.headers);

  if (!p.startsWith("/api/")) {
    if (p === "/" || p === "/index.html")
      return serveStatic(res, PUBLIC, "index.html");
    if (p === "/custom" || p.startsWith("/custom/"))
      return PUBLIC_DEMO
        ? send(res, 403, "Custom indicators are disabled in public demo mode")
        : serveStatic(res, CUSTOM, p.slice(8));
    return serveStatic(res, PUBLIC, p.slice(1));
  }

  if (PUBLIC_DEMO && req.method === "GET" && PUBLIC_READ_ROUTES.has(p)) {
    const cacheKey = `${req.method}:${req.url}`;
    const entry = publicResponseCache.get(cacheKey);
    if (entry && entry.expiresAt > Date.now()) return replayPublicCache(res, entry, responseHeaders);
    if (entry) publicResponseCache.delete(cacheKey);
    res.__qtPublicCacheKey = cacheKey;
  }

  try {
    if (p === "/api/health") {
      if (PUBLIC_DEMO)
        return send(res, 200, {
          ok: true,
          app: "quant-terminal",
          mode: "public-demo",
          version: VERSION,
          node: process.version,
          platform: process.platform,
          providers: data.health,
          yahoo: data.yahooAvailable() ? "available" : "rate limited",
        }, rate?.headers);
      return send(res, 200, {
        ok: true,
        app: "quant-terminal",
        root: ROOT,
        version: VERSION,
        node: process.version,
        platform: process.platform,
        providers: data.health,
        yahoo: data.yahooAvailable() ? "available" : "rate limited",
        alerts: alerts.list().filter((a) => a.active).length,
      });
    }
    if (p === "/api/probe") return send(res, 200, await data.probeAll());
    if (p === "/api/resolve")
      return send(res, 200, await data.resolve(q.symbol), rate?.headers);
    if (p === "/api/search") {
      if (PUBLIC_DEMO && String(q.q || "").length > 80)
        throw httpError(400, "Search query is too long");
      return send(res, 200, await data.search(q.q), rate?.headers);
    }
    if (p === "/api/spread") return send(res, 200, await data.getSpread(q.symbol), rate?.headers);
    if (p === "/api/candles")
      return send(
        res,
        200,
        await data.getCandles(
          q.symbol,
          q.tf || "1D",
          PUBLIC_DEMO ? Math.min(Number(q.limit) || 1000, 1000) : q.limit,
        ),
        rate?.headers,
      );
    if (p === "/api/quotes")
      return send(
        res,
        200,
        await data.getQuotes(
          publicQuoteSymbols ||
            [...new Set((q.symbols || "").split(",").filter(Boolean))].slice(0, 200),
        ),
        responseHeaders,
      );
    if (p === "/api/calendar")
      return send(res, 200, await data.economicCalendar(), rate?.headers);
    if (p === "/api/earnings") return send(res, 200, await info.earnings(Number(q.days) || 5), rate?.headers);
    if (p === "/api/dividends") return send(res, 200, await info.dividends(Number(q.days) || 5), rate?.headers);
    if (p === "/api/news") return send(res, 200, await info.news(q.symbol), rate?.headers);
    if (p === "/api/financials") return send(res, 200, await info.financials(q.symbol, q.frequency), rate?.headers);
    if (p === "/api/screener") {
      const u = q.universe || "crypto";
      const rows =
        u === "crypto"
          ? await data.cryptoScreener()
          : await data.nasdaqScreener(u === "etf" ? "etf" : "stocks");
      return send(res, 200, rows, rate?.headers);
    }
    if (p === "/api/scan" && req.method === "POST") {
      const body = await readBody(req, PUBLIC_DEMO ? PUBLIC_SCAN_MAX_BODY : 2e6);
      if (!Array.isArray(body.symbols) || !Array.isArray(body.rules ?? []))
        throw httpError(400, "Send { symbols: [...], rules: [...] }");
      const scan = PUBLIC_DEMO ? validatePublicScan(body) : body;
      const maxSymbols = PUBLIC_DEMO ? PUBLIC_SCAN_MAX_SYMBOLS : 150;
      const maxRules = PUBLIC_DEMO ? PUBLIC_SCAN_MAX_RULES : 1000;
      const symbols = scan.symbols.slice(0, maxSymbols);
      if (scan.symbols.length > maxSymbols)
        throw httpError(400, `Public scans allow at most ${maxSymbols} symbols`);
      const rules = scan.rules || [];
      if (rules.length > maxRules)
        throw httpError(400, `Public scans allow at most ${maxRules} rules`);
      const results = await mapLimit(symbols, 4, async (symbol) => {
        try {
          const { candles } = await data.getCandles(
            symbol,
            scan.tf || "1D",
            400,
          );
          const make = conditionFn(candles, scan.indicators || {});
          const i = candles.length - 1;
          const passes = rules.map((r) => make(r)(i));
          return {
            symbol,
            pass: passes.every(Boolean),
            passes,
            close: candles[i].close,
          };
        } catch (e) {
          return { symbol, error: e.message };
        }
      });
      return send(res, 200, results, rate?.headers);
    }
    if (p === "/api/state") {
      if (req.method === "GET") return send(res, 200, store.read("state", {}));
      if (req.method === "PUT") {
        const patch = await readBody(req, 20e6);
        const next = { ...store.read("state", {}), ...patch };
        store.write("state", next);
        return send(res, 200, { ok: true });
      }
    }
    if (p === "/api/events") {
      res.writeHead(200, {
        ...SECURITY_HEADERS,
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      });
      res.write("retry: 3000\n\n");
      clients.add(res);
      req.on("close", () => clients.delete(res));
      return;
    }
    if (p === "/api/alerts") {
      if (req.method === "GET") return send(res, 200, alerts.list());
      if (req.method === "POST")
        return send(res, 200, alerts.add(await readBody(req)));
    }
    if (p === "/api/alerts/log") return send(res, 200, alerts.history());
    if (p === "/api/alerts/check" && req.method === "POST") {
      await alerts.evaluate();
      return send(res, 200, { ok: true });
    }
    if (p.startsWith("/api/alerts/")) {
      const id = p.split("/")[3];
      if (req.method === "DELETE") {
        alerts.remove(id);
        return send(res, 200, { ok: true });
      }
      if (req.method === "PATCH")
        return send(res, 200, alerts.update(id, await readBody(req)));
    }
    if (p === "/api/webhook-test" && req.method === "POST") {
      const { url: hook } = await readBody(req);
      if (!/^https?:\/\/[^\s]+$/i.test(String(hook || "")))
        throw httpError(400, "Webhook must be an http(s) URL");
      const r = await fetch(hook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text: "Quant Terminal test alert",
          content: "Quant Terminal test alert",
        }),
        signal: AbortSignal.timeout(10000),
      });
      return send(res, 200, { ok: r.ok, status: r.status });
    }
    if (p === "/api/custom") {
      if (req.method === "GET") return send(res, 200, listCustom());
      if (req.method === "POST") {
        const { name, code } = await readBody(req);
        if (!code || !/export\s+default/.test(code))
          throw Object.assign(
            new Error(
              "The file must `export default { name, calc(bars, params, ta) { ... } }`",
            ),
            { status: 400 },
          );
        const file = `${slug(name)}.js`;
        fs.mkdirSync(CUSTOM, { recursive: true });
        fs.writeFileSync(path.join(CUSTOM, file), code);
        await loadCustom(file);
        return send(
          res,
          customErrors[file] ? 400 : 200,
          customErrors[file]
            ? { error: customErrors[file], file }
            : { ok: true, file, id: `custom:${file.replace(/\.js$/, "")}` },
        );
      }
    }
    if (p.startsWith("/api/custom/") && req.method === "DELETE") {
      const file = path.basename(p.slice(12));
      fs.rmSync(path.join(CUSTOM, file), { force: true });
      return send(res, 200, { ok: true });
    }
    if (p === "/api/shutdown" && req.method === "POST") {
      // Lets the installer stop a running copy before updating it, on any OS.
      send(res, 200, { ok: true });
      setTimeout(() => process.exit(0), 100);
      return;
    }
    // PTQ connector: reads and fail-safe controls only. There is no route here that arms a
    // strategy or places an order; that stays inside PTQ (`ptq arm-strategy`).
    if (p === "/api/ptq/status") return send(res, 200, await ptq.status());
    if (p === "/api/ptq/overview") return send(res, 200, await ptq.overview());
    if (p === "/api/ptq/check" && req.method === "POST") {
      try {
        return send(res, 200, await ptq.check(await readBody(req)));
      } catch (e) {
        return send(res, e.status || 502, { error: e.message, code: e.code, problems: e.problems || [], notes: e.notes || [] });
      }
    }
    if (p === "/api/ptq/kill-switch" && req.method === "POST") return send(res, 200, await ptq.engageKillSwitch());
    const disarmMatch = /^\/api\/ptq\/arms\/([^/]+)\/disarm$/.exec(p);
    if (disarmMatch && req.method === "POST") return send(res, 200, await ptq.disarm(decodeURIComponent(disarmMatch[1])));
    return send(res, 404, { error: "Unknown endpoint" });
  } catch (e) {
    // Upstream failures are a bad gateway, whatever status the provider used.
    const code = e.upstream ? 502 : e.status >= 400 && e.status < 600 ? e.status : 500;
    return send(res, code, { error: e.message });
  }
}

// ---------- start ----------
function openBrowser(url) {
  const cmd =
    process.platform === "win32"
      ? ["cmd", ["/c", "start", '""', url]]
      : process.platform === "darwin"
        ? ["open", [url]]
        : ["xdg-open", [url]];
  try {
    const child = spawn(cmd[0], cmd[1], { detached: true, stdio: "ignore" });
    child.on("error", () => {});
    child.unref();
  } catch {
    /* no desktop: the URL is printed anyway */
  }
}

export function start(port = START_PORT, tries = 20) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      handle(req, res).catch((e) => {
        if (!res.headersSent) send(res, 500, { error: e.message });
      });
    });
    server.once("error", (e) => {
      if (e.code === "EADDRINUSE" && tries > 0)
        resolve(start(port + 1, tries - 1));
      else reject(e);
    });
    server.listen(port, HOST, () => resolve({ server, port }));
  });
}

const isMain =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
const relaunched = isMain ? relaunchForProxy() : null;
if (relaunched) process.exit(await relaunched);
if (isMain) {
  if (!PUBLIC_DEMO)
    for (const c of listCustom()) await loadCustom(c.file);
  const { port } = await start();
  const url = `http://localhost:${port}`;
  if (!PUBLIC_DEMO) alerts.start();
  console.log(
    `\n  Quant Terminal ${VERSION} is running\n\n  Open:  ${url}\n  Stop:  Ctrl+C\n  Data:  ${PUBLIC_DEMO ? "browser localStorage only (public demo)" : store.DATA_DIR}\n`,
  );
  if (proxyNote()) console.log(`  ${proxyNote()}\n`);
  if (HOST !== "127.0.0.1" && HOST !== "localhost")
    console.log(
      `  Also on your network: ${lanAddresses()
        .filter((a) => a.includes(".") && a !== "127.0.0.1")
        .map((a) => `http://${a}:${port}`)
        .join("  ")}\n`,
    );
  if (process.argv.includes("--open") || process.env.QT_OPEN === "1")
    openBrowser(url);
  const bye = () => {
    console.log("\n  Stopped.");
    process.exit(0);
  };
  process.on("SIGINT", bye);
  process.on("SIGTERM", bye);
}
