import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const PUBLIC_HOST = "quant.sisengai.com";
let child;
let base;
let dataDir;

function startServer(extra = {}) {
  return new Promise((resolve, reject) => {
    const port = 42000 + Math.floor(Math.random() * 1000);
    child = spawn(process.execPath, ["server.js"], {
      cwd: ROOT,
      env: {
        ...process.env,
        QT_OFFLINE: "1",
        QT_DATA_DIR: dataDir,
        PORT: String(port),
        PUBLIC_DEMO: "1",
        PUBLIC_HOST,
        PUBLIC_RATE_MAX: "100",
        PUBLIC_RATE_WINDOW_MS: "60000",
        ...extra,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    const timer = setTimeout(() => {
      reject(new Error(`public server did not start\nstdout: ${out}\nstderr: ${err}`));
    }, 5000);
    child.stdout.on("data", (chunk) => {
      out += chunk;
      const match = /Open:\s+http:\/\/localhost:(\d+)/.exec(out);
      if (!match) return;
      clearTimeout(timer);
      base = `http://127.0.0.1:${match[1]}`;
      resolve();
    });
    child.stderr.on("data", (chunk) => {
      err += chunk;
    });
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("exit", (code, signal) => {
      if (!base && !timer._destroyed)
        reject(new Error(`public server exited (${code ?? signal})\n${err}`));
    });
  });
}

async function stopServer() {
  if (!child || child.exitCode !== null) return;
  const exited = new Promise((resolve) => child.once("exit", resolve));
  child.kill("SIGTERM");
  await exited;
  child = null;
  base = null;
}

async function request(url, init = {}, host = PUBLIC_HOST) {
  const target = new URL(`${base}${url}`);
  const body = init.body;
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: target.hostname,
        port: target.port,
        path: `${target.pathname}${target.search}`,
        method: init.method || "GET",
        headers: { Host: host, ...(init.headers || {}) },
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          const bodyText = Buffer.concat(chunks).toString("utf8");
          resolve({
            status: res.statusCode,
            headers: new Headers(res.headers),
            text: async () => bodyText,
            json: async () => JSON.parse(bodyText),
          });
        });
      },
    );
    req.on("error", reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "qt-public-test-"));
  fs.writeFileSync(
    path.join(dataDir, "state.json"),
    JSON.stringify({ secret: "must-not-be-served", watchlists: { Shared: ["US:SECRET"] } }),
  );
  await startServer();
});

after(async () => {
  await stopServer();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test("public mode requires the configured host and marks the app", async () => {
  const denied = await request("/api/health", {}, "localhost");
  assert.equal(denied.status, 403);
  const wrong = await request("/api/health", {}, "quant.sisengai.com.evil");
  assert.equal(wrong.status, 403);

  const page = await (await request("/")).text();
  assert.match(page, /QUANT_TERMINAL_PUBLIC_DEMO\s*=\s*true/);
  const health = await (await request("/api/health")).json();
  assert.equal(health.mode, "public-demo");
  assert.equal("root" in health, false);
  assert.equal("alerts" in health, false);
});

test("public responses include baseline security headers", async () => {
  const page = await request("/");
  assert.equal(page.status, 200);
  assert.equal(page.headers.get("x-content-type-options"), "nosniff");
  assert.equal(page.headers.get("x-frame-options"), "SAMEORIGIN");
  assert.equal(page.headers.get("referrer-policy"), "no-referrer");
  const csp = page.headers.get("content-security-policy");
  assert.ok(csp);
  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /script-src 'self' 'unsafe-inline'/);
  assert.match(csp, /style-src 'self' 'unsafe-inline' https:\/\/fonts\.googleapis\.com/);
  assert.match(csp, /font-src 'self' https:\/\/fonts\.gstatic\.com/);
  assert.match(csp, /connect-src 'self' wss:\/\/stream\.binance\.com:9443 wss:\/\/data-stream\.binance\.vision/);
  assert.match(csp, /object-src 'none'/);
  assert.match(csp, /frame-ancestors 'self'/);
});

test("toast content treats untrusted errors as text and keeps safe markup explicit", async () => {
  const appSource = fs.readFileSync(path.join(ROOT, "public/js/app.js"), "utf8");
  assert.match(appSource, /setToastContent\(el, message\)/);
  assert.match(appSource, /toastHtml\(html, kind = "", ms = 3500\)/);
  assert.ok(appSource.includes("this.toastHtml(`<b>Alert</b><br>\${esc(e.text)}`"));
  assert.doesNotMatch(appSource, /toast\(html, kind = "", ms = 3500\)[\s\S]*?el\.innerHTML\s*=\s*html/);

  const { setToastContent } = await import("../public/js/toast.js");
  const el = { innerHTML: "", textContent: "" };
  setToastContent(el, '<img src=x onerror="alert(1)">');
  assert.equal(el.textContent, '<img src=x onerror="alert(1)">');
  assert.equal(el.innerHTML, "");
  setToastContent(el, "<b>Alert</b><br>safe", { trustedHtml: true });
  assert.equal(el.innerHTML, "<b>Alert</b><br>safe");
});

test("public scans validate built-in indicators and bounded parameters", async () => {
  const tooLarge = await request("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      symbols: ["BTCUSDT"],
      indicators: { slow: { id: "alma", params: { length: 1001 } } },
      rules: [{ left: "slow", op: ">", right: 0 }],
    }),
  });
  assert.equal(tooLarge.status, 400);
  assert.match(await tooLarge.text(), /length/);

  const unknownParam = await request("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      symbols: ["BTCUSDT"],
      indicators: { r: { id: "rsi", params: { nope: 14 } } },
      rules: [{ left: "r", op: ">", right: 0 }],
    }),
  });
  assert.equal(unknownParam.status, 400);

  const unknownIndicator = await request("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      symbols: ["BTCUSDT"],
      indicators: { evil: { id: "custom:evil", params: {} } },
      rules: [{ left: "evil", op: ">", right: 0 }],
    }),
  });
  assert.equal(unknownIndicator.status, 400);
});

test("public quotes cap symbols before upstream work", async () => {
  const symbols = Array.from({ length: 21 }, (_, i) => `BINANCE:TEST${i}USDT`);
  const res = await request(`/api/quotes?symbols=${encodeURIComponent(symbols.join(","))}`);
  assert.equal(res.status, 400);
  assert.match(await res.text(), /at most 20 symbols/);
});

test("public mode denies shared state, alerts, code, PTQ, webhooks and shutdown", async () => {
  const denied = [
    ["GET", "/api/state"],
    ["PUT", "/api/state"],
    ["GET", "/api/alerts"],
    ["POST", "/api/alerts"],
    ["GET", "/api/alerts/log"],
    ["POST", "/api/alerts/check"],
    ["GET", "/api/events"],
    ["GET", "/api/custom"],
    ["POST", "/api/custom"],
    ["DELETE", "/api/custom/example.js"],
    ["GET", "/custom/ema-ribbon-squeeze.js"],
    ["GET", "/api/ptq/status"],
    ["POST", "/api/ptq/kill-switch"],
    ["POST", "/api/webhook-test"],
    ["POST", "/api/shutdown"],
    ["GET", "/api/probe"],
  ];
  for (const [method, url] of denied) {
    const res = await request(url, {
      method,
      headers: { "Content-Type": "application/json", "x-qt": "1" },
      body: method === "GET" || method === "DELETE" ? undefined : "{}",
    });
    assert.equal(res.status, 403, `${method} ${url}`);
  }

  const state = fs.readFileSync(path.join(dataDir, "state.json"), "utf8");
  assert.match(state, /must-not-be-served/);
  assert.match(state, /US:SECRET/);
});

test("public computation is bounded", async () => {
  const tooMany = await request("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      symbols: Array.from({ length: 21 }, () => "BTCUSDT"),
      rules: [],
    }),
  });
  assert.equal(tooMany.status, 400);

  const tooManyRules = await request("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      symbols: ["BTCUSDT"],
      rules: Array.from({ length: 6 }, () => ({ left: "close", op: ">", right: 0 })),
    }),
  });
  assert.equal(tooManyRules.status, 400);
});

test("public market responses are cached and rate limited", async () => {
  await stopServer();
  await startServer({ PUBLIC_CACHE_MAX: "8" });
  for (let limit = 10; limit < 19; limit++) {
    const res = await request(`/api/candles?symbol=BTCUSDT&tf=1D&limit=${limit}`);
    assert.equal(res.status, 200);
  }
  const evicted = await request("/api/candles?symbol=BTCUSDT&tf=1D&limit=10");
  assert.equal(evicted.headers.get("x-qt-cache"), "MISS");

  await stopServer();
  await startServer({ PUBLIC_RATE_MAX: "2", PUBLIC_RATE_WINDOW_MS: "60000" });
  const url = "/api/candles?symbol=BTCUSDT&tf=1D&limit=20";
  const first = await request(url);
  assert.equal(first.status, 200);
  assert.equal(first.headers.get("x-qt-cache"), "MISS");
  const firstBody = await first.text();

  const second = await request(url);
  assert.equal(second.status, 200);
  assert.equal(second.headers.get("x-qt-cache"), "HIT");
  assert.equal(await second.text(), firstBody);

  const limited = await request(url);
  assert.equal(limited.status, 429);
  assert.match(await limited.text(), /Too many requests/);

  const otherClient = await request(url, {
    headers: { "X-Forwarded-For": "203.0.113.8" },
  });
  assert.equal(otherClient.status, 200);
});

test("public rate-limit buckets have a hard maximum", async () => {
  await stopServer();
  await startServer({
    PUBLIC_RATE_MAX: "1",
    PUBLIC_RATE_MAX_KEYS: "2",
    PUBLIC_RATE_WINDOW_MS: "60000",
  });
  const url = "/api/health";
  const from = (ip) => request(url, { headers: { "X-Forwarded-For": ip } });
  assert.equal((await from("203.0.113.1")).status, 200);
  assert.equal((await from("203.0.113.2")).status, 200);
  assert.equal((await from("203.0.113.3")).status, 200);
  // With a 2-key cap, adding the third client must evict one prior bucket.
  assert.equal((await from("203.0.113.1")).status, 200);
});

test("public screener uses the public scan limit", () => {
  const panels = fs.readFileSync(path.join(ROOT, "public/js/panels.js"), "utf8");
  assert.match(panels, /const scanLimit = app\.publicDemo \? 20 : 100/);
  assert.match(panels, /Scan top \$\{scanLimit\}/);
  assert.match(panels, /\.slice\(0, scanLimit\)/);
});

test("public quotes enforce a weighted per-route upstream-work budget", async () => {
  await stopServer();
  await startServer({
    PUBLIC_QUOTES_WORK_MAX: "15",
    PUBLIC_QUOTES_RATE_MAX: "50",
  });
  const symbols = Array.from({ length: 8 }, (_, i) => `BINANCE:BUDGET${i}USDT`);
  const url = `/api/quotes?symbols=${encodeURIComponent(symbols.join(","))}`;
  const headers = { "X-Forwarded-For": "203.0.113.55" };
  const first = await request(url, { headers });
  assert.equal(first.status, 200);
  const second = await request(url, { headers });
  assert.equal(second.status, 429);
  assert.match(await second.text(), /quote|upstream|budget/i);

  // HEAD must not bypass the route-specific budget while still reaching the provider.
  const head = await request(url, { method: "HEAD", headers });
  assert.equal(head.status, 429);
});
