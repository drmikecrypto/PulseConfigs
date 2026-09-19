/**
 * PulseConfigs Cloudflare Worker — short-TTL mirror + probe forward + pool refresh.
 *
 * Bindings / vars (wrangler.toml):
 *   ORIGIN_BASE   = https://raw.githubusercontent.com/drmikecrypto/PulseConfigs/main
 *   COLLECTOR_URL = https://your-de-vps.example.com   (optional)
 *   PROBE_SECRET  = shared secret for POST /probes/iran
 *   GITHUB_TOKEN  = fine-grained PAT with Actions:write for repository_dispatch (secret)
 *   GITHUB_REPO   = drmikecrypto/PulseConfigs
 *
 * Deploy: cd deploy/cloudflare-worker && npx wrangler deploy
 *         npx wrangler secret put GITHUB_TOKEN
 */
const DEFAULT_ORIGIN = "https://raw.githubusercontent.com/drmikecrypto/PulseConfigs/main";
const DEFAULT_REPO = "drmikecrypto/PulseConfigs";
const TTL_SECONDS = 180;
const REFRESH_COOLDOWN_MS = 15 * 60 * 1000;

/** @type {Map<string, number>} */
const refreshByIp = new Map();

const ALLOWED = new Set([
  "top5.txt",
  "top5_speed.txt",
  "top5_iran.txt",
  "top100.txt",
  "index.json",
  "health.json",
  "candidates.json",
  "candidates.txt",
  "verified/configs.txt",
  "verified/configs_base64.txt",
  "fast/configs_base64.txt",
  "secure/configs_base64.txt",
  "features/reality.txt",
  "features/vision.txt",
]);

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Pulse-Secret",
  };
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    const url = new URL(request.url);
    const path = url.pathname.replace(/^\/+/, "");

    if (request.method === "POST" && (path === "probes/iran" || path === "api/probes/iran")) {
      return forwardProbe(request, env);
    }

    if (request.method === "POST" && (path === "refresh" || path === "api/refresh")) {
      return handleRefresh(request, env);
    }

    if (request.method !== "GET") {
      return json({ error: "method not allowed" }, 405);
    }

    if (!path || path === "health") {
      return json(
        {
          ok: true,
          service: "pulseconfigs-worker",
          ttl_seconds: TTL_SECONDS,
          origin: env.ORIGIN_BASE || DEFAULT_ORIGIN,
          refresh: true,
        },
        200
      );
    }

    if (!ALLOWED.has(path)) {
      return json({ error: "path not mirrored", path }, 404);
    }

    const origin = (env.ORIGIN_BASE || DEFAULT_ORIGIN).replace(/\/$/, "");
    const upstream = `${origin}/${path}`;
    const upstreamResp = await fetch(upstream, {
      cf: { cacheTtl: TTL_SECONDS, cacheEverything: true },
      headers: { "User-Agent": "PulseConfigs-Worker/1.0" },
    });

    if (!upstreamResp.ok) {
      return json({ error: "upstream failed", status: upstreamResp.status, upstream }, upstreamResp.status);
    }

    const body = await upstreamResp.arrayBuffer();
    const ctype =
      path.endsWith(".json") ? "application/json; charset=utf-8" : "text/plain; charset=utf-8";
    return new Response(body, {
      status: 200,
      headers: {
        ...corsHeaders(),
        "Content-Type": ctype,
        "Cache-Control": `public, max-age=${TTL_SECONDS}`,
        "X-Pulse-Upstream": upstream,
      },
    });
  },
};

async function handleRefresh(request, env) {
  const ip =
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
    "unknown";
  const now = Date.now();
  const last = refreshByIp.get(ip) || 0;
  if (now - last < REFRESH_COOLDOWN_MS) {
    return json(
      {
        ok: true,
        skipped: true,
        freshening: false,
        retry_after_seconds: Math.ceil((REFRESH_COOLDOWN_MS - (now - last)) / 1000),
      },
      200
    );
  }

  const token = env.GITHUB_TOKEN || "";
  const repo = env.GITHUB_REPO || DEFAULT_REPO;
  if (!token) {
    return json({ ok: false, error: "GITHUB_TOKEN not configured", freshening: false }, 503);
  }

  refreshByIp.set(ip, now);
  // Bound map growth
  if (refreshByIp.size > 5000) {
    const cutoff = now - REFRESH_COOLDOWN_MS;
    for (const [k, t] of refreshByIp) {
      if (t < cutoff) refreshByIp.delete(k);
    }
  }

  try {
    const resp = await fetch(`https://api.github.com/repos/${repo}/dispatches`, {
      method: "POST",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "User-Agent": "PulseConfigs-Worker/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      body: JSON.stringify({ event_type: "aggregate-now", client_payload: { source: "worker-refresh" } }),
    });

    if (!resp.ok && resp.status !== 204) {
      const text = await resp.text();
      return json(
        { ok: false, error: "dispatch failed", status: resp.status, detail: text.slice(0, 200), freshening: false },
        502
      );
    }

    return json({ ok: true, skipped: false, freshening: true }, 200);
  } catch (err) {
    return json({ ok: false, error: String(err), freshening: false }, 502);
  }
}

async function forwardProbe(request, env) {
  const collector = (env.COLLECTOR_URL || "").replace(/\/$/, "");
  if (!collector) {
    return json({ error: "COLLECTOR_URL not configured" }, 503);
  }
  const secret = env.PROBE_SECRET || "";
  const auth = request.headers.get("Authorization") || "";
  const hdrSecret = request.headers.get("X-Pulse-Secret") || "";
  if (secret && auth !== `Bearer ${secret}` && hdrSecret !== secret) {
    return json({ error: "unauthorized" }, 401);
  }
  const body = await request.arrayBuffer();
  const resp = await fetch(`${collector}/probes/iran`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: auth || (secret ? `Bearer ${secret}` : ""),
      "X-Pulse-Secret": hdrSecret || secret,
    },
    body,
  });
  const text = await resp.text();
  return new Response(text, {
    status: resp.status,
    headers: { ...corsHeaders(), "Content-Type": "application/json" },
  });
}

function json(obj, status) {
  return new Response(JSON.stringify(obj) + "\n", {
    status,
    headers: { ...corsHeaders(), "Content-Type": "application/json; charset=utf-8" },
  });
}
