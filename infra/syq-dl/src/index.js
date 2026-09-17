// syq download host: records one row per request, then serves the matching
// GitHub release asset from the edge cache, fetching it from GitHub on a miss.
// GitHub stays the immutable source of the bytes; every syq client verifies
// what it downloads against the signed release manifest, so this host can
// only delay or withhold, never forge. If GitHub cannot be reached the client
// is redirected there to try directly.

const TAG = /^v\d+\.\d+\.\d+$/;
const ASSET = /^[A-Za-z0-9._-]{1,100}$/;
const TARGETS = ["linux-x86_64", "linux-aarch64", "macos-arm64", "macos-x86_64"];
const CLIENT = /^(syq|syq-python-sdk)\/(\d+\.\d+\.\d+)/;
// Tagged assets never change once published.
const ASSET_TTL_SECONDS = 365 * 24 * 60 * 60;
const LATEST_TTL_SECONDS = 300;

export default {
  async fetch(request, env, ctx) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("method not allowed", { status: 405 });
    }
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length === 0) {
      return Response.redirect(env.HOME_REDIRECT, 302);
    }
    if (parts.length !== 2 || !ASSET.test(parts[1])) {
      return new Response("not found", { status: 404 });
    }
    const [first, asset] = parts;

    let tag = null;
    let latest = 0;
    if (first === "latest") {
      latest = 1;
      tag = await resolveLatestTag(env, ctx, asset);
    } else if (TAG.test(first)) {
      tag = first;
    } else {
      return new Response("not found", { status: 404 });
    }

    const response = tag
      ? await serveAsset(env, ctx, request, tag, asset)
      : redirect(`${env.GITHUB_RELEASES}/latest/download/${asset}`);
    ctx.waitUntil(
      record(env, request, { asset, tag, latest, status: response.status }).catch(() => {}),
    );
    return response;
  },
};

function redirect(location) {
  return new Response(null, {
    status: 302,
    headers: { location, "cache-control": "no-store" },
  });
}

// Serve /<tag>/<asset> from the edge cache, filling it from GitHub on a miss.
async function serveAsset(env, ctx, request, tag, asset) {
  const cacheKey = new Request(`https://${new URL(request.url).host}/${tag}/${asset}`);
  const cache = caches.default;
  const hit = await cache.match(cacheKey);
  if (hit) {
    return withCacheStatus(hit, "hit", request.method);
  }
  const origin = `${env.GITHUB_RELEASES}/download/${tag}/${asset}`;
  let upstream;
  try {
    upstream = await fetch(origin, { redirect: "follow" });
  } catch {
    return redirect(origin);
  }
  if (upstream.status === 404) {
    return new Response("not found", { status: 404 });
  }
  if (!upstream.ok || !upstream.body) {
    return redirect(origin);
  }
  const headers = new Headers({
    "content-type": "application/octet-stream",
    "content-disposition": `attachment; filename="${asset}"`,
    "cache-control": `public, max-age=${ASSET_TTL_SECONDS}, immutable`,
  });
  const length = upstream.headers.get("content-length");
  if (length) headers.set("content-length", length);
  const [toClient, toCache] = upstream.body.tee();
  ctx.waitUntil(cache.put(cacheKey, new Response(toCache, { status: 200, headers })));
  return withCacheStatus(new Response(toClient, { status: 200, headers }), "miss", request.method);
}

function withCacheStatus(response, status, method) {
  const headers = new Headers(response.headers);
  headers.set("x-syq-cache", status);
  return new Response(method === "HEAD" ? null : response.body, {
    status: response.status,
    headers,
  });
}

// Ask GitHub where /releases/latest/download/<asset> points and read the tag
// out of the redirect. This avoids the rate-limited REST API. Cached briefly
// so a burst of checks after a release does not hammer GitHub.
async function resolveLatestTag(env, ctx, asset) {
  const probe = `${env.GITHUB_RELEASES}/latest/download/${asset}`;
  const cache = caches.default;
  const key = new Request(probe);
  const cached = await cache.match(key);
  if (cached) {
    return (await cached.text()) || null;
  }
  let tag = null;
  try {
    const response = await fetch(probe, { method: "HEAD", redirect: "manual" });
    const location = response.headers.get("location") || "";
    const match = location.match(/\/releases\/download\/(v\d+\.\d+\.\d+)\//);
    tag = match ? match[1] : null;
  } catch {
    tag = null;
  }
  if (tag) {
    ctx.waitUntil(
      cache.put(
        key,
        new Response(tag, { headers: { "cache-control": `public, max-age=${LATEST_TTL_SECONDS}` } }),
      ),
    );
  }
  return tag;
}

function classify(asset) {
  if (asset === "install.sh") return "installer";
  if (asset === "syq-release-manifest.json") return "manifest";
  if (asset === "syq.rb") return "formula";
  if (asset.endsWith(".sha256")) return "checksum";
  if (asset.endsWith(".gz")) return "archive";
  if (asset.startsWith("syq-")) return "binary";
  return "other";
}

function targetOf(request, asset) {
  const header = request.headers.get("x-syq-target");
  if (header && TARGETS.includes(header)) return header;
  for (const t of TARGETS) {
    if (asset.startsWith(`syq-${t}`)) return t;
  }
  return null;
}

async function record(env, request, { asset, tag, latest, status }) {
  const now = new Date();
  const ua = request.headers.get("user-agent") || null;
  const client = ua && ua.match(CLIENT);
  const purpose = request.headers.get("x-syq-purpose");
  const cf = request.cf || {};
  await env.DB.prepare(
    `INSERT INTO events
       (ts, day, kind, tag, latest, asset, target, client_version, user_agent,
        country, region, city, colo, ip, status, purpose, client)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)`,
  )
    .bind(
      now.toISOString().slice(0, 19) + "Z",
      now.toISOString().slice(0, 10),
      classify(asset),
      tag,
      latest,
      asset,
      targetOf(request, asset),
      client ? client[2] : null,
      ua,
      cf.country || null,
      cf.region || null,
      cf.city || null,
      cf.colo || null,
      request.headers.get("cf-connecting-ip") || null,
      status,
      purpose === "check" || purpose === "interactive" ? purpose : null,
      client ? client[1] : null,
    )
    .run();
}
