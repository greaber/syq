// syq download host: records one row per request, then redirects to the
// matching GitHub release asset. GitHub stays the immutable source of the
// bytes; every syq client verifies what it downloads against the signed
// release manifest, so this host can only delay or withhold, never forge.

const TAG = /^v\d+\.\d+\.\d+$/;
const ASSET = /^[A-Za-z0-9._-]{1,100}$/;
const TARGETS = ["linux-x86_64", "linux-aarch64", "macos-arm64", "macos-x86_64"];

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("method not allowed", { status: 405 });
    }
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length === 0) {
      return Response.redirect(env.HOME_REDIRECT, 302);
    }
    if (parts.length !== 2) {
      return new Response("not found", { status: 404 });
    }
    const [first, asset] = parts;
    if (!ASSET.test(asset)) {
      return new Response("not found", { status: 404 });
    }

    let tag = null;
    let latest = 0;
    let location;
    if (first === "latest") {
      latest = 1;
      tag = await resolveLatestTag(env, asset);
      location = tag
        ? `${env.GITHUB_RELEASES}/download/${tag}/${asset}`
        : `${env.GITHUB_RELEASES}/latest/download/${asset}`;
    } else if (TAG.test(first)) {
      tag = first;
      location = `${env.GITHUB_RELEASES}/download/${tag}/${asset}`;
    } else {
      return new Response("not found", { status: 404 });
    }

    const status = 302;
    ctx.waitUntil(record(env, request, { asset, tag, latest, status }).catch(() => {}));
    return new Response(null, {
      status,
      headers: { location, "cache-control": "no-store" },
    });
  },
};

// Ask GitHub where /releases/latest/download/<asset> points and read the tag
// out of the redirect. This avoids the rate-limited REST API. Cached briefly
// so a burst of checks after a release does not hammer GitHub.
async function resolveLatestTag(env, asset) {
  const probe = `${env.GITHUB_RELEASES}/latest/download/${asset}`;
  const cache = caches.default;
  const key = new Request(probe, { method: "GET" });
  let cached = await cache.match(key);
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
    await cache.put(
      key,
      new Response(tag, { headers: { "cache-control": "public, max-age=300" } }),
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
  const version = ua && ua.match(/^syq\/(\d+\.\d+\.\d+)/);
  const cf = request.cf || {};
  await env.DB.prepare(
    `INSERT INTO events
       (ts, day, kind, tag, latest, asset, target, client_version, user_agent,
        country, region, city, colo, ip, status)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)`,
  )
    .bind(
      now.toISOString().slice(0, 19) + "Z",
      now.toISOString().slice(0, 10),
      classify(asset),
      tag,
      latest,
      asset,
      targetOf(request, asset),
      version ? version[1] : null,
      ua,
      cf.country || null,
      cf.region || null,
      cf.city || null,
      cf.colo || null,
      request.headers.get("cf-connecting-ip") || null,
      status,
    )
    .run();
}
