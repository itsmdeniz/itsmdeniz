const POSTS_KEY = "timeline:posts";
const MAX_POST_LENGTH = 280;
const TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7;
const LOGIN_WINDOW_SECONDS = 60 * 10;
const MAX_LOGIN_ATTEMPTS = 8;

const securityHeaders = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "Content-Security-Policy": [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "connect-src 'self'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'"
  ].join("; ")
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (url.pathname === "/api/admin-login" && request.method === "POST") {
        return withSecurityHeaders(await handleAdminLogin(request, env));
      }

      if (url.pathname === "/api/timeline" && request.method === "GET") {
        return withSecurityHeaders(await handleGetTimeline(env));
      }

      if (url.pathname === "/api/timeline" && request.method === "POST") {
        return withSecurityHeaders(await handleCreatePost(request, env));
      }

      if (url.pathname === "/api/timeline" && request.method === "DELETE") {
        return withSecurityHeaders(await handleDeletePost(request, env, url));
      }

      if (url.pathname.startsWith("/api/")) {
        return withSecurityHeaders(json({ error: "Endpoint bulunamadı." }, 404));
      }

      const assetResponse = await env.ASSETS.fetch(request);
      return withSecurityHeaders(assetResponse);
    } catch (error) {
      console.error(error);

      if (error instanceof HttpError) {
        return withSecurityHeaders(json({ error: error.message }, error.status));
      }

      return withSecurityHeaders(json({ error: "Sunucu tarafında beklenmeyen bir hata oldu." }, 500));
    }
  }
};

async function handleAdminLogin(request, env) {
  assertEnv(env);

  const clientIp = getClientIp(request);
  await enforceLoginRateLimit(env, clientIp);

  const body = await readJson(request);
  const password = String(body.password || "");

  const isValid = await timingSafeEqual(password, env.ADMIN_PASSWORD);
  if (!isValid) {
    await recordFailedLogin(env, clientIp);
    return json({ error: "Admin şifresi yanlış." }, 401);
  }

  await clearFailedLogins(env, clientIp);

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: "deniz-admin",
    role: "admin",
    iat: now,
    exp: now + TOKEN_TTL_SECONDS
  };

  const token = await signToken(payload, env.TOKEN_SECRET);
  return json({ token, expiresIn: TOKEN_TTL_SECONDS });
}

async function handleGetTimeline(env) {
  assertEnv(env, { requireSecrets: false });
  const posts = await getPosts(env);
  posts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  return json({ posts });
}

async function handleCreatePost(request, env) {
  assertEnv(env);
  await requireAdmin(request, env);

  const body = await readJson(request);
  const content = String(body.content || "").trim();

  if (!content) {
    return json({ error: "Boş paylaşım olmaz Deniz, timeline da kalite ister." }, 400);
  }

  if (content.length > MAX_POST_LENGTH) {
    return json({ error: `Paylaşım ${MAX_POST_LENGTH} karakteri geçemez.` }, 400);
  }

  const posts = await getPosts(env);
  const post = {
    id: crypto.randomUUID(),
    content,
    createdAt: new Date().toISOString()
  };

  posts.unshift(post);
  await savePosts(env, posts.slice(0, 200));

  return json({ post }, 201);
}

async function handleDeletePost(request, env, url) {
  assertEnv(env);
  await requireAdmin(request, env);

  const id = url.searchParams.get("id");
  if (!id) {
    return json({ error: "Silinecek post id eksik." }, 400);
  }

  const posts = await getPosts(env);
  const nextPosts = posts.filter((post) => post.id !== id);

  if (nextPosts.length === posts.length) {
    return json({ error: "Post bulunamadı." }, 404);
  }

  await savePosts(env, nextPosts);
  return json({ ok: true });
}

function assertEnv(env, options = {}) {
  const requireSecrets = options.requireSecrets !== false;

  if (!env.TIMELINE_KV) {
    throw new HttpError("TIMELINE_KV binding eksik. Cloudflare Worker'a KV namespace bağlanmalı.", 500);
  }

  if (requireSecrets && (!env.ADMIN_PASSWORD || !env.TOKEN_SECRET)) {
    throw new HttpError("Worker secret ayarları eksik: ADMIN_PASSWORD ve TOKEN_SECRET gerekli.", 500);
  }
}

async function requireAdmin(request, env) {
  const header = request.headers.get("Authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";

  if (!token) {
    throw new HttpError("Admin oturumu yok.", 401);
  }

  const payload = await verifyToken(token, env.TOKEN_SECRET);
  if (payload.role !== "admin" || payload.sub !== "deniz-admin") {
    throw new HttpError("Bu işlem için yetki yok.", 403);
  }

  return payload;
}

async function getPosts(env) {
  const raw = await env.TIMELINE_KV.get(POSTS_KEY);
  if (!raw) return [];

  try {
    const posts = JSON.parse(raw);
    return Array.isArray(posts) ? posts.filter(isValidPost) : [];
  } catch {
    return [];
  }
}

async function savePosts(env, posts) {
  await env.TIMELINE_KV.put(POSTS_KEY, JSON.stringify(posts));
}

function isValidPost(post) {
  return post && typeof post.id === "string" && typeof post.content === "string" && typeof post.createdAt === "string";
}

async function enforceLoginRateLimit(env, clientIp) {
  const key = loginKey(clientIp);
  const raw = await env.TIMELINE_KV.get(key);
  if (!raw) return;

  const data = JSON.parse(raw);
  if (data.count >= MAX_LOGIN_ATTEMPTS) {
    throw new HttpError("Çok fazla yanlış deneme var. Biraz sonra tekrar dene.", 429);
  }
}

async function recordFailedLogin(env, clientIp) {
  const key = loginKey(clientIp);
  const raw = await env.TIMELINE_KV.get(key);
  const data = raw ? JSON.parse(raw) : { count: 0 };
  data.count += 1;
  await env.TIMELINE_KV.put(key, JSON.stringify(data), { expirationTtl: LOGIN_WINDOW_SECONDS });
}

async function clearFailedLogins(env, clientIp) {
  await env.TIMELINE_KV.delete(loginKey(clientIp));
}

function loginKey(clientIp) {
  return `login-fail:${clientIp}`;
}

function getClientIp(request) {
  return request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown";
}

async function readJson(request) {
  const contentType = request.headers.get("Content-Type") || "";
  if (!contentType.includes("application/json")) {
    return {};
  }

  try {
    return await request.json();
  } catch {
    throw new HttpError("Geçersiz JSON gönderildi.", 400);
  }
}

async function signToken(payload, secret) {
  const encodedHeader = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signature = await hmac(`${encodedHeader}.${encodedPayload}`, secret);
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

async function verifyToken(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new HttpError("Geçersiz admin token.", 401);
  }

  const [header, payload, signature] = parts;
  const expected = await hmac(`${header}.${payload}`, secret);

  if (!(await timingSafeEqual(signature, expected))) {
    throw new HttpError("Admin token doğrulanamadı.", 401);
  }

  let decoded;
  try {
    decoded = JSON.parse(base64UrlDecode(payload));
  } catch {
    throw new HttpError("Admin token okunamadı.", 401);
  }

  const now = Math.floor(Date.now() / 1000);
  if (!decoded.exp || decoded.exp < now) {
    throw new HttpError("Admin oturumu süresi doldu.", 401);
  }

  return decoded;
}

async function hmac(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return arrayBufferToBase64Url(signature);
}

function base64UrlEncode(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlDecode(value) {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(base64);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

async function timingSafeEqual(a, b) {
  const left = new TextEncoder().encode(String(a));
  const right = new TextEncoder().encode(String(b));

  if (left.length !== right.length) {
    const max = Math.max(left.length, right.length);
    let mismatch = left.length ^ right.length;
    for (let index = 0; index < max; index++) {
      mismatch |= (left[index] || 0) ^ (right[index] || 0);
    }
    return false;
  }

  let mismatch = 0;
  for (let index = 0; index < left.length; index++) {
    mismatch |= left[index] ^ right[index];
  }
  return mismatch === 0;
}

function withSecurityHeaders(response) {
  const next = new Response(response.body, response);
  for (const [key, value] of Object.entries(securityHeaders)) {
    next.headers.set(key, value);
  }
  return next;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

class HttpError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}
