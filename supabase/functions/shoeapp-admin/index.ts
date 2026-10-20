const BRANDS = ["K2", "아이더", "WIDEANGLE", "다이나핏", "노르디스크", "NEPA", "K2 Safety", "EIDER SAFETY", "NEPA SAFETY"];
const encoder = new TextEncoder();

function json(body: unknown, status = 200, origin = "") {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Headers": "authorization, content-type",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Vary": "Origin",
      "Cache-Control": "no-store",
    },
  });
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)].map((n) => n.toString(16).padStart(2, "0")).join("");
}

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

async function rest(path: string, init: RequestInit = {}) {
  const url = `${Deno.env.get("SUPABASE_URL")}/rest/v1/${path}`;
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!key) throw new Error("Server configuration is incomplete.");
  return await fetch(url, {
    ...init,
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
      ...(init.headers || {}),
    },
  });
}

async function verifySession(request: Request): Promise<boolean> {
  const token = request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "") || "";
  if (token.length < 40) return false;
  const tokenHash = await sha256(token);
  const query = new URLSearchParams({
    select: "token_hash",
    token_hash: `eq.${tokenHash}`,
    expires_at: `gt.${new Date().toISOString()}`,
    limit: "1",
  });
  const response = await rest(`shoeapp_admin_sessions?${query}`);
  if (!response.ok) throw new Error("Could not verify the administrator session.");
  return (await response.json()).length > 0;
}

Deno.serve(async (request) => {
  const origin = request.headers.get("Origin") || "";
  const allowedOrigins = new Set([
    "https://nge00.github.io",
    "http://10.100.40.168:8000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
  ]);
  if (!allowedOrigins.has(origin)) return json({ error: "Origin not allowed." }, 403, "https://nge00.github.io");
  if (request.method === "OPTIONS") return json({}, 200, origin);
  if (request.method !== "POST") return json({ error: "Method not allowed." }, 405, origin);

  try {
    const body = await request.json();
    if (body.action === "login") {
      const ip = request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
      const rateSalt = Deno.env.get("ADMIN_RATE_LIMIT_SALT");
      if (!rateSalt) throw new Error("Server configuration is incomplete.");
      const rateLimitKey = await sha256(`${rateSalt}:${ip}`);
      const allowedResponse = await rest("rpc/shoeapp_admin_login_allowed", {
        method: "POST",
        body: JSON.stringify({ p_ip_hash: rateLimitKey }),
      });
      if (!allowedResponse.ok) throw new Error("Could not verify administrator access.");
      const [{ allowed }] = await allowedResponse.json();
      if (!allowed) return json({ error: "로그인 시도가 잠시 제한되었습니다. 15분 후 다시 시도해 주세요." }, 429, origin);

      const expectedPasswords = [
        Deno.env.get("ADMIN_PASSWORD"),
        Deno.env.get("ADMIN_PASSWORD_2"),
      ].filter((password): password is string => Boolean(password));
      if (typeof body.password !== "string" || !expectedPasswords.some((password) => body.password === password)) {
        await rest("rpc/shoeapp_admin_login_attempt", {
          method: "POST",
          body: JSON.stringify({ p_ip_hash: rateLimitKey, p_success: false }),
        });
        return json({ error: "관리자 비밀번호가 올바르지 않습니다." }, 401, origin);
      }
      await rest("rpc/shoeapp_admin_login_attempt", {
        method: "POST",
        body: JSON.stringify({ p_ip_hash: rateLimitKey, p_success: true }),
      });
      const bytes = crypto.getRandomValues(new Uint8Array(32));
      const token = base64url(bytes);
      const tokenHash = await sha256(token);
      const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString();
      const created = await rest("shoeapp_admin_sessions", {
        method: "POST",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({ token_hash: tokenHash, expires_at: expiresAt }),
      });
      if (!created.ok) throw new Error("Could not create administrator session.");
      return json({ token, expiresAt }, 200, origin);
    }

    if (!await verifySession(request)) return json({ error: "관리자 세션이 만료되었습니다. 다시 로그인해 주세요." }, 401, origin);

    if (body.action === "read") {
      const query = new URLSearchParams({ select: "brand,payload", brand: `in.(${BRANDS.join(",")})` });
      const response = await rest(`shoeapp?${query}`);
      if (!response.ok) return json({ error: "전체 브랜드 데이터를 읽지 못했습니다." }, 502, origin);
      return json({ rows: await response.json() }, 200, origin);
    }

    if (body.action === "save") {
      if (!Array.isArray(body.rows) || body.rows.length !== BRANDS.length || body.rows.some((row: any) => !BRANDS.includes(row.brand))) {
        return json({ error: "저장할 브랜드 데이터가 올바르지 않습니다." }, 400, origin);
      }
      const response = await rest("shoeapp?on_conflict=brand", {
        method: "POST",
        headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
        body: JSON.stringify(body.rows),
      });
      if (!response.ok) return json({ error: "전체 브랜드 데이터를 저장하지 못했습니다." }, 502, origin);
      return json({ ok: true }, 200, origin);
    }

    return json({ error: "Unknown action." }, 400, origin);
  } catch (error) {
    console.error("shoeapp-admin request failed", error);
    return json({ error: "관리자 요청을 처리하지 못했습니다. Supabase 설정을 확인해 주세요." }, 500, origin);
  }
});
