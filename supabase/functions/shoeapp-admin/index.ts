const BRANDS = ["K2", "아이더", "WIDEANGLE", "다이나핏", "노르디스크", "NEPA", "K2 Safety", "EIDER SAFETY", "NEPA SAFETY"];
const PBKDF2_ITERATIONS = 310_000;
const encoder = new TextEncoder();

type AdminRole = "super_admin" | "manager";
type AdminSession = { role: AdminRole; managerSlot: number | null };

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

function hex(bytes: Uint8Array): string {
  return [...bytes].map((n) => n.toString(16).padStart(2, "0")).join("");
}

function fromHex(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})+$/i.test(value)) return new Uint8Array();
  return new Uint8Array(value.match(/.{2}/g)!.map((part) => parseInt(part, 16)));
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) mismatch |= a[i] ^ b[i];
  return mismatch === 0;
}

async function hashPassword(password: string, saltHex?: string, iterations = PBKDF2_ITERATIONS) {
  const salt = saltHex ? fromHex(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const saltBuffer = Uint8Array.from(salt).buffer as ArrayBuffer;
  const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: saltBuffer, iterations }, material, 256);
  return { salt: hex(salt), hash: hex(new Uint8Array(bits)), iterations };
}

async function verifyPassword(password: string, salt: string, expected: string, iterations: number) {
  if (!salt || !expected || !Number.isInteger(iterations) || iterations < 200_000 || iterations > 1_000_000) return false;
  const derived = await hashPassword(password, salt, iterations);
  return sameBytes(fromHex(derived.hash), fromHex(expected));
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

async function restJson(path: string, init: RequestInit = {}) {
  const response = await rest(path, init);
  if (!response.ok) throw new Error(`Database request failed (${response.status}).`);
  const text = await response.text();
  return text ? JSON.parse(text) : null;
}

async function profiles() {
  return await restJson("shoeapp_admin_manager_profiles?select=manager_slot,display_name,is_active,password_salt,password_hash,password_iterations,must_change_password") as Array<any>;
}

async function assignments() {
  return await restJson("shoeapp_admin_manager_brands?select=manager_slot,brand") as Array<{ manager_slot: number; brand: string }>;
}

async function assignedBrands(slot: number): Promise<string[]> {
  return (await assignments()).filter((item) => item.manager_slot === slot).map((item) => item.brand);
}

async function verifySession(request: Request): Promise<AdminSession | null> {
  const token = request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "") || "";
  if (token.length < 40) return null;
  const tokenHash = await sha256(token);
  const query = new URLSearchParams({
    select: "admin_role,manager_slot",
    token_hash: `eq.${tokenHash}`,
    expires_at: `gt.${new Date().toISOString()}`,
    limit: "1",
  });
  const rows = await restJson(`shoeapp_admin_sessions?${query}`) as Array<any>;
  const row = rows[0];
  if (!row || !["super_admin", "manager"].includes(row.admin_role)) return null;
  if (row.admin_role === "super_admin") return { role: "super_admin", managerSlot: null };
  if (!Number.isInteger(row.manager_slot) || row.manager_slot < 1 || row.manager_slot > 4) return null;
  const manager = (await profiles()).find((item) => item.manager_slot === row.manager_slot);
  const brands = await assignedBrands(row.manager_slot);
  if (!manager?.is_active || manager.must_change_password || brands.length < 2 || brands.length > 3) return null;
  return { role: "manager", managerSlot: row.manager_slot };
}

function roleBrands(role: AdminSession, managerBrands: string[]) {
  return role.role === "super_admin" ? BRANDS : managerBrands;
}

function brandFilter(brands: string[]) {
  const value = `in.(${brands.map((brand) => `"${brand.replaceAll('"', '\\"')}"`).join(",")})`;
  return new URLSearchParams({ select: "brand,payload", brand: value });
}

async function readRows(brands: string[]) {
  if (!brands.length) return [];
  return await restJson(`shoeapp?${brandFilter(brands)}`) as Array<{ brand: string; payload: any }>;
}

async function readSchedules() {
  const rows = await restJson("shoeapp_admin_schedules?select=id,schedule_date,title,times,brand,created_by_manager_slot&order=schedule_date.asc") as Array<any>;
  return rows.map((row) => ({
    id: row.id,
    date: row.schedule_date,
    title: row.title,
    times: row.times,
    brand: row.brand,
    createdByManagerSlot: row.created_by_manager_slot,
  }));
}

async function createSession(role: AdminRole, managerSlot: number | null, origin: string) {
  const token = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const tokenHash = await sha256(token);
  const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString();
  await restJson("shoeapp_admin_sessions", {
    method: "POST",
    headers: { Prefer: "return=minimal" },
    body: JSON.stringify({ token_hash: tokenHash, expires_at: expiresAt, admin_role: role, manager_slot: managerSlot }),
  });
  return json({ token, expiresAt, role, managerSlot }, 200, origin);
}

function validTimes(times: unknown): times is string[] {
  return Array.isArray(times) && times.length > 0 && times.length <= 23
    && times.every((time) => typeof time === "string" && /^(?:0[7-9]|1[0-9]|2[0-3]):(?:00|30)$/.test(time))
    && new Set(times).size === times.length;
}

async function scheduleConflicts(date: string, brand: string | null, times: string[], skipId = "") {
  const targetBrands = brand ? [brand] : BRANDS;
  const rows = await readRows(targetBrands);
  for (const row of rows) {
    for (const booking of Array.isArray(row.payload?.books) ? row.payload.books : []) {
      if (!booking.completed && booking.date === date && times.includes(String(booking.time || ""))) return true;
    }
  }
  const schedules = await readSchedules();
  return schedules.some((schedule) => schedule.id !== skipId
    && schedule.date === date
    && (brand === null ? schedule.brand === null : schedule.brand === null || schedule.brand === brand)
    && (schedule.times || []).some((time: string) => times.includes(time)));
}

async function findSchedule(id: string) {
  const rows = await restJson(`shoeapp_admin_schedules?select=id,schedule_date,title,times,brand,created_by_manager_slot&id=eq.${encodeURIComponent(id)}&limit=1`) as Array<any>;
  return rows[0] || null;
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
        method: "POST", body: JSON.stringify({ p_ip_hash: rateLimitKey }),
      });
      if (!allowedResponse.ok) throw new Error("Could not verify administrator access.");
      const [{ allowed }] = await allowedResponse.json();
      if (!allowed) return json({ error: "로그인 시도가 잠시 제한되었습니다. 15분 후 다시 시도해 주세요." }, 429, origin);

      const password = typeof body.password === "string" ? body.password : "";
      const superPasswords = [Deno.env.get("ADMIN_PASSWORD"), Deno.env.get("ADMIN_PASSWORD_2")].filter(Boolean);
      if (superPasswords.some((candidate) => password === candidate)) {
        await rest("rpc/shoeapp_admin_login_attempt", { method: "POST", body: JSON.stringify({ p_ip_hash: rateLimitKey, p_success: true }) });
        return await createSession("super_admin", null, origin);
      }

      let managerMatch: any = null;
      if (password) {
        for (const profile of await profiles()) {
          if (!profile.is_active || profile.must_change_password || !profile.password_hash || !profile.password_salt) continue;
          if (await verifyPassword(password, profile.password_salt, profile.password_hash, profile.password_iterations)) {
            const brands = await assignedBrands(profile.manager_slot);
            if (brands.length >= 2 && brands.length <= 3) managerMatch = profile;
            break;
          }
        }
      }
      if (!managerMatch) {
        await rest("rpc/shoeapp_admin_login_attempt", { method: "POST", body: JSON.stringify({ p_ip_hash: rateLimitKey, p_success: false }) });
        return json({ error: "관리자 비밀번호가 올바르지 않습니다." }, 401, origin);
      }
      await rest("rpc/shoeapp_admin_login_attempt", { method: "POST", body: JSON.stringify({ p_ip_hash: rateLimitKey, p_success: true }) });
      return await createSession("manager", managerMatch.manager_slot, origin);
    }

    const session = await verifySession(request);
    if (!session) return json({ error: "관리자 세션이 만료되었거나 권한 배정이 변경되었습니다. 다시 로그인해 주세요." }, 401, origin);
    const managerBrands = session.managerSlot ? await assignedBrands(session.managerSlot) : [];
    const allowedBrands = roleBrands(session, managerBrands);

    if (body.action === "read") {
      const rows = await readRows(allowedBrands);
      return json({ rows, schedules: await readSchedules(), role: session.role, managerSlot: session.managerSlot, brands: allowedBrands }, 200, origin);
    }

    if (body.action === "save") {
      if (!Array.isArray(body.rows) || !body.rows.length
        || body.rows.some((row: any) => !allowedBrands.includes(row?.brand))) {
        return json({ error: "저장 권한이 없는 브랜드가 포함되어 있습니다." }, 403, origin);
      }
      const rowBrands = body.rows.map((row: any) => row.brand);
      if (new Set(rowBrands).size !== rowBrands.length
        || (session.role === "super_admin" && (rowBrands.length !== BRANDS.length || !BRANDS.every((brand) => rowBrands.includes(brand))))
        || (session.role === "manager" && (rowBrands.length !== managerBrands.length || !managerBrands.every((brand) => rowBrands.includes(brand))))) {
        return json({ error: "저장할 브랜드 목록이 현재 권한과 일치하지 않습니다." }, 403, origin);
      }
      const existing = await readRows(rowBrands);
      const byBrand = new Map(existing.map((row) => [row.brand, row.payload || {}]));
      for (const row of body.rows) {
        const payload = row?.payload || {};
        if (![...(Array.isArray(payload.samples) ? payload.samples : []), ...(Array.isArray(payload.books) ? payload.books : [])]
          .every((item: any) => item.brand === row.brand)) {
          return json({ error: "다른 브랜드의 데이터가 포함되어 있습니다." }, 403, origin);
        }
        const previous = byBrand.get(row.brand) || {};
        row.payload = {
          ...previous,
          ...payload,
          samples: Array.isArray(payload.samples) ? payload.samples : [],
          books: Array.isArray(payload.books) ? payload.books : [],
          season: session.role === "super_admin" ? (payload.season || "") : (previous.season || ""),
          schedules: previous.schedules || [],
        };
      }
      const response = await rest("shoeapp?on_conflict=brand", {
        method: "POST", headers: { Prefer: "resolution=merge-duplicates,return=minimal" }, body: JSON.stringify(body.rows),
      });
      if (!response.ok) return json({ error: "브랜드 데이터를 저장하지 못했습니다." }, 502, origin);
      return json({ ok: true }, 200, origin);
    }

    if (body.action === "managers_read") {
      if (session.role !== "super_admin") return json({ error: "최종 관리자만 브랜드관리자 권한을 관리할 수 있습니다." }, 403, origin);
      const [storedProfiles, storedAssignments] = await Promise.all([profiles(), assignments()]);
      const managers = [1, 2, 3, 4].map((slot) => {
        const stored = storedProfiles.find((item) => item.manager_slot === slot);
        return {
          managerSlot: slot,
          displayName: stored?.display_name || `브랜드관리자 ${slot}`,
          active: Boolean(stored?.is_active),
          hasPassword: Boolean(stored?.password_hash),
          mustChangePassword: Boolean(stored?.must_change_password),
          brands: storedAssignments.filter((item) => item.manager_slot === slot).map((item) => item.brand),
        };
      });
      return json({ managers, brands: BRANDS }, 200, origin);
    }

    if (body.action === "managers_save") {
      if (session.role !== "super_admin") return json({ error: "최종 관리자만 브랜드관리자 권한을 관리할 수 있습니다." }, 403, origin);
      if (!Array.isArray(body.managers) || body.managers.length !== 4) return json({ error: "브랜드관리자 설정을 확인해 주세요." }, 400, origin);
      const existingProfiles = await profiles();
      const finalProfiles = [] as Array<any>;
      const seenBrands = new Set<string>();
      const submittedPasswords = new Set<string>();
      for (let i = 0; i < 4; i++) {
        const manager = body.managers[i];
        const slot = i + 1;
        if (Number(manager?.managerSlot) !== slot || !Array.isArray(manager.brands)
          || manager.brands.length > 3 || new Set(manager.brands).size !== manager.brands.length
          || manager.brands.some((brand: string) => !BRANDS.includes(brand))) {
          return json({ error: `브랜드관리자 ${slot}의 브랜드 배정을 확인해 주세요. 한 명당 최대 3개까지 배정할 수 있습니다.` }, 400, origin);
        }
        for (const brand of manager.brands) {
          if (seenBrands.has(brand)) return json({ error: `${brand} 브랜드는 중복 배정할 수 없습니다.` }, 409, origin);
          seenBrands.add(brand);
        }
        const old = existingProfiles.find((item) => item.manager_slot === slot);
        let passwordSalt = old?.password_salt || null;
        let passwordHash = old?.password_hash || null;
        let passwordIterations = old?.password_iterations || PBKDF2_ITERATIONS;
        let mustChangePassword = old?.must_change_password ?? true;
        const newPassword = typeof manager.password === "string" ? manager.password : "";
        if (newPassword) {
          if (newPassword.length < 12 || newPassword.length > 128) {
            return json({ error: `브랜드관리자 ${slot} 비밀번호는 12자 이상으로 설정해 주세요.` }, 400, origin);
          }
          if ([Deno.env.get("ADMIN_PASSWORD"), Deno.env.get("ADMIN_PASSWORD_2")].some((candidate) => candidate && candidate === newPassword)) {
            return json({ error: "최종 관리자와 브랜드관리자는 서로 다른 비밀번호를 사용해야 합니다." }, 409, origin);
          }
          if (submittedPasswords.has(newPassword)) return json({ error: "브랜드관리자 비밀번호는 서로 다르게 설정해 주세요." }, 409, origin);
          submittedPasswords.add(newPassword);
          for (const other of existingProfiles) {
            const beingChanged = body.managers.some((candidate: any) => Number(candidate.managerSlot) === other.manager_slot && Boolean(candidate.password));
            if (other.manager_slot !== slot && !beingChanged && other.password_hash && await verifyPassword(newPassword, other.password_salt, other.password_hash, other.password_iterations)) {
              return json({ error: "브랜드관리자 비밀번호는 서로 다르게 설정해 주세요." }, 409, origin);
            }
          }
          const hashed = await hashPassword(newPassword);
          passwordSalt = hashed.salt;
          passwordHash = hashed.hash;
          passwordIterations = hashed.iterations;
          mustChangePassword = false;
        }
        const active = Boolean(manager.active);
        if (active && (manager.brands.length < 2 || manager.brands.length > 3 || !passwordHash || mustChangePassword)) {
          return json({ error: `브랜드관리자 ${slot}을 활성화하려면 12자 이상의 새 비밀번호와 고유 브랜드 2~3개가 필요합니다.` }, 400, origin);
        }
        finalProfiles.push({
          manager_slot: slot,
          display_name: `브랜드관리자 ${slot}`,
          is_active: active,
          password_salt: passwordSalt,
          password_hash: passwordHash,
          password_iterations: passwordIterations,
          must_change_password: mustChangePassword,
        });
      }
      const finalAssignments = body.managers.flatMap((manager: any) => manager.brands.map((brand: string) => ({ manager_slot: Number(manager.managerSlot), brand })));
      const saved = await rest("rpc/shoeapp_save_admin_managers", {
        method: "POST", body: JSON.stringify({ p_profiles: finalProfiles, p_assignments: finalAssignments }),
      });
      if (!saved.ok) return json({ error: "브랜드관리자 설정을 저장하지 못했습니다. 활성 상태와 브랜드 배정 수를 확인해 주세요." }, 400, origin);
      return json({ ok: true, sessionsRevoked: true }, 200, origin);
    }

    if (body.action === "schedule_save") {
      const id = typeof body.schedule?.id === "string" && body.schedule.id ? body.schedule.id : crypto.randomUUID();
      const schedule = body.schedule || {};
      const date = String(schedule.date || "");
      const title = String(schedule.title || "").trim();
      const brand = schedule.brand === null || schedule.brand === "" ? null : String(schedule.brand);
      const times = schedule.times;
      if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !title || title.length > 80 || !validTimes(times)
        || (brand !== null && !BRANDS.includes(brand))) return json({ error: "일정 날짜, 이름, 브랜드, 시간을 확인해 주세요." }, 400, origin);
      const previous = await findSchedule(id);
      if (session.role === "manager") {
        if (brand === null || !managerBrands.includes(brand) || (previous && (previous.brand === null || !managerBrands.includes(previous.brand)))) {
          return json({ error: "배정된 브랜드 일정만 등록·수정할 수 있습니다." }, 403, origin);
        }
      }
      if (await scheduleConflicts(date, brand, times, id)) return json({ error: "예약 또는 기존 일정과 겹치는 시간은 등록할 수 없습니다." }, 409, origin);
      await restJson("shoeapp_admin_schedules?on_conflict=id", {
        method: "POST",
        headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
        body: JSON.stringify({
          id, schedule_date: date, title, times, brand,
          created_by_manager_slot: session.role === "manager" ? session.managerSlot : (previous?.created_by_manager_slot ?? null),
          updated_at: new Date().toISOString(),
        }),
      });
      return json({ ok: true }, 200, origin);
    }

    if (body.action === "schedule_delete") {
      const id = String(body.id || "");
      const schedule = await findSchedule(id);
      if (!schedule) return json({ error: "일정을 찾을 수 없습니다." }, 404, origin);
      if (session.role === "manager" && (schedule.brand === null || !managerBrands.includes(schedule.brand))) {
        return json({ error: "배정된 브랜드 일정만 삭제할 수 있습니다." }, 403, origin);
      }
      await restJson(`shoeapp_admin_schedules?id=eq.${encodeURIComponent(id)}`, { method: "DELETE", headers: { Prefer: "return=minimal" } });
      return json({ ok: true }, 200, origin);
    }

    if (body.action === "reserved_slots") {
      const date = String(body.date || "");
      const brand = String(body.brand || "");
      if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !allowedBrands.includes(brand)) {
        return json({ error: "예약 날짜와 브랜드를 확인해 주세요." }, 400, origin);
      }
      const rows = await readRows(BRANDS);
      const reserved = new Set<string>();
      for (const row of rows) {
        for (const booking of Array.isArray(row.payload?.books) ? row.payload.books : []) {
          if (!booking.completed && booking.date === date && booking.time) reserved.add(String(booking.time));
        }
        for (const legacy of Array.isArray(row.payload?.schedules) ? row.payload.schedules : []) {
          if (legacy.date === date) for (const time of legacy.times || []) reserved.add(String(time));
        }
      }
      for (const schedule of await readSchedules()) {
        if (schedule.date === date && (schedule.brand === null || schedule.brand === brand)) {
          for (const time of schedule.times || []) reserved.add(String(time));
        }
      }
      return json({ times: [...reserved] }, 200, origin);
    }

    return json({ error: "Unknown action." }, 400, origin);
  } catch (error) {
    console.error("shoeapp-admin request failed", error);
    return json({ error: "관리자 요청을 처리하지 못했습니다. Supabase 설정을 확인해 주세요." }, 500, origin);
  }
});
