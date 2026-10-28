import crypto from "node:crypto";

export const SESSION_COOKIE_NAME = "vg_session";
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export interface AdminSessionPayload {
  user: string;
  method: "github" | "password";
  exp: number;
}

function getSigningSecret(): string {
  return (
    process.env.GUARDIAN_AUTH_SECRET ||
    process.env.GUARDIAN_ADMIN_PASSWORD ||
    process.env.CRON_SECRET ||
    process.env.GITHUB_TOKEN ||
    "vuln-guardian-default-signing-key-change-in-prod"
  );
}

export function getAllowedGithubOwners(): string[] {
  const raw =
    process.env.GUARDIAN_ALLOWED_GITHUB_USERS ||
    process.env.GITHUB_OWNER ||
    "huseyindol";
  return raw
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

export function signAdminSession(
  user: string,
  method: "github" | "password"
): string {
  const payload: AdminSessionPayload = {
    user,
    method,
    exp: Date.now() + SESSION_TTL_MS,
  };
  const data = Buffer.from(JSON.stringify(payload), "utf8").toString(
    "base64url"
  );
  const sig = crypto
    .createHmac("sha256", getSigningSecret())
    .update(data)
    .digest("base64url");
  return `${data}.${sig}`;
}

export function verifyAdminSessionToken(
  token: string | undefined | null
): AdminSessionPayload | null {
  if (!token || !token.includes(".")) return null;
  const [data, sig] = token.split(".");
  if (!data || !sig) return null;

  const expectedSig = crypto
    .createHmac("sha256", getSigningSecret())
    .update(data)
    .digest("base64url");

  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expectedSig);
  if (
    sigBuf.length !== expBuf.length ||
    !crypto.timingSafeEqual(sigBuf, expBuf)
  ) {
    return null;
  }

  try {
    const parsed = JSON.parse(
      Buffer.from(data, "base64url").toString("utf8")
    ) as AdminSessionPayload;
    if (!parsed.exp || Date.now() > parsed.exp) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function extractCookieValue(
  cookieHeader: string | null,
  name: string
): string | null {
  if (!cookieHeader) return null;
  const parts = cookieHeader.split(";");
  for (const part of parts) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) {
      return decodeURIComponent(rest.join("="));
    }
  }
  return null;
}

export function verifyRequestAdminAuth(req: Request): {
  authorized: boolean;
  session: AdminSessionPayload | null;
} {
  const cookieHeader = req.headers.get("cookie");
  const cookieToken = extractCookieValue(cookieHeader, SESSION_COOKIE_NAME);
  const headerToken = req.headers.get("x-guardian-session");
  const session = verifyAdminSessionToken(cookieToken || headerToken);
  return {
    authorized: Boolean(session),
    session,
  };
}

export async function authenticateWithGithubToken(
  inputToken: string
): Promise<{ ok: boolean; username?: string; error?: string }> {
  const trimmed = inputToken.trim();
  if (!trimmed) {
    return { ok: false, error: "Lütfen geçerli bir GitHub Token girin." };
  }

  // Direct match with server's configured GITHUB_TOKEN
  const serverGhToken = process.env.GITHUB_TOKEN?.trim();
  const allowedOwners = getAllowedGithubOwners();

  try {
    const res = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${trimmed}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      cache: "no-store",
    });

    if (!res.ok) {
      return {
        ok: false,
        error: "GitHub Token doğrulanamadı (Geçersiz veya süresi dolmuş token).",
      };
    }

    const userData = (await res.json()) as { login?: string };
    const login = (userData.login || "").trim();
    if (!login) {
      return { ok: false, error: "GitHub kullanıcı bilgisi alınamadı." };
    }

    const isAllowedUser = allowedOwners.includes(login.toLowerCase());
    const isExactServerToken = Boolean(
      serverGhToken && trimmed === serverGhToken
    );

    if (!isAllowedUser && !isExactServerToken) {
      return {
        ok: false,
        error: `Bu GitHub hesabı (@${login}) bu komuta merkezinde yönetici yetkisine sahip değil. Yalnızca yetkili hesap (@${allowedOwners[0] || "admin"}) işlem yapabilir.`,
      };
    }

    return { ok: true, username: `@${login}` };
  } catch {
    return {
      ok: false,
      error: "GitHub API ile bağlantı kurulamadı. Lütfen tekrar deneyin.",
    };
  }
}

export function authenticateWithAdminPassword(inputPassword: string): {
  ok: boolean;
  username?: string;
  error?: string;
} {
  const trimmed = inputPassword.trim();
  if (!trimmed) {
    return { ok: false, error: "Lütfen kurulum yönetici şifresini girin." };
  }

  const configuredAdminPassword = process.env.GUARDIAN_ADMIN_PASSWORD?.trim();
  const cronSecret = process.env.CRON_SECRET?.trim();
  const serverGhToken = process.env.GITHUB_TOKEN?.trim();

  const validSecrets = [
    configuredAdminPassword,
    cronSecret,
    serverGhToken,
  ].filter((v): v is string => Boolean(v && v.length >= 4));

  if (validSecrets.length === 0) {
    return {
      ok: false,
      error:
        "Sunucuda henüz GUARDIAN_ADMIN_PASSWORD tanımlanmamış. Lütfen GitHub sekmesinden giriş yapın veya ortam değişkenlerine GUARDIAN_ADMIN_PASSWORD ekleyin.",
    };
  }

  const matched = validSecrets.some((secret) => {
    const a = Buffer.from(trimmed);
    const b = Buffer.from(secret);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  });

  if (!matched) {
    return {
      ok: false,
      error: "Girilen yönetici şifresi hatalı. Yetkiniz doğrulanamadı.",
    };
  }

  const owner = getAllowedGithubOwners()[0] || "admin";
  return { ok: true, username: `${owner} (Yönetici Şifresi)` };
}
