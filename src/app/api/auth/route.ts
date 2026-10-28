import { NextResponse } from "next/server";
import {
  authenticateWithAdminPassword,
  authenticateWithGithubToken,
  getAllowedGithubOwners,
  SESSION_COOKIE_NAME,
  signAdminSession,
  verifyRequestAdminAuth,
} from "@/lib/auth";

export async function GET(req: Request) {
  const { authorized, session } = verifyRequestAdminAuth(req);
  const owners = getAllowedGithubOwners();
  return NextResponse.json({
    authenticated: authorized,
    user: session?.user || null,
    method: session?.method || null,
    ownerHint: owners[0] ? `@${owners[0]}` : "@admin",
  });
}

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const { action, method, githubToken, password } = body as {
      action?: string;
      method?: "github" | "password";
      githubToken?: string;
      password?: string;
    };

    if (action === "logout") {
      const res = NextResponse.json({
        authenticated: false,
        user: null,
        method: null,
      });
      res.cookies.set(SESSION_COOKIE_NAME, "", {
        httpOnly: true,
        path: "/",
        maxAge: 0,
        sameSite: "lax",
      });
      return res;
    }

    if (method === "github") {
      const result = await authenticateWithGithubToken(githubToken || "");
      if (!result.ok || !result.username) {
        return NextResponse.json(
          { error: result.error || "GitHub doğrulaması başarısız." },
          { status: 401 }
        );
      }

      const sessionToken = signAdminSession(result.username, "github");
      const res = NextResponse.json({
        authenticated: true,
        user: result.username,
        method: "github",
      });
      res.cookies.set(SESSION_COOKIE_NAME, sessionToken, {
        httpOnly: true,
        path: "/",
        maxAge: 7 * 24 * 60 * 60,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
      });
      return res;
    }

    if (method === "password") {
      const result = authenticateWithAdminPassword(password || "");
      if (!result.ok || !result.username) {
        return NextResponse.json(
          { error: result.error || "Yönetici şifresi doğrulanamadı." },
          { status: 401 }
        );
      }

      const sessionToken = signAdminSession(result.username, "password");
      const res = NextResponse.json({
        authenticated: true,
        user: result.username,
        method: "password",
      });
      res.cookies.set(SESSION_COOKIE_NAME, sessionToken, {
        httpOnly: true,
        path: "/",
        maxAge: 7 * 24 * 60 * 60,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
      });
      return res;
    }

    return NextResponse.json(
      { error: "Geçersiz giriş yöntemi. 'github' veya 'password' seçin." },
      { status: 400 }
    );
  } catch (err) {
    return NextResponse.json(
      {
        error:
          err instanceof Error
            ? err.message
            : "Kimlik doğrulama sırasında sunucu hatası oluştu.",
      },
      { status: 500 }
    );
  }
}
