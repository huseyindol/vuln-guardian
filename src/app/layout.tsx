import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "VulnGuardian Studio — Otonom Zafiyet Tarama, Safe-Version Yama & Deploy Merkezi",
  description:
    "Projelerin zafiyet haberlerini (OSV.dev / CVE / GHSA) okuyan, zafiyetli paketleri safe versiyona çekip doğrulayarak deploy çıkan genel Antigravity Skill ve Kontrol Paneli.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="tr" className="dark">
      <body className="min-h-screen bg-[#0b0c0e] text-[#f3f4f6] antialiased selection:bg-[#d83a26] selection:text-white">
        {children}
      </body>
    </html>
  );
}
