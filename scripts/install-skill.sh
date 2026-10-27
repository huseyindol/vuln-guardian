#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL_SRC="$REPO_ROOT/.agents/skills/vuln-guardian"

echo "🛡️  VulnGuardian Skill Kurulumu Başlatılıyor..."

# 1. Google Antigravity Global Skill Directory
AGY_SKILLS_DIR="$HOME/.gemini/config/skills"
mkdir -p "$AGY_SKILLS_DIR"
ln -sfn "$SKILL_SRC" "$AGY_SKILLS_DIR/vuln-guardian"
echo "  ✓ Google Antigravity global skill bağlandı: $AGY_SKILLS_DIR/vuln-guardian"

# 2. Claude Code Global Skill Directory
CLAUDE_SKILLS_DIR="$HOME/.claude/skills"
mkdir -p "$CLAUDE_SKILLS_DIR"
ln -sfn "$SKILL_SRC" "$CLAUDE_SKILLS_DIR/vuln-guardian"
echo "  ✓ Claude Code global skill bağlandı: $CLAUDE_SKILLS_DIR/vuln-guardian"

# 3. Project-level .claude/skills symlink
mkdir -p "$REPO_ROOT/.claude/skills"
ln -sfn "$SKILL_SRC" "$REPO_ROOT/.claude/skills/vuln-guardian"
echo "  ✓ Proje içi .claude/skills/vuln-guardian bağlandı"

echo "✅ Kurulum tamamlandı! Artık tüm projelerinizde 'vuln-guardian' skill'ini kullanabilirsiniz."
