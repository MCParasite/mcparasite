#!/bin/bash
# MCParasite — Remote Setup Script
# Run this on the target Mac after extracting the archive
set -e

echo "================================================"
echo "  MCParasite — MCP Security Research Framework"
echo "  Remote Setup"
echo "================================================"
echo ""

# Check Python 3.12+
if ! command -v python3 &>/dev/null; then
    echo "❌ Python 3 not found. Install: brew install python@3.12"
    exit 1
fi

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 12 ]); then
    echo "❌ Python $PY_VER detected, need 3.12+. Install: brew install python@3.12"
    exit 1
fi
echo "✅ Python $PY_VER"

# Check/install uv
if ! command -v uv &>/dev/null; then
    echo "📦 Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi
echo "✅ uv $(uv --version)"

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
uv sync

# Check Ollama (optional)
if command -v ollama &>/dev/null; then
    echo "✅ Ollama found"
else
    echo "⚠️  Ollama not found (optional — needed for local model tests)"
    echo "   Install: brew install ollama"
fi

# Check Docker (optional)
if command -v docker &>/dev/null; then
    echo "✅ Docker found"
else
    echo "⚠️  Docker not found (optional — needed for containerized lab)"
fi

echo ""
echo "================================================"
echo "  Setup complete!"
echo "================================================"
echo ""
echo "🔑 Set API keys (add to ~/.zshrc or export):"
echo "   export OPENAI_API_KEY=sk-..."
echo "   export ANTHROPIC_API_KEY=sk-ant-..."
echo "   export GOOGLE_API_KEY=AI..."
echo ""
echo "🚀 Quick commands:"
echo "   uv run mcparasite scan servers/patient_zero.py    # Scan a server"
echo "   uv run mcparasite live --provider openai --worm   # Worm test (GPT-4o)"
echo "   uv run mcparasite live --provider ollama --model llama3.1:8b --worm"
echo "   uv run mcparasite dashboard                       # Launch dashboard"
echo "   uv run pytest tests/ -q                      # Run all tests"
echo ""
echo "🌐 Dashboard: http://localhost:5001"
echo ""
