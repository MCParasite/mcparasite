# MCParasite: Universal MCP Worm Security Testing Framework

MCParasite is an open-source security research tool that tests LLM-powered agents for susceptibility to **context worm attacks**, self-propagating prompt injections that spread autonomously across AI agents through shared communication channels.

## What is a Context Worm?

A context worm is a self-propagating prompt injection payload that:

1. **Infects**: enters an AI agent's context via a poisoned MCP tool description
2. **Propagates**: the infected agent writes the worm to a shared channel (Slack, email, GitHub issues, Jira tickets, wiki pages, etc.)
3. **Spreads**: a second, clean agent reads the channel and follows the worm's hidden instructions
4. **Executes**: the victim agent performs autonomous malicious actions like RCE, credential theft, data exfiltration, and further propagation

MCParasite demonstrates this attack across **14 communication platforms** and **12 attack scenarios**, with support for **4+ LLM providers**.

### Local RCE Chain (Zero Dependencies)
![Local RCE Kill Chain](demo/local_rce_chain_off.gif)

### Slack RCE with Unicode Stealth Encoding
![Slack RCE Chain](demo/slack_rce_chain_unicode.gif)

### GitHub Supply Chain Poisoning
![GitHub Supply Chain](demo/github_supply_chain_off.gif)

## Key Features

- **14 Propagation Channels**: Slack, Gmail, GitHub Issues, Discord, Microsoft Teams, Jira, Confluence, Google Drive, AWS S3, CI/CD Pipelines (GitHub Actions / GitLab CI / Jenkins), Notion, Linear, Webhooks, Local Simulation
- **12 Attack Scenarios**: RCE Chain, Data Exfiltration, Supply Chain Poisoning, Cross-Platform Cascade, Meeting Notes Hijack, Knowledge Base Worm, Customer Support Poisoning, Calendar & Email Mass Propagation, Cross-Company Supply Chain Worm, Developer Worm (PR/Issue Injection), Capability Recon Exfiltration, Rug Pull (Description Mutation)
- **Multi-Model Benchmarking**: Compare susceptibility across OpenAI GPT-4o, Anthropic Claude, Google Gemini, and local models (Ollama)
- **5 Stealth Encoding Modes**: Unicode Tag steganography (U+E0000-E007F), whitespace hiding, metadata injection, context truncation, link obfuscation
- **Zero-Dependency Demo Mode**: Local file-based channel simulation for air-gapped demos without any API keys or tokens
- **HTML Report Generator**: Comparative benchmark reports with visual charts
- **Channel-Agnostic Engine**: Plug any MCP server as a propagation channel

## Quick Start

```bash
git clone https://github.com/MCParasite/mcparasite.git
cd mcparasite
docker compose up
```

Open **http://localhost:8888** and the kill chain dashboard is ready.

### First Run (zero dependencies)

1. In the dashboard, select **Channel → local** and **Scenario → rce_chain**
2. Pick any model from the dropdown (e.g. `openai/gpt-4o-mini`)
3. Click **LAUNCH** and watch the worm propagate in real time
4. The **local** channel needs no API keys since it uses filesystem simulation

### Adding Real Channels

Click **🔑 API Keys** in the dashboard sidebar and paste your tokens. Keys are stored locally in `.mcparasite_keys.json` (git-ignored, never leaves your machine).

### Without Docker

```bash
# 1. Clone
git clone https://github.com/MCParasite/mcparasite.git
cd mcparasite

# 2. Install uv (skip if already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 3. Install dependencies (requires Python 3.12+)
uv sync

# 4. Install Playwright browsers
uv run playwright install

# 5. Launch dashboard
uv run python lab/dashboard.py

# Open http://localhost:5001
```

## Architecture

```
                    ┌──────────────┐
                    │ Patient Zero │ ← Poisoned MCP Server
                    │  (Worm Src)  │   (hidden payload in tool descriptions)
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │   Agent A    │ ← "DevOps Release Bot" (Infected)
                    │  (Carrier)   │   Reads poisoned tools, writes worm
                    └──────┬───────┘   to communication channel
                           │
              ┌────────────▼────────────┐
              │  Communication Channel  │ ← Any of 14 supported platforms
              │ (Slack/GitHub/Jira/...) │   Worm hidden via stealth encoding
              └────────────┬────────────┘
                           │
                    ┌──────▼───────┐
                    │   Agent B    │ ← "SRE Incident Bot" (Clean Victim)
                    │  (Victim)    │   Reads channel, follows worm instructions:
                    └──────┬───────┘   • curl|bash (RCE)
                           │           • credential theft
                           │           • data exfiltration
                           │           • further propagation
                    ┌──────▼───────┐
                    │   IMPACT     │
                    │  ANALYSIS    │ ← Compares expected vs. actual actions
                    └──────────────┘   to measure autonomous worm behavior
```

## Dashboard

Everything runs through the web dashboard. No config files, no CLI flags needed.

| Feature | Description |
|---------|-------------|
| **Channel selector** | Pick from 14 supported platforms |
| **Scenario selector** | 12 attack scenarios with YAML definitions |
| **Model picker** | OpenAI, Anthropic, Google, Ollama (one-click switch) |
| **Stealth mode** | off / unicode / whitespace / metadata / truncation / link |
| **Real-time event log** | Watch both hops execute live |
| **Impact analysis** | Side-by-side: expected behavior vs. worm-driven actions |
| **Webhook inspector** | See exfiltrated data arrive in real time |
| **API key manager** | Enter keys once via 🔑 sidebar, stored locally (never committed) |

### CLI (Advanced)

For scripting, CI, or headless benchmarks:

```bash
# Single run
uv run python cli.py run --channel slack --scenario rce_chain --provider openai --stealth unicode

# Multi-model benchmark
uv run python cli.py benchmark --scenario rce_chain \
    --models openai/gpt-4o claude/claude-sonnet-4-20250514 gemini/gemini-2.0-flash --runs 5

# HTML report
uv run python cli.py report --input /tmp/mcparasite_benchmark/benchmark_results.json
```

Environment variables for CI: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, `DEEPSEEK_API_KEY`, `SLACK_BOT_TOKEN`, `GITHUB_TOKEN`, `JIRA_API_TOKEN`, `DISCORD_BOT_TOKEN`, `NOTION_API_KEY`

## Supported Channels

| Channel | API/Protocol | Use Case |
|---------|-------------|----------|
| **Local** | Filesystem | Zero-dep demos, air-gapped testing |
| **Slack** | Web API | Team messaging, standups |
| **Gmail** | IMAP/SMTP | Email-based workflows |
| **GitHub** | REST API v3 | Issues, PRs, code review |
| **Discord** | Bot API v10 | Community/team chat |
| **MS Teams** | Graph API | Enterprise messaging |
| **Jira** | REST API v3 | Ticket workflows, sprint automation |
| **Confluence** | REST API v2 | Wiki, knowledge base |
| **Google Drive** | Docs API | Shared documents |
| **AWS S3** | boto3 | Shared cloud storage, configs |
| **CI/CD** | GH Actions / GitLab / Jenkins | Build pipelines |
| **Notion** | REST API | Project management, notes |
| **Linear** | GraphQL | Issue tracking |
| **Webhook** | HTTP POST | Generic integration |

## Attack Scenarios

| Scenario | Severity | Kill Chain |
|----------|----------|------------|
| **RCE Chain** | Critical | DevOps Bot → Channel → SRE Bot → `curl\|bash` |
| **Data Exfiltration** | Critical | HR Bot → Channel → Finance Bot → DB theft + email |
| **Supply Chain** | Critical | Triage Bot → Channel → CI/CD Bot → pipeline backdoor |
| **Cross-Platform** | Critical | Bot A → Channel → Bot B → multi-platform spread |
| **Meeting Hijack** | High | Notes Bot → Channel → Action Items Bot → RCE |
| **Knowledge Base** | High | Docs Bot → Channel → Research Bot → data theft |
| **Customer Support** | High | Portal Bot → Channel → Support Bot → data exfil |
| **Calendar & Email Mass Propagation** | Critical | Worm spreads via mass email and calendar invites |
| **Cross-Company Supply Chain Worm** | Critical | Worm crosses organizational boundaries via shared platforms |
| **Developer Worm (PR/Issue Injection)** | Critical | Worm spreads via GitHub issues, PRs, and code review with RCE |
| **Capability Recon Exfiltration** | High | Poisoned tool maps all connected MCP servers and exfiltrates capabilities |
| **Rug Pull (Description Mutation)** | Critical | MCP tool descriptions mutate from benign to malicious after trust is established |

## Stealth Encoding

MCParasite supports **five** stealth modes to hide worm payloads:

- **Unicode Tags** (`unicode`): Encodes payload in invisible Unicode Tag characters (U+E0000-E007F). Survives Slack, Teams, Discord, and most platforms. Invisible to humans, visible to LLMs.
- **Whitespace** (`whitespace`): Hides payload below 60 newlines (below "Show More" fold in most UIs).
- **Metadata** (`metadata`): Stores payload in message metadata fields (platform-dependent).
- **Truncation** (`truncation`): Hides payload using context window truncation techniques.
- **Link** (`link`): Embeds payload within URL/link structures that agents follow.

## Benchmark Mode

Run the same worm scenario N times against each model and compare infection rates:

```bash
uv run python cli.py benchmark \
    --models openai/gpt-4o openai/gpt-4o-mini claude/claude-sonnet-4-20250514 gemini/gemini-2.0-flash \
    --scenario rce_chain --runs 5 --stealth unicode
```

Generates an HTML report showing infection rate, autonomous action count, and RCE success per model.

## Project Structure

```
├── cli.py                  # CLI entry point
├── mcparasite/             # Core framework
│   ├── runner.py           # Kill chain runner
│   ├── engine.py           # Result analysis
│   ├── benchmark.py        # Multi-model benchmarks
│   ├── report.py           # HTML report generator
│   ├── config.py           # Configuration loader
│   ├── channels/           # 14 propagation channels
│   ├── servers/            # MCP server implementations
│   ├── scenarios/          # YAML attack definitions
│   ├── payloads/           # Worm payload profiles
│   ├── scanner/            # MCP security scanner
│   └── forensics/          # Analysis tools
├── lab/                    # Dashboard + live agent
├── demo/                   # Demo GIFs
└── tests/                  # Test suite
```

## Requirements

- **Docker** (recommended): just `docker compose up`
- Or: Python 3.12+ and [uv](https://docs.astral.sh/uv/) for native install
- At least one LLM provider API key, or use the **local** channel for zero-dependency demos

## Disclaimer

MCParasite is a security research tool for **authorized testing only**. It demonstrates vulnerabilities in the MCP ecosystem to help improve AI agent security. Use responsibly and only in environments you own or have explicit permission to test.

## License

MIT
