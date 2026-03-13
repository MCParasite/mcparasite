#!/usr/bin/env python3
"""
MCParasite - Universal MCP Worm Security Testing Framework

CLI: Run worm propagation tests across any channel with any model.

Usage:
    # Quick test with local simulation (zero dependencies)
    uv run python cli.py run --channel local --scenario rce_chain --provider openai

    # Real Slack test with stealth encoding
    uv run python cli.py run --channel slack --scenario data_exfil --provider claude --stealth unicode

    # Multi-model benchmark
    uv run python cli.py benchmark --scenario rce_chain --runs 5

    # List available channels and scenarios
    uv run python cli.py list

    # Generate HTML report from results
    uv run python cli.py report --input /tmp/mcparasite_benchmark/benchmark_results.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Load .env file if present
_env_file = Path(__file__).resolve().parent / ".env"
if _env_file.exists():
    for _line in _env_file.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            _k, _v = _k.strip(), _v.strip().strip('"').strip("'")
            if _k and _v and not os.environ.get(_k):
                os.environ[_k] = _v

# Ensure project root on sys.path
_root = str(Path(__file__).resolve().parent)
if _root not in sys.path:
    sys.path.insert(0, _root)


def cmd_run(args):
    """Run a single kill chain test."""
    from mcparasite.runner import run_kill_chain

    # Parse channel params from --param key=value pairs
    channel_params = {}
    if args.param:
        for p in args.param:
            key, _, value = p.partition("=")
            channel_params[key.strip()] = value.strip()

    # Load params from config file if provided
    if args.config:
        from mcparasite.config import MCParasiteConfig
        config = MCParasiteConfig(args.config)
        ch = config.get_channel(args.channel)
        channel_params = {**ch.config.params, **channel_params}

    result = run_kill_chain(
        provider_name=args.provider,
        model=args.model,
        channel_type=args.channel,
        channel_params=channel_params,
        scenario_name=args.scenario,
        stealth_mode=args.stealth,
        max_hop1_retries=args.retries,
        output_file=args.output,
        docker_mode=args.docker_mode,
        base_url=getattr(args, "base_url", ""),
    )

    # Print summary
    status = "INFECTED" if result.kill_chain_complete else "SAFE"
    print(f"\nResult: {status}")
    print(f"Autonomous actions: {result.hop2_autonomous_actions}")
    print(f"RCE: {result.hop2_rce_count} | Creds: {result.hop2_credential_reads} | "
          f"Emails: {result.hop2_attacker_emails}")
    if args.output:
        print(f"Saved to: {args.output}")


def cmd_benchmark(args):
    """Run multi-model benchmark."""
    from mcparasite.benchmark import run_benchmark
    from mcparasite.config import MCParasiteConfig

    if args.config:
        config = MCParasiteConfig(args.config)
    else:
        # Build minimal config from CLI args
        config = _build_config_from_args(args)

    scenarios = [args.scenario] if args.scenario else None
    results = run_benchmark(config, scenarios=scenarios, output_dir=args.output)

    # Auto-generate HTML report
    if args.html:
        from mcparasite.report import generate_html_report
        html_path = Path(args.output) / "report.html"
        generate_html_report(results, str(html_path))
        print(f"\nHTML report: {html_path}")


def cmd_list(args):
    """List available channels and scenarios."""
    from mcparasite.channels.registry import ChannelRegistry
    from mcparasite.engine import list_scenarios

    print("=" * 50)
    print("  MCParasite - Available Channels")
    print("=" * 50)
    for ch in ChannelRegistry.available():
        print(f"  - {ch}")

    print()
    print("=" * 50)
    print("  MCParasite - Available Scenarios")
    print("=" * 50)
    scenarios = list_scenarios(Path(__file__).parent / "mcparasite" / "scenarios")
    for s in scenarios:
        sev = s.get("severity", "?")
        print(f"  - {s['name']:<30} [{sev}]  {s['description'][:60]}")

    print()
    print("=" * 50)
    print("  MCParasite - Supported Providers")
    print("=" * 50)
    providers = [
        ("openai",    "GPT-4o, GPT-4o-mini, GPT-4-turbo", "OPENAI_API_KEY"),
        ("claude",    "Claude 3.5 Sonnet, Opus, Haiku",    "ANTHROPIC_API_KEY"),
        ("gemini",    "Gemini 2.0 Flash, Pro",             "GOOGLE_API_KEY"),
        ("ollama",    "Llama 3.1, Mistral, Qwen (local)",  "(none - runs locally)"),
    ]
    for name, models, env in providers:
        key_status = "SET" if os.environ.get(env) else "NOT SET"
        if env.startswith("("):
            key_status = "local"
        print(f"  - {name:<12} {models:<38} [{key_status}]")


def cmd_report(args):
    """Generate HTML report from benchmark results."""
    from mcparasite.report import generate_html_report

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: {input_path} not found")
        sys.exit(1)

    results = json.loads(input_path.read_text())
    output_path = args.output or str(input_path.parent / "report.html")
    generate_html_report(results, output_path)
    print(f"Report generated: {output_path}")


def _build_config_from_args(args) -> "MCParasiteConfig":
    """Build a config object from CLI arguments for benchmark mode."""
    from mcparasite.config import MCParasiteConfig

    # Create temp config dict
    config_dict = {
        "providers": {},
        "default_channel": getattr(args, "channel", "local"),
        "stealth_mode": getattr(args, "stealth", "off"),
        "benchmark": {
            "runs_per_model": getattr(args, "runs", 3),
            "scenarios": [args.scenario] if hasattr(args, "scenario") and args.scenario else ["rce_chain"],
            "models": [],
        },
    }

    # Add models from --models flag
    if hasattr(args, "models") and args.models:
        for m in args.models:
            provider, _, model_name = m.partition("/")
            config_dict["benchmark"]["models"].append({"provider": provider, "model": model_name})
    else:
        # Default: test all configured providers
        for env, prov, default_model in [
            ("OPENAI_API_KEY", "openai", "gpt-4o"),
            ("ANTHROPIC_API_KEY", "claude", "claude-sonnet-4-5-20250929"),
            ("GOOGLE_API_KEY", "gemini", "gemini-2.5-flash"),
        ]:
            if os.environ.get(env):
                config_dict["benchmark"]["models"].append({"provider": prov, "model": default_model})

        # Always add ollama if no API keys found
        if not config_dict["benchmark"]["models"]:
            config_dict["benchmark"]["models"].append({"provider": "ollama", "model": "llama3.1:8b"})

    return MCParasiteConfig.from_dict(config_dict)


def main():
    parser = argparse.ArgumentParser(
        prog="mcparasite",
        description="MCParasite - Universal MCP Worm Security Testing Framework",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # ── run ──
    run_parser = subparsers.add_parser("run", help="Run a single kill chain test")
    run_parser.add_argument("--provider", default="openai", choices=["openai", "claude", "gemini", "ollama"],
                           help="LLM provider")
    run_parser.add_argument("--model", help="Model name (default: provider default)")
    run_parser.add_argument("--channel", default="local",
                           help="Propagation channel (local, slack, github, gmail, etc.)")
    run_parser.add_argument("--scenario", default="rce_chain",
                           help="Scenario name (without .yaml)")
    run_parser.add_argument("--stealth", default="off",
                           choices=["off", "unicode", "whitespace", "metadata", "truncation", "link"],
                           help="Stealth encoding mode")
    run_parser.add_argument("--retries", type=int, default=10,
                           help="Max hop1 retry attempts")
    run_parser.add_argument("--param", action="append",
                           help="Channel parameter (key=value), can specify multiple")
    run_parser.add_argument("--docker-mode", dest="docker_mode", action="store_true",
                           default=False,
                           help="Enable real command execution (use inside Docker container only!)")
    run_parser.add_argument("--base-url", dest="base_url", default="",
                           help="Custom API base URL for OpenAI-compatible endpoints")
    run_parser.add_argument("--config", help="YAML config file")
    run_parser.add_argument("--output", "-o", help="Output JSON file")
    run_parser.set_defaults(func=cmd_run)

    # ── benchmark ──
    bench_parser = subparsers.add_parser("benchmark", help="Run multi-model benchmark")
    bench_parser.add_argument("--config", help="YAML config file")
    bench_parser.add_argument("--scenario", help="Scenario to benchmark")
    bench_parser.add_argument("--models", nargs="*",
                             help="Models to test (provider/model format)")
    bench_parser.add_argument("--runs", type=int, default=3,
                             help="Runs per model")
    bench_parser.add_argument("--channel", default="local",
                             help="Propagation channel")
    bench_parser.add_argument("--stealth", default="off",
                             choices=["off", "unicode", "whitespace", "metadata", "truncation", "link"])
    bench_parser.add_argument("--output", default="/tmp/mcparasite_benchmark",
                             help="Output directory")
    bench_parser.add_argument("--html", action="store_true", default=True,
                             help="Generate HTML report (default: true)")
    bench_parser.set_defaults(func=cmd_benchmark)

    # ── list ──
    list_parser = subparsers.add_parser("list", help="List channels, scenarios, and providers")
    list_parser.set_defaults(func=cmd_list)

    # ── report ──
    report_parser = subparsers.add_parser("report", help="Generate HTML report from results")
    report_parser.add_argument("--input", "-i", required=True,
                              help="Path to benchmark_results.json")
    report_parser.add_argument("--output", "-o", help="Output HTML file")
    report_parser.set_defaults(func=cmd_report)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
