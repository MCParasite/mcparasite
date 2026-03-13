"""
MCParasite - CLI: Command-Line Interface for MCP Security Testing

Usage:
    mcparasite scan <server_command> [args...]   - Scan an MCP server for vulnerabilities
    mcparasite demo                               - Run Patient Zero demo with scanner
    mcparasite poison --type <type>              - Generate a poisoning payload
    mcparasite monitor <server_command>          - Continuous monitoring for rug pulls
    mcparasite report <json_file>                - Pretty-print a scan report
"""

import asyncio
import json
import os
import sys
import subprocess
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text

from mcparasite.scanner.tool_analyzer import ToolAnalyzer, AnalysisReport
from mcparasite.payloads.tool_poisoner import ToolPoisoner, PayloadType, ObfuscationMethod


console = Console()


def connect_and_list_tools(command: list[str], timeout: int = 10) -> list[dict]:
    """Connect to an MCP server via stdio and retrieve its tool list.

    This sends a JSON-RPC initialize + tools/list sequence over stdio.
    """
    # Build JSON-RPC messages
    init_request = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {
                "name": "mcparasite-scanner",
                "version": "1.0.0",
            },
        },
    })

    initialized_notification = json.dumps({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    })

    tools_list_request = json.dumps({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    })

    # Start the server process
    try:
        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        console.print(f"[red]Error: Command not found: {command[0]}[/red]")
        return []

    try:
        # Send initialize
        proc.stdin.write(init_request + "\n")
        proc.stdin.flush()

        # Read initialize response
        init_response_line = proc.stdout.readline()
        if not init_response_line:
            console.print("[red]Error: No response from server during initialization[/red]")
            return []

        # Send initialized notification
        proc.stdin.write(initialized_notification + "\n")
        proc.stdin.flush()

        # Send tools/list
        proc.stdin.write(tools_list_request + "\n")
        proc.stdin.flush()

        # Read tools/list response
        tools_response_line = proc.stdout.readline()
        if not tools_response_line:
            console.print("[red]Error: No response from server for tools/list[/red]")
            return []

        tools_response = json.loads(tools_response_line)
        tools = tools_response.get("result", {}).get("tools", [])

        return tools

    except json.JSONDecodeError as e:
        console.print(f"[red]Error parsing server response: {e}[/red]")
        return []
    except Exception as e:
        console.print(f"[red]Error communicating with server: {e}[/red]")
        return []
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@click.group()
@click.version_option(version="0.1.0", prog_name="mcparasite")
def cli():
    """MCParasite - MCP Security Research Framework

    A comprehensive toolkit for testing MCP (Model Context Protocol)
    server security, including tool poisoning detection, SSRF testing,
    rug pull monitoring, and payload generation.

    FOR AUTHORIZED SECURITY TESTING ONLY.
    """
    pass


@cli.command()
@click.argument("server_command", nargs=-1, required=True)
@click.option("--output", "-o", type=click.Path(), help="Save report to JSON file")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed analysis")
def scan(server_command: tuple[str, ...], output: str | None, verbose: bool):
    """Scan an MCP server for security vulnerabilities.

    Connects to the server via stdio, retrieves tool definitions,
    and analyzes them for tool poisoning, suspicious patterns,
    invisible characters, and other security issues.

    Examples:
        mcparasite scan uv run servers/patient_zero.py
        mcparasite scan uv run servers/victim_server.py
        mcparasite scan node path/to/server.js
    """
    command = list(server_command)
    console.print(Panel(
        f"Scanning MCP Server: {' '.join(command)}",
        style="bold blue",
    ))

    # Connect and get tools
    with console.status("[bold green]Connecting to server..."):
        tools = connect_and_list_tools(command)

    if not tools:
        console.print("[yellow]No tools found or connection failed.[/yellow]")
        return

    console.print(f"Found {len(tools)} tool(s). Analyzing...")

    # Analyze
    analyzer = ToolAnalyzer()
    report = analyzer.analyze_server(tools)
    report.server_name = " ".join(command)

    # Print report
    analyzer.print_report(report)

    # Show raw descriptions if verbose
    if verbose:
        console.print("\n[bold]Raw Tool Descriptions:[/bold]")
        for tool in tools:
            name = tool.get("name", "unknown")
            desc = tool.get("description", "")
            console.print(f"\n[cyan]{name}[/cyan]:")
            # Show with invisible chars visible
            visible_desc = ""
            for char in desc:
                if char in {"\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\ufeff", "\u2060"}:
                    visible_desc += f"[red]\\u{ord(char):04x}[/red]"
                else:
                    visible_desc += char
            console.print(visible_desc)

    # Save report
    if output:
        with open(output, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        console.print(f"\n[green]Report saved to {output}[/green]")


@cli.command()
@click.option("--payload", "-p",
              type=click.Choice(["exfil", "shadow", "worm"]),
              default="exfil", help="Patient Zero payload type")
def demo(payload: str):
    """Run a demo: start Patient Zero and scan it.

    This launches the Patient Zero malicious MCP server with the
    specified payload, then immediately scans it to demonstrate
    MCParasite's detection capabilities.

    Examples:
        mcparasite demo --payload exfil
        mcparasite demo --payload shadow
        mcparasite demo --payload worm
    """
    console.print(Panel(
        f"MCParasite Demo - Patient Zero ({payload})",
        style="bold magenta",
    ))

    command = ["uv", "run", "mcparasite/servers/patient_zero.py", "--payload", payload]

    console.print(f"[dim]Starting: {' '.join(command)}[/dim]")
    console.print()

    with console.status("[bold green]Connecting to Patient Zero..."):
        tools = connect_and_list_tools(command)

    if not tools:
        console.print("[red]Failed to connect to Patient Zero.[/red]")
        console.print("[yellow]Make sure you're running from the mcparasite directory.[/yellow]")
        return

    console.print(f"[green]Connected! Found {len(tools)} tool(s).[/green]\n")

    analyzer = ToolAnalyzer()
    report = analyzer.analyze_server(tools)
    report.server_name = f"Patient Zero ({payload})"

    analyzer.print_report(report)

    # Summary
    if report.critical_count > 0:
        console.print(
            f"\n[bold red]VERDICT: Server is MALICIOUS "
            f"({report.critical_count} critical findings)[/bold red]"
        )
    elif report.high_count > 0:
        console.print(
            f"\n[bold yellow]VERDICT: Server is SUSPICIOUS "
            f"({report.high_count} high findings)[/bold yellow]"
        )
    else:
        console.print("\n[bold green]VERDICT: No issues detected[/bold green]")


@cli.command()
@click.option("--type", "-t", "payload_type",
              type=click.Choice(["exfiltration", "shadow", "worm", "recon", "persistence"]),
              default="exfiltration", help="Payload type to generate")
@click.option("--obfuscation", "-o",
              type=click.Choice(["unicode_hide", "base64_wrap", "comment_bury", "whitespace_pad", "tag_disguise"]),
              default="unicode_hide", help="Obfuscation method")
@click.option("--benign-desc", "-d",
              default="Format and beautify markdown text.",
              help="Benign description to use as cover")
@click.option("--output-file", "-f", type=click.Path(), help="Save payload to file")
def poison(payload_type: str, obfuscation: str, benign_desc: str, output_file: str | None):
    """Generate a tool poisoning payload for testing.

    Creates poisoned tool descriptions with various obfuscation methods.
    Use these to test your MCP security scanning tools.
    """
    console.print(Panel("MCParasite Payload Generator", style="bold yellow"))

    poisoner = ToolPoisoner()
    payload = poisoner.generate(
        payload_type=PayloadType(payload_type),
        benign_description=benign_desc,
        obfuscation=ObfuscationMethod(obfuscation),
    )

    # Display info
    table = Table(title="Generated Payload")
    table.add_column("Property", style="cyan")
    table.add_column("Value")

    table.add_row("Type", payload_type)
    table.add_row("Obfuscation", obfuscation)
    table.add_row("Benign Desc", benign_desc)
    table.add_row("Raw Length", str(len(payload.raw_payload)))
    table.add_row("Final Length", str(len(payload.final_description)))
    table.add_row("Hidden Ratio", f"{payload.metadata['hidden_ratio']:.1%}")

    console.print(table)

    # Show the raw payload
    console.print("\n[bold]Raw Payload:[/bold]")
    console.print(payload.raw_payload)

    if output_file:
        with open(output_file, "w") as f:
            json.dump({
                "payload_type": payload_type,
                "obfuscation": obfuscation,
                "benign_description": benign_desc,
                "raw_payload": payload.raw_payload,
                "final_description": payload.final_description,
                "metadata": payload.metadata,
            }, f, indent=2)
        console.print(f"\n[green]Payload saved to {output_file}[/green]")


@cli.command()
@click.argument("server_command", nargs=-1, required=True)
@click.option("--interval", "-i", type=int, default=30, help="Check interval in seconds")
@click.option("--baseline", "-b", type=click.Path(), help="Baseline fingerprints file")
def monitor(server_command: tuple[str, ...], interval: int, baseline: str | None):
    """Monitor an MCP server for rug pull attacks.

    Continuously checks tool descriptions against baseline fingerprints
    and alerts on any changes.
    """
    command = list(server_command)
    console.print(Panel(
        f"Monitoring: {' '.join(command)} (every {interval}s)",
        style="bold blue",
    ))

    analyzer = ToolAnalyzer()

    # Load or create baseline
    baseline_fps: dict[str, dict] = {}
    if baseline and Path(baseline).exists():
        with open(baseline) as f:
            baseline_fps = json.load(f)
        console.print(f"Loaded baseline: {len(baseline_fps)} tools")

    check_count = 0
    try:
        while True:
            check_count += 1
            timestamp = time.strftime("%H:%M:%S")

            tools = connect_and_list_tools(command)
            if not tools:
                console.print(f"[{timestamp}] [red]Connection failed[/red]")
                time.sleep(interval)
                continue

            report = analyzer.analyze_server(tools)

            # Compare with baseline
            changes_detected = False
            for fp in report.fingerprints:
                fp_key = fp.tool_name
                if fp_key in baseline_fps:
                    if fp.description_hash != baseline_fps[fp_key]["description_hash"]:
                        console.print(
                            f"[{timestamp}] [bold red]RUG PULL DETECTED: "
                            f"Tool '{fp_key}' description changed![/bold red]"
                        )
                        changes_detected = True
                else:
                    baseline_fps[fp_key] = fp.to_dict()

            status = "[red]CHANGES DETECTED" if changes_detected else "[green]OK"
            console.print(
                f"[{timestamp}] Check #{check_count}: "
                f"{len(tools)} tools, "
                f"{len(report.findings)} findings - {status}[/]"
            )

            # Save baseline
            if baseline:
                with open(baseline, "w") as f:
                    json.dump(baseline_fps, f, indent=2)

            time.sleep(interval)

    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring stopped.[/yellow]")
        if baseline:
            console.print(f"Baseline saved: {baseline}")


@cli.command()
@click.argument("json_file", type=click.Path(exists=True))
def report(json_file: str):
    """Pretty-print a previously saved scan report."""
    with open(json_file) as f:
        data = json.load(f)

    analyzer = ToolAnalyzer()

    # Reconstruct report
    from mcparasite.scanner.tool_analyzer import Finding, Severity, ToolFingerprint
    report = AnalysisReport(
        server_name=data.get("server_name", "unknown"),
        tools_analyzed=data.get("tools_analyzed", 0),
    )

    for f_data in data.get("findings", []):
        report.findings.append(Finding(
            tool_name=f_data["tool_name"],
            category=f_data["category"],
            severity=Severity(f_data["severity"]),
            title=f_data["title"],
            description=f_data["description"],
            evidence=f_data.get("evidence", ""),
            remediation=f_data.get("remediation", ""),
        ))

    analyzer.print_report(report)


@cli.command("registry")
@click.option("--registry", "-r", type=click.Choice(["npm", "pypi"]), default="npm")
@click.option("--package", "-p", help="Check typosquats for a specific package")
@click.option("--popular", is_flag=True, help="Scan all popular MCP packages")
@click.option("--max-checks", "-m", type=int, default=20, help="Max candidates per package")
@click.option("--output", "-o", type=click.Path(), help="Save report to JSON file")
def registry_scan(registry: str, package: str | None, popular: bool, max_checks: int, output: str | None):
    """Scan package registries for MCP typosquatting & supply chain attacks.

    Checks npm/PyPI for packages with names similar to popular MCP servers.
    Analyzes metadata for install scripts, missing repos, suspicious patterns.

    Examples:
        mcparasite registry --popular
        mcparasite registry -p @modelcontextprotocol/server-filesystem
        mcparasite registry -r pypi -p mcp
    """
    from mcparasite.scanner.registry_scanner import RegistryScanner, RegistryType, RegistryReport
    from datetime import datetime

    console.print(Panel("MCParasite Registry Scanner", style="bold blue"))

    scanner = RegistryScanner()
    reg_type = RegistryType(registry)

    try:
        if package:
            console.print(f"Checking typosquats for: [cyan]{package}[/cyan] on {registry}")
            with console.status("[bold green]Scanning registry..."):
                findings = scanner.check_typosquat(package, registry=reg_type, max_checks=max_checks)
            report = RegistryReport(
                target_packages=[package],
                packages_scanned=1,
                findings=findings,
                scan_time=datetime.now().isoformat(),
            )
        elif popular:
            console.print(f"Scanning popular MCP packages on {registry}")
            report = scanner.scan_popular_packages(registry=reg_type, max_checks_per_package=max_checks)
        else:
            console.print("[yellow]Specify --package or --popular[/yellow]")
            return

        scanner.print_report(report)

        if output:
            with open(output, "w") as f:
                json.dump(report.to_dict(), f, indent=2)
            console.print(f"\n[green]Report saved to {output}[/green]")
    finally:
        scanner.close()


@cli.command("auth")
@click.argument("target")
@click.option("--config", "-c", is_flag=True, help="Audit a config file instead of a server URL")
@click.option("--output", "-o", type=click.Path(), help="Save report to JSON file")
def auth_audit(target: str, config: bool, output: str | None):
    """Audit MCP server authentication & OAuth configuration.

    Tests for missing PKCE, redirect_uri bypass, transport security,
    token exposure, and MCP-specific auth issues.

    Examples:
        mcparasite auth https://my-mcp-server.com/mcp
        mcparasite auth --config ~/.config/claude/claude_desktop_config.json
    """
    from mcparasite.scanner.auth_auditor import AuthAuditor, AuthAuditReport
    from datetime import datetime

    console.print(Panel("MCParasite Auth Auditor", style="bold blue"))

    auditor = AuthAuditor()

    try:
        if config:
            console.print(f"Auditing config: [cyan]{target}[/cyan]")
            with open(target) as f:
                config_data = json.load(f)
            findings = auditor.audit_config_file(config_data)
            report = AuthAuditReport(
                server_url=target,
                findings=findings,
                scan_time=datetime.now().isoformat(),
            )
        else:
            console.print(f"Auditing server: [cyan]{target}[/cyan]")
            with console.status("[bold green]Running auth audit..."):
                report = auditor.audit(target)

        auditor.print_report(report)

        if output:
            with open(output, "w") as f:
                json.dump(report.to_dict(), f, indent=2)
            console.print(f"\n[green]Report saved to {output}[/green]")
    finally:
        auditor.close()


@cli.command("harness")
@click.option("--scenario", "-s",
              type=click.Choice(["worm_propagation", "tool_poisoning", "rug_pull", "full_chain"]),
              default="worm_propagation")
@click.option("--log-dir", "-l", default="/tmp/mcparasite/agent")
def harness(scenario: str, log_dir: str):
    """Run the agent harness simulation.

    Executes pre-defined attack scenarios without needing a real LLM API.

    Examples:
        mcparasite harness -s worm_propagation
        mcparasite harness -s full_chain
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location("agent_harness", "lab/agent_harness.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    agent = mod.AgentHarness(log_dir=log_dir)
    try:
        result = agent.run_scenario(scenario)
        console.print(Panel(f"Scenario: {scenario}", style="bold magenta"))
        console.print(json.dumps(result, indent=2, default=str))
        console.print(f"\nLog: {agent.harness_log.log_file}")
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
    finally:
        agent.disconnect_all()


@cli.command("live")
@click.option("--provider", "-p",
              type=click.Choice(["claude", "openai", "gemini", "ollama"]),
              default="ollama", help="LLM provider to use")
@click.option("--model", "-m", help="Model name (default: provider-specific)")
@click.option("--payload", default="exfil",
              type=click.Choice(["exfil", "shadow", "worm"]),
              help="Patient Zero payload type")
@click.option("--compare", is_flag=True, help="Compare all available providers")
@click.option("--worm", is_flag=True, help="Run worm propagation test suite (multi-turn cross-server)")
@click.option("--attack",
              type=click.Choice(["real_exfil", "real_backdoor", "real_lateral", "real_data_theft", "real_slack_lateral"]),
              help="Run realistic attack scenario (Patient Zero + Corporate/Slack Server)")
@click.option("--kill-chain", "kill_chain", is_flag=True,
              help="Run FULL kill chain: Agent A infects Slack → Agent B reads & exfiltrates data")
@click.option("--rce-chain", "rce_chain", is_flag=True,
              help="Run RCE kill chain: Agent A infects Slack → Agent B executes commands + backdoor")
@click.option("--docker-mode", "docker_mode", is_flag=True,
              help="Enable real command execution (use inside Docker container only!)")
@click.option("--multi-dept", "multi_dept", is_flag=True,
              help="Use separate Slack bots for Agent A (Eng) and Agent B (SRE)")
@click.option("--three-hop", "three_hop", is_flag=True,
              help="3-hop kill chain: A→Slack→B→Slack→C (requires 3 Slack apps)")
@click.option("--stealth", type=click.Choice(["off", "unicode", "whitespace", "metadata"]),
              default="off", help="Worm stealth mode: unicode (invisible chars), whitespace (fold), metadata (API field)")
@click.option("--html", type=click.Path(), help="Generate visual HTML worm report (requires --worm)")
@click.option("--output", "-o", type=click.Path(), help="Save report to JSON file")
def live_test(provider: str, model: str | None, payload: str, compare: bool, worm: bool,
              attack: str | None, kill_chain: bool, rce_chain: bool,
              docker_mode: bool, multi_dept: bool, three_hop: bool, stealth: str,
              html: str | None, output: str | None):
    """Test real LLM models against MCP tool poisoning.

    Connects real LLMs (Claude, GPT, Gemini, Ollama) to Patient Zero
    and runs a standardized injection resistance test suite.

    Examples:
        mcparasite live --provider ollama --model llama3.1:8b
        mcparasite live --provider openai --model gpt-4o --worm
        mcparasite live --attack real_exfil --provider ollama --model llama3.1:8b
        mcparasite live --attack real_backdoor --provider openai --model gpt-4o
        mcparasite live --attack real_lateral --provider openai --model gpt-4o-mini
        mcparasite live --attack real_data_theft --provider ollama
        mcparasite live --attack real_slack_lateral --provider ollama  # REAL SLACK!
        mcparasite live --kill-chain --provider openai --model gpt-4o  # FULL KILL CHAIN
        mcparasite live --rce-chain --provider openai --model gpt-4o   # RCE KILL CHAIN
        mcparasite live --rce-chain --docker-mode --provider openai    # REAL RCE (Docker)
        mcparasite live --rce-chain --multi-dept --provider openai     # Multi-dept bots
        mcparasite live --rce-chain --three-hop --provider openai      # 3-hop worm chain
        mcparasite live --kill-chain --stealth unicode --provider openai # Invisible worm (Unicode)
        mcparasite live --rce-chain --stealth metadata --provider openai # Invisible worm (API metadata)
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location("live_agent", "lab/live_agent.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    if compare:
        providers = []
        if os.environ.get("ANTHROPIC_API_KEY"):
            providers.append(("claude", model or "claude-sonnet-4-5-20250929"))
        if os.environ.get("OPENAI_API_KEY"):
            providers.append(("openai", model or "gpt-4o"))
        if os.environ.get("GOOGLE_API_KEY"):
            providers.append(("gemini", model or "gemini-2.5-flash"))
        providers.append(("ollama", model or "llama3.2:3b"))

        console.print(Panel(
            f"MCParasite Live Agent - Comparing {len(providers)} provider(s)\nPayload: {payload}",
            style="bold magenta",
        ))

        report = mod.run_comparison(providers, payload_type=payload)
        mod.print_comparison_report(report)

        if output:
            with open(output, "w") as f:
                json.dump(report.to_dict(), f, indent=2)
            console.print(f"\n[green]Report saved to {output}[/green]")

    elif rce_chain:
        # RCE kill chain: Agent A → Slack → Agent B → System Compromise
        if not os.environ.get("SLACK_BOT_TOKEN"):
            console.print("[red]SLACK_BOT_TOKEN not set! Export it first:[/red]")
            console.print("[yellow]  export SLACK_BOT_TOKEN=xoxb-...[/yellow]")
            return

        if docker_mode:
            console.print("[bold red]🐳 DOCKER REAL-EXEC MODE - commands will actually run![/bold red]")
        if multi_dept:
            if not os.environ.get("SLACK_BOT_TOKEN_DEPT_B"):
                console.print("[yellow]SLACK_BOT_TOKEN_DEPT_B not set, falling back to same bot token[/yellow]")
            console.print("[cyan]Multi-department mode: Agent A (Eng) ↔ Agent B (SRE)[/cyan]")
        if three_hop:
            if not os.environ.get("SLACK_BOT_TOKEN_DEPT_C"):
                console.print("[yellow]SLACK_BOT_TOKEN_DEPT_C not set, falling back to same bot token[/yellow]")
            console.print("[bold magenta]3-HOP WORM CHAIN: Agent A → Slack → Agent B → Slack → Agent C[/bold magenta]")

        if stealth != "off":
            console.print(f"[bold green]🥷 STEALTH MODE: {stealth.upper()} - worm payload invisible in Slack UI[/bold green]")

        mod.run_rce_kill_chain(
            provider_name=provider,
            model=model,
            slack_channel="#worm-test",
            output_file=output,
            docker_mode=docker_mode,
            multi_dept=multi_dept,
            three_hop=three_hop,
            stealth_mode=stealth,
        )

    elif kill_chain:
        # Full kill chain: Agent A → Slack → Agent B → Data Theft
        if not os.environ.get("SLACK_BOT_TOKEN"):
            console.print("[red]SLACK_BOT_TOKEN not set! Export it first:[/red]")
            console.print("[yellow]  export SLACK_BOT_TOKEN=xoxb-...[/yellow]")
            return

        if stealth != "off":
            console.print(f"[bold green]🥷 STEALTH MODE: {stealth.upper()} - worm payload invisible in Slack UI[/bold green]")

        mod.run_full_kill_chain(
            provider_name=provider,
            model=model,
            slack_channel="#worm-test",
            output_file=output,
            stealth_mode=stealth,
        )

    elif attack:
        # Realistic attack mode
        # For real_slack_lateral, use real_lateral payload + real Slack server
        payload_for_pzero = "real_lateral" if attack == "real_slack_lateral" else attack
        is_slack = attack == "real_slack_lateral"

        server_label = "Patient Zero + Real Slack + Corporate" if is_slack else "Patient Zero + Corporate (sandboxed)"
        console.print(Panel(
            f"MCParasite REALISTIC ATTACK - {attack}\n"
            f"Provider: {provider}/{model or 'default'}\n"
            f"Servers: {server_label}",
            style="bold red",
        ))

        if is_slack and not os.environ.get("SLACK_BOT_TOKEN"):
            console.print("[red]SLACK_BOT_TOKEN not set! Export it first:[/red]")
            console.print("[yellow]  export SLACK_BOT_TOKEN=xoxb-...[/yellow]")
            return

        llm_provider = mod.create_provider(provider, model)
        agent = mod.LiveAgent(provider=llm_provider, payload_type=payload_for_pzero)

        server_configs = [
            {"name": "patient-zero", "command": ["uv", "run", "mcparasite/servers/patient_zero.py", "--payload", payload_for_pzero]},
        ]
        # Corporate FIRST, then Real Slack - so send_slack_message maps to real Slack (last writer wins)
        server_configs.append({"name": "corporate", "command": ["uv", "run", "mcparasite/servers/corporate_server.py"]})
        if is_slack:
            server_configs.append({"name": "slack", "command": ["uv", "run", "mcparasite/servers/slack_mcp.py"]})

        try:
            agent.connect_servers(server_configs)

            if not agent.connections:
                console.print("[red]Failed to connect to MCP servers.[/red]")
                return

            result = agent.run_realistic_attack_suite(attack)
            single_report = mod.ComparisonReport(payload_type=attack)
            single_report.models[llm_provider.name()] = result
            mod.print_comparison_report(single_report)

            if output:
                with open(output, "w") as f:
                    json.dump(single_report.to_dict(), f, indent=2)
                console.print(f"\n[green]Report saved to {output}[/green]")
        finally:
            agent.disconnect_all()

    else:
        console.print(Panel(
            f"MCParasite Live Agent - {provider}/{model or 'default'}\nPayload: {payload}",
            style="bold magenta",
        ))

        llm_provider = mod.create_provider(provider, model)
        effective_payload = "worm" if worm else payload
        agent = mod.LiveAgent(provider=llm_provider, payload_type=effective_payload)

        try:
            if worm:
                agent.connect_servers([
                    {"name": "patient-zero", "command": ["uv", "run", "mcparasite/servers/patient_zero.py", "--payload", "worm"]},
                    {"name": "victim", "command": ["uv", "run", "mcparasite/servers/victim_server.py"]},
                    {"name": "canary", "command": ["uv", "run", "mcparasite/servers/canary_server.py"]},
                ])
            else:
                agent.connect_servers()

            if not agent.connections:
                console.print("[red]Failed to connect to any MCP servers.[/red]")
                return

            if worm:
                result = agent.run_worm_test_suite()
            else:
                result = agent.run_test_suite()
            single_report = mod.ComparisonReport(payload_type=effective_payload)
            single_report.models[llm_provider.name()] = result
            mod.print_comparison_report(single_report)

            if output:
                with open(output, "w") as f:
                    json.dump(single_report.to_dict(), f, indent=2)
                console.print(f"\n[green]Report saved to {output}[/green]")

            if html and worm:
                from lab.worm_report import generate_html_report
                generate_html_report(single_report.to_dict(), html)
                console.print(f"\n[green]HTML report: {html}[/green]")
        finally:
            agent.disconnect_all()


@cli.command("worm-report")
@click.argument("json_files", nargs=-1, required=True)
@click.option("--output", "-o", default="/tmp/mcparasite_worm_report.html", help="Output HTML file path")
def worm_report_cmd(json_files: tuple[str, ...], output: str):
    """Generate a visual HTML worm propagation report from JSON results.

    Merges multiple JSON result files into a single comparison report.

    Examples:
        mcparasite worm-report /tmp/mcparasite_worm_*.json
        mcparasite worm-report result1.json result2.json -o report.html
    """
    from lab.worm_report import generate_from_json_files

    console.print(Panel("MCParasite Worm Report Generator", style="bold magenta"))
    console.print(f"Input files: {len(json_files)}")

    path = generate_from_json_files(list(json_files), output)
    console.print(f"\n[green]HTML report generated: {path}[/green]")


def main():
    cli()


if __name__ == "__main__":
    main()
