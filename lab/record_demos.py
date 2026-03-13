#!/usr/bin/env python3
"""
MCParasite Demo Recorder
========================
Records kill chain demos with Playwright - clean Chromium, zero extensions.
Human-like interaction: natural clicks, scrolling, timing.

Fixes layout shift issues by injecting CSS that makes each column
independently scrollable with fixed height.

Usage:
    uv run python lab/record_demos.py --channel local --scenario rce_chain --stealth off
    uv run python lab/record_demos.py --dry-run
    uv run python lab/record_demos.py
    uv run python lab/record_demos.py --gif-only
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

# ─── Config ───
DASHBOARD_URL = "http://localhost:5001"
AUTH_USER = os.environ.get("MCPARASITE_AUTH_USER", "")
AUTH_PASS = os.environ.get("MCPARASITE_AUTH_PASS", "")
RECORDINGS_DIR = Path(__file__).parent / "recordings"
MP4_DIR = RECORDINGS_DIR / "mp4"
GIF_DIR = RECORDINGS_DIR / "gif"

# Wide viewport - dashboard is designed for ultrawide
VIEWPORT_W = 2560
VIEWPORT_H = 1440

KC_TIMEOUT = 480  # 8 min max

DEFAULT_PROVIDER = "openai"
DEFAULT_MODEL = "gpt-4o-mini"


# ─── CSS override injected into the page to stabilize layout for recording ───
RECORDING_CSS = """
/* ── Recording Mode: Stabilize layout to prevent shifts ── */

/* Widen container to fill 2560px viewport better */
.container { max-width: 2400px !important; padding: 12px 24px !important; }

/* Make all three grid columns fixed-height and independently scrollable */
.kc-layout {
    grid-template-columns: 320px 1fr 440px !important;
    gap: 14px !important;
    height: calc(100vh - 130px) !important;
    min-height: unset !important;
    overflow: hidden !important;
}
.kc-layout > div,
.kc-layout > .impact-panel {
    overflow-y: auto !important;
    max-height: calc(100vh - 140px) !important;
    scrollbar-width: thin !important;
}

/* Disable ALL transitions and animations - they cause frame jitter in video */
*, *::before, *::after {
    transition-duration: 0s !important;
    transition-delay: 0s !important;
    animation-duration: 0.01s !important;
    animation-delay: 0s !important;
}

/* But keep the step-body expansion smooth (looks good in recording) */
.step-body {
    transition: max-height 0.25s ease !important;
}

/* Keep the step cards collapsed by default - they auto-expand during attack */
/* This prevents big layout shifts from pre-expanded cards */

/* Make log area fill its column and scroll internally */
#kc-log {
    max-height: calc(100vh - 260px) !important;
    overflow-y: auto !important;
}

/* Impact panel columns: scroll internally */
.impact-panel .panel {
    max-height: 45vh !important;
    overflow-y: auto !important;
}

/* Hide scrollbars for cleaner recording (webkit) */
.kc-layout > div::-webkit-scrollbar,
.kc-layout > .impact-panel::-webkit-scrollbar,
#kc-log::-webkit-scrollbar,
.impact-panel .panel::-webkit-scrollbar {
    width: 4px !important;
}
.kc-layout > div::-webkit-scrollbar-thumb,
.kc-layout > .impact-panel::-webkit-scrollbar-thumb {
    background: rgba(255,255,255,0.1) !important;
    border-radius: 2px !important;
}

/* Step cards: cap their expanded height so they don't push the launch button off-screen */
.step-card.open .step-body {
    max-height: 350px !important;
    overflow-y: auto !important;
}

/* The step panel itself should be scrollable */
.step-panel {
    max-height: calc(100vh - 360px) !important;
    overflow-y: auto !important;
}

/* Ensure the launch section (kc-start) is always visible at the bottom of left col */
.kc-start {
    position: sticky !important;
    bottom: 0 !important;
    background: var(--bg) !important;
    z-index: 10 !important;
    padding-top: 8px !important;
    border-top: 1px solid var(--border) !important;
}

/* Fix header to not be too tall */
.top-bar { padding: 8px 20px !important; }

/* No body scroll - columns scroll independently */
body { overflow: hidden !important; }
html { overflow: hidden !important; }
"""


# ─── Demo Matrix ───
DEMO_MATRIX = [
    # Slack
    {"channel": "slack", "scenario": "rce_chain",       "stealth": "off"},
    {"channel": "slack", "scenario": "rce_chain",       "stealth": "unicode"},
    {"channel": "slack", "scenario": "data_exfil",      "stealth": "off"},
    {"channel": "slack", "scenario": "data_exfil",      "stealth": "unicode"},
    {"channel": "slack", "scenario": "calendar_worm",   "stealth": "off"},
    {"channel": "slack", "scenario": "calendar_worm",   "stealth": "unicode"},
    {"channel": "slack", "scenario": "cross_company",   "stealth": "off"},
    {"channel": "slack", "scenario": "cross_company",   "stealth": "unicode"},
    {"channel": "slack", "scenario": "supply_chain",    "stealth": "off"},
    {"channel": "slack", "scenario": "supply_chain",    "stealth": "unicode"},
    # Discord
    {"channel": "discord", "scenario": "rce_chain",      "stealth": "off"},
    {"channel": "discord", "scenario": "rce_chain",      "stealth": "unicode"},
    {"channel": "discord", "scenario": "data_exfil",     "stealth": "off"},
    {"channel": "discord", "scenario": "data_exfil",     "stealth": "unicode"},
    {"channel": "discord", "scenario": "developer_worm", "stealth": "off"},
    {"channel": "discord", "scenario": "developer_worm", "stealth": "unicode"},
    # Jira
    {"channel": "jira", "scenario": "rce_chain",      "stealth": "off"},
    {"channel": "jira", "scenario": "rce_chain",      "stealth": "unicode"},
    {"channel": "jira", "scenario": "data_exfil",     "stealth": "off"},
    {"channel": "jira", "scenario": "data_exfil",     "stealth": "unicode"},
    {"channel": "jira", "scenario": "supply_chain",   "stealth": "off"},
    {"channel": "jira", "scenario": "supply_chain",   "stealth": "unicode"},
    # GitHub
    {"channel": "github", "scenario": "rce_chain",       "stealth": "off"},
    {"channel": "github", "scenario": "rce_chain",       "stealth": "unicode"},
    {"channel": "github", "scenario": "developer_worm",  "stealth": "off"},
    {"channel": "github", "scenario": "developer_worm",  "stealth": "unicode"},
    {"channel": "github", "scenario": "supply_chain",    "stealth": "off"},
    {"channel": "github", "scenario": "supply_chain",    "stealth": "unicode"},
    # Notion
    {"channel": "notion", "scenario": "rce_chain",           "stealth": "off"},
    {"channel": "notion", "scenario": "rce_chain",           "stealth": "unicode"},
    {"channel": "notion", "scenario": "knowledge_base_worm", "stealth": "off"},
    {"channel": "notion", "scenario": "knowledge_base_worm", "stealth": "unicode"},
    {"channel": "notion", "scenario": "cross_company",       "stealth": "off"},
    {"channel": "notion", "scenario": "cross_company",       "stealth": "unicode"},
    # Gmail
    {"channel": "gmail", "scenario": "calendar_worm", "stealth": "off"},
    {"channel": "gmail", "scenario": "calendar_worm", "stealth": "unicode"},
    {"channel": "gmail", "scenario": "data_exfil",    "stealth": "off"},
    {"channel": "gmail", "scenario": "data_exfil",    "stealth": "unicode"},
    # Confluence
    {"channel": "confluence", "scenario": "knowledge_base_worm", "stealth": "off"},
    {"channel": "confluence", "scenario": "knowledge_base_worm", "stealth": "unicode"},
    {"channel": "confluence", "scenario": "rce_chain",           "stealth": "off"},
    {"channel": "confluence", "scenario": "rce_chain",           "stealth": "unicode"},
    # Linear
    {"channel": "linear", "scenario": "rce_chain",      "stealth": "off"},
    {"channel": "linear", "scenario": "rce_chain",      "stealth": "unicode"},
    {"channel": "linear", "scenario": "developer_worm", "stealth": "off"},
    {"channel": "linear", "scenario": "developer_worm", "stealth": "unicode"},
    # Local (baseline)
    {"channel": "local", "scenario": "rce_chain",   "stealth": "off"},
    {"channel": "local", "scenario": "rce_chain",   "stealth": "unicode"},
    {"channel": "local", "scenario": "data_exfil",  "stealth": "off"},
    {"channel": "local", "scenario": "recon_exfil", "stealth": "off"},
    {"channel": "local", "scenario": "rug_pull",    "stealth": "off"},
]


def make_filename(ch, sc, st):
    return f"{ch}_{sc}_{st}"


def generate_gif(mp4_path: str, gif_path: str, max_dur: int = 20):
    pal = mp4_path.replace(".mp4", "_pal.png")
    subprocess.run(["ffmpeg", "-y", "-i", mp4_path, "-t", str(max_dur),
                     "-vf", "fps=12,scale=1280:-1:flags=lanczos,palettegen=stats_mode=diff",
                     pal], capture_output=True)
    subprocess.run(["ffmpeg", "-y", "-i", mp4_path, "-i", pal, "-t", str(max_dur),
                     "-lavfi", "fps=12,scale=1280:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=3",
                     gif_path], capture_output=True)
    if os.path.exists(pal):
        os.remove(pal)


def inject_recording_css(page):
    """Inject CSS overrides that stabilize layout for recording."""
    page.add_style_tag(content=RECORDING_CSS)
    page.wait_for_timeout(200)


def collapse_all_steps(page):
    """Collapse all step cards to start clean."""
    page.evaluate("""() => {
        document.querySelectorAll('.step-card.open').forEach(c => c.classList.remove('open'));
    }""")
    page.wait_for_timeout(200)


def wait_for_completion(page, timeout: int = KC_TIMEOUT) -> tuple[bool, float]:
    """Wait for kill chain to complete by watching the page."""
    start = time.time()
    last_log = ""

    while time.time() - start < timeout:
        try:
            status = page.evaluate("""() => {
                const btn = document.getElementById('kc-launch-btn');
                const btnText = btn ? btn.textContent.trim() : '';
                const badge3 = (document.getElementById('step-3-badge') || {}).textContent || '';
                const s2 = (document.getElementById('step-2-badge') || {}).textContent || '';
                const logArea = document.getElementById('kc-log-area');
                const logText = logArea ? logArea.innerText : '';
                const done = btnText.includes('COMPLETE') || btnText.includes('RELAUNCH') ||
                             btnText.includes('RETRY') || btnText.includes('FAILED') ||
                             logText.includes('Result saved') || logText.includes('Process exited') ||
                             logText.includes('COMPLETE');
                return { btnText, badge3: badge3.trim(), s2: s2.trim(), done, logLen: logText.length };
            }""")

            elapsed = int(time.time() - start)
            log_line = f"[{elapsed}s] btn={status['btnText'][:30]} hop2={status['s2']} impact={status['badge3']} log={status['logLen']}"
            if log_line != last_log:
                print(f"         {log_line}")
                last_log = log_line

            # Check completion - need minimum 15s to avoid false positives
            if elapsed > 15 and status["done"]:
                success = "COMPLETE" in status["btnText"].upper() or status["badge3"] not in ("-", "WAIT", "")
                return success, time.time() - start

        except Exception as e:
            print(f"         [poll error: {e}]")

        page.wait_for_timeout(3000)

    return False, time.time() - start


def record_single(page, channel: str, scenario: str, stealth: str,
                   provider: str, model: str) -> dict:
    """Record one kill chain - NO main page scrolling, columns scroll independently."""

    tag = f"{channel}/{scenario}/stealth={stealth}"

    # ── 1. Collapse all step cards for clean start ──
    collapse_all_steps(page)
    page.wait_for_timeout(300)

    # ── 2. Select channel ──
    print(f"   [1/5] Selecting channel: {channel}")
    page.evaluate(f"""() => {{
        const sel = document.getElementById('kc-channel');
        if (sel) {{ sel.value = '{channel}'; sel.dispatchEvent(new Event('change')); }}
    }}""")
    page.wait_for_timeout(700)

    # ── 3. Select scenario ──
    print(f"   [2/5] Selecting scenario: {scenario}")
    page.evaluate(f"""() => {{
        const sel = document.getElementById('kc-scenario');
        if (sel) {{ sel.value = '{scenario}'; sel.dispatchEvent(new Event('change')); }}
    }}""")
    page.wait_for_timeout(700)

    # ── 4. Select model ──
    print(f"   [3/5] Selecting model: {provider}/{model}")
    model_val = f"{provider}/{model}"
    found = page.evaluate(f"""() => {{
        const sel = document.getElementById('kc-provider');
        if (!sel) return false;
        // Exact match first
        for (const opt of sel.options) {{
            if (opt.value === '{model_val}') {{
                sel.value = opt.value;
                sel.dispatchEvent(new Event('change'));
                return true;
            }}
        }}
        // Partial match on model name
        for (const opt of sel.options) {{
            if (opt.value.includes('{model}')) {{
                sel.value = opt.value;
                sel.dispatchEvent(new Event('change'));
                return true;
            }}
        }}
        return false;
    }}""")
    if not found:
        print(f"   ⚠️  Model {model_val} not found in dropdown!")
    page.wait_for_timeout(500)

    # ── 5. Select stealth ──
    print(f"   [4/5] Setting stealth: {stealth}")
    page.evaluate(f"""() => {{
        const sel = document.getElementById('stealth-mode-select');
        if (sel) {{ sel.value = '{stealth}'; sel.dispatchEvent(new Event('change')); }}
    }}""")
    page.wait_for_timeout(500)

    # ── 6. Show configured state for 2.5s (let viewer see the setup) ──
    print(f"   [5/5] Showing configured state...")
    page.wait_for_timeout(2500)

    # ── 7. Launch attack ──
    print(f"         Launching kill chain...")
    page.evaluate("""() => {
        const btn = document.getElementById('kc-launch-btn');
        if (btn && !btn.disabled) btn.click();
    }""")
    page.wait_for_timeout(1500)

    # ── 8. Wait for completion ──
    print(f"         Waiting for kill chain (max {KC_TIMEOUT}s)...")
    success, duration = wait_for_completion(page)

    # ── 9. Post-completion: pause to show final state ──
    page.wait_for_timeout(3000)

    # Scroll the left column (step panel) to show completed step badges
    page.evaluate("""() => {
        const leftCol = document.querySelector('.kc-layout > div');
        if (leftCol) leftCol.scrollTop = 0;
    }""")
    page.wait_for_timeout(1500)

    # Scroll the right column (impact panel) to top to show impact summary
    page.evaluate("""() => {
        const rightCol = document.querySelector('.impact-panel');
        if (rightCol) rightCol.scrollTop = 0;
    }""")
    page.wait_for_timeout(2000)

    # Scroll right column down to show webhook data
    page.evaluate("""() => {
        const rightCol = document.querySelector('.impact-panel');
        if (rightCol) rightCol.scrollTo({top: rightCol.scrollHeight, behavior: 'smooth'});
    }""")
    page.wait_for_timeout(3000)

    # Scroll left column to show step 2 evidence (bottom of step panel)
    page.evaluate("""() => {
        const sp = document.getElementById('step-panel');
        if (sp) sp.scrollTo({top: sp.scrollHeight, behavior: 'smooth'});
    }""")
    page.wait_for_timeout(2000)

    # Back to top of left column
    page.evaluate("""() => {
        const sp = document.getElementById('step-panel');
        if (sp) sp.scrollTo({top: 0, behavior: 'smooth'});
    }""")
    page.wait_for_timeout(1500)

    return {"success": success, "duration_sec": round(duration, 1)}


def run_recordings(matrix: list[dict], provider: str, model: str, headless: bool = False):
    from playwright.sync_api import sync_playwright

    MP4_DIR.mkdir(parents=True, exist_ok=True)
    GIF_DIR.mkdir(parents=True, exist_ok=True)

    total = len(matrix)
    results = []

    print(f"\n{'='*60}")
    print(f"🎬 MCParasite Demo Recorder - {total} recordings")
    print(f"   {provider}/{model} | Viewport: {VIEWPORT_W}x{VIEWPORT_H}")
    print(f"   Dashboard: {DASHBOARD_URL}")
    print(f"   Output: {RECORDINGS_DIR}")
    print(f"{'='*60}\n")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=headless,
            args=["--disable-extensions", "--no-first-run",
                  "--no-default-browser-check", f"--window-size={VIEWPORT_W},{VIEWPORT_H}"],
        )

        for i, combo in enumerate(matrix, 1):
            ch, sc, st = combo["channel"], combo["scenario"], combo["stealth"]
            fn = make_filename(ch, sc, st)
            mp4_target = MP4_DIR / f"{fn}.mp4"

            # Skip existing
            if mp4_target.exists() and mp4_target.stat().st_size > 100_000:
                print(f"[{i}/{total}] ⏭️  {fn} (exists)")
                results.append({"file": fn, "success": True, "skipped": True})
                continue

            print(f"\n[{i}/{total}] 📹 {fn}")

            ctx_opts = dict(
                viewport={"width": VIEWPORT_W, "height": VIEWPORT_H},
                record_video_dir=str(MP4_DIR),
                record_video_size={"width": VIEWPORT_W, "height": VIEWPORT_H},
                color_scheme="dark",
            )
            if AUTH_USER and AUTH_PASS:
                ctx_opts["http_credentials"] = {"username": AUTH_USER, "password": AUTH_PASS}
            context = browser.new_context(**ctx_opts)
            page = context.new_page()

            try:
                page.goto(DASHBOARD_URL, wait_until="networkidle", timeout=20000)
                page.wait_for_timeout(1500)

                # Inject layout-stabilizing CSS
                inject_recording_css(page)
                page.wait_for_timeout(500)

                # Ensure we're on the Kill Chain tab
                page.evaluate("""() => {
                    const kcTab = document.querySelector('[onclick*="switchTab"][onclick*="killchain"]');
                    if (kcTab) kcTab.click();
                }""")
                page.wait_for_timeout(500)

                result = record_single(page, ch, sc, st, provider, model)
                result["file"] = fn

            except Exception as e:
                result = {"file": fn, "success": False, "error": str(e)}
                print(f"   ❌ Error: {e}")

            # Get video path before closing
            video_path = page.video.path() if page.video else None
            page.close()
            context.close()

            # Rename video
            if video_path and Path(video_path).exists():
                src = Path(video_path)
                if src.suffix == ".webm":
                    print(f"   🔄 webm → mp4...")
                    subprocess.run(["ffmpeg", "-y", "-i", str(src),
                                    "-c:v", "libx264", "-preset", "fast", "-crf", "18",
                                    "-pix_fmt", "yuv420p", str(mp4_target)], capture_output=True)
                    src.unlink()
                else:
                    src.rename(mp4_target)

                result["mp4"] = str(mp4_target)

                # GIF
                gif_target = GIF_DIR / f"{fn}.gif"
                print(f"   🎞️  GIF...")
                generate_gif(str(mp4_target), str(gif_target))
                if gif_target.exists():
                    sz = gif_target.stat().st_size / 1024 / 1024
                    result["gif"] = str(gif_target)
                    ok = "✅" if result.get("success") else "⚠️"
                    print(f"   {ok} Done! {result.get('duration_sec', '?')}s | GIF {sz:.1f}MB")

            results.append(result)

            # Reset dashboard for next recording: call the reset function
            # (This happens naturally when we create a new context/page)

            if i < total:
                time.sleep(3)

        browser.close()

    # Summary
    print(f"\n{'='*60}")
    ok = sum(1 for r in results if r.get("success"))
    skip = sum(1 for r in results if r.get("skipped"))
    fail = total - ok
    print(f"📊 {ok}/{total} success ({skip} skipped), {fail} failed")
    for r in results:
        if not r.get("success") and not r.get("skipped"):
            print(f"   ❌ {r.get('file')}: {r.get('error','?')}")

    log_path = RECORDINGS_DIR / "recording_log.json"
    with open(log_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"   Log: {log_path}")


def gif_only():
    GIF_DIR.mkdir(parents=True, exist_ok=True)
    for mp4 in sorted(MP4_DIR.glob("*.mp4")):
        gif = str(GIF_DIR / mp4.stem) + ".gif"
        if os.path.exists(gif):
            print(f"  ⏭️  {mp4.stem}")
            continue
        print(f"  🎞️  {mp4.stem}...", end=" ", flush=True)
        generate_gif(str(mp4), gif)
        sz = os.path.getsize(gif) / 1024 / 1024 if os.path.exists(gif) else 0
        print(f"({sz:.1f} MB)")
    print("✅ Done!")


def _set_url(url):
    global DASHBOARD_URL
    DASHBOARD_URL = url


def main():
    parser = argparse.ArgumentParser(description="MCParasite Demo Recorder")
    parser.add_argument("--channel", help="Record only this channel")
    parser.add_argument("--scenario", help="Record only this scenario")
    parser.add_argument("--stealth", default=None)
    parser.add_argument("--provider", default=DEFAULT_PROVIDER)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--gif-only", action="store_true")
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--dashboard-url", default=DASHBOARD_URL)
    args = parser.parse_args()

    _set_url(args.dashboard_url)

    if args.gif_only:
        gif_only()
        return

    matrix = DEMO_MATRIX
    if args.channel:
        matrix = [m for m in matrix if m["channel"] == args.channel]
    if args.scenario:
        matrix = [m for m in matrix if m["scenario"] == args.scenario]
    if args.stealth is not None:
        matrix = [m for m in matrix if m["stealth"] == args.stealth]

    if not matrix:
        print("❌ No matching combinations!")
        sys.exit(1)

    if args.dry_run:
        print(f"🎬 {len(matrix)} recordings:\n")
        for i, m in enumerate(matrix, 1):
            print(f"  {i:3d}. {make_filename(m['channel'], m['scenario'], m['stealth'])}")
        t = len(matrix) * 5
        print(f"\n   ~{t} min ({t//60}h{t%60}m)")
        return

    run_recordings(matrix, args.provider, args.model, headless=args.headless)


if __name__ == "__main__":
    main()
