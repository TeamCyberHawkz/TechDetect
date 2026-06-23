import os
import sys
import json
import asyncio
import argparse
import time
from pathlib import Path

from .profiler import TechDetect, ProfileResult
from .__version__ import __version__


_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
_x = lambda c: c if _COLOR else ""
RESET, DIM, BOLD = _x("\033[0m"), _x("\033[2m"), _x("\033[1m")
CYAN, GREEN, YELLOW = _x("\033[36m"), _x("\033[32m"), _x("\033[33m")
RED, GREY, WHITE = _x("\033[31m"), _x("\033[90m"), _x("\033[97m")


def _banner():
    print('''
         ______          __    ____       __            __
        /_  __/__  _____/ /_  / __ \___  / /____  _____/ /_
         / / / _ \/ ___/ __ \/ / / / _ \/ __/ _ \/ ___/ __/
        / / /  __/ /__/ / / / /_/ /  __/ /_/  __/ /__/ /_
       /_/  \___/\___/_/ /_/_____/\___/\__/\___/\___/\__/

[ Website Technology Detection Engine ][==o==][ GitHub:TeamCyberHawkz ]
''')

def _conf_color(c: int) -> str:
    return GREEN if c >= 80 else YELLOW if c >= 50 else GREY


def _print_result(r: ProfileResult, verbose: bool = False):
    if r.error:
        print(f"\n  {RED}✖ {r.url}{RESET}\n    {RED}{r.error}{RESET}")
        return

    sc = r.status_code
    sc_color = GREEN if 200 <= sc < 300 else CYAN if 300 <= sc < 400 else RED
    size = f"{r.content_length / 1024:.1f} KB" if r.content_length >= 1024 else f"{r.content_length} B"
    dot = f"  {DIM}·{RESET}  "

    print(f"\n  {BOLD}{WHITE}{r.url}{RESET}")
    if r.final_url and r.final_url != r.url:
        print(f"  {DIM}→ {r.final_url}{RESET}")
    print(
        f"  {DIM}status{RESET} {sc_color}{sc}{RESET}{dot}"
        f"{DIM}server{RESET} {r.server or 'unknown'}{dot}"
        f"{DIM}time{RESET} {r.scan_time_ms:.0f} ms{dot}"
        f"{DIM}size{RESET} {size}"
    )

    extra = []
    if r.redirect_chain:
        extra.append(f"{len(r.redirect_chain)} redirects")
    if r.ssl_issuer:
        extra.append(f"SSL {r.ssl_issuer}")
    if extra:
        print(f"  {DIM}{'  ·  '.join(extra)}{RESET}")

    if not r.technologies:
        print(f"\n  {DIM}No technologies detected.{RESET}")
        return

    print(f"\n  {BOLD}{len(r.technologies)} technologies{RESET}  {DIM}— confidence %{RESET}")
    for cat in sorted(r.technologies_by_category):
        print(f"\n  {CYAN}{cat}{RESET}")
        for t in sorted(r.technologies_by_category[cat], key=lambda x: -x["confidence"]):
            c = t["confidence"]
            col = _conf_color(c)
            name = t["name"] if len(t["name"]) <= 30 else t["name"][:29] + "…"
            ver = f" {DIM}v{t['version']}{RESET}" if t.get("version") else ""
            print(f"    {name:<30}{col}{c:>3d}%{RESET}{ver}")
            if verbose:
                for ev in t.get("evidence", [])[:2]:
                    print(f"      {DIM}└ {ev}{RESET}")


async def _scan(profiler: TechDetect, url: str, output: str | None, verbose: bool, as_json: bool) -> ProfileResult:
    quiet = as_json or bool(output)
    if not quiet:
        print(f"\n  Scanning: {url}")
    result = await profiler.scan(url)

    if as_json:
        print(result.to_json())
    elif not output:
        _print_result(result, verbose=verbose)

    if output:
        p = Path(output)
        p.write_text(result.to_json())
        if not as_json:
            print(f"\n  URL:       {result.url}")
            print(f"  Saved {p.name} to {p.resolve()}")
    return result


async def _scan_file(profiler: TechDetect, path: str, output: str | None, verbose: bool, as_json: bool):
    lines = [l.strip() for l in Path(path).read_text().splitlines() if l.strip() and not l.startswith("#")]
    if not lines:
        print("No URLs in file.")
        sys.exit(1)

    quiet = as_json or bool(output)
    if not quiet:
        print(f"\n  {len(lines)} URLs to scan")
    t0 = time.monotonic()
    results = await profiler.scan_many(lines)
    elapsed = (time.monotonic() - t0) * 1000

    data = {"results": {u: r.to_dict() for u, r in results.items()}}

    if as_json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    elif not output:
        for url in lines:
            if url in results:
                _print_result(results[url], verbose=verbose)
        print(f"\n  Done: {len(lines)} scans in {elapsed:.0f} ms")

    if output:
        p = Path(output)
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        if not as_json:
            print(f"\n  URLs:      {len(lines)} scanned")
            print(f"  Saved {p.name} to {p.resolve()}")


def main():
    ap = argparse.ArgumentParser(
        prog="techdetect",
        description="TechDetect — Website Technology Detection Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  techdetect https://example.com
  techdetect https://example.com --json
  techdetect https://example.com -v
  techdetect -f urls.txt --output results.json
""",
    )
    ap.add_argument("url", nargs="?", help="URL to scan")
    ap.add_argument("-f", "--file", help="File with URLs (one per line)")
    ap.add_argument("-o", "--output", help="Save JSON results to file")
    ap.add_argument("--json", action="store_true", help="Output JSON only (banner + JSON)")
    ap.add_argument("-v", "--verbose", action="store_true", help="Show detection evidence")
    ap.add_argument("--fingerprints", help="Path to fingerprints.json")
    ap.add_argument("--timeout", type=float, default=15.0, help="Request timeout in seconds")
    ap.add_argument("--no-robots", action="store_true", help="Skip robots.txt fetching")
    ap.add_argument("--user-agent", help="Custom User-Agent string")
    ap.add_argument("--no-ssl-verify", action="store_true", help="Disable SSL verification")
    ap.add_argument("--version", action="version", version=f"techdetect {__version__}")
    args = ap.parse_args()

    if not args.url and not args.file:
        ap.print_help()
        sys.exit(1)

    _banner()

    kw: dict = {
        "timeout": args.timeout,
        "fetch_robots": not args.no_robots,
        "verify_ssl": not args.no_ssl_verify,
    }
    if args.fingerprints:
        kw["fingerprints_path"] = args.fingerprints
    if args.user_agent:
        kw["user_agent"] = args.user_agent

    async def _run():
        async with TechDetect(**kw) as p:
            if args.file:
                await _scan_file(p, args.file, args.output, args.verbose, args.json)
            else:
                await _scan(p, args.url, args.output, args.verbose, args.json)

    asyncio.run(_run())


if __name__ == "__main__":
    main()
