"""Pro reports — JSON + console summary with vulnerability details"""
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.logger import logger
from core.logger import dashboard

console = Console()

SEV_COLOR = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "green"
}


def report(session):
    data = session.data
    valid = data.get("validated", [])
    valid.sort(key=lambda x: x.get("confidence", 0), reverse=True)

    nuclei_findings = data.get("nuclei_findings", [])
    confirmed = data.get("confirmed_vulnerabilities", [])

    console.print(Panel.fit(
        f"[bold cyan]Target:[/] {data['target']}\n"
        f"[bold]Subdomains:[/] {len(data.get('subdomains', []))}  "
        f"[bold]Alive:[/] {len(data.get('alive_hosts', []))}\n"
        f"[bold]Endpoints:[/] {len(data.get('endpoints', []))}  "
        f"[bold]Nuclei Findings:[/] {len(nuclei_findings)}\n"
        f"[bold green]Validated Findings:[/] {len(valid)}  "
        f"[bold red]Confirmed:[/] {len(confirmed)}",
        title="🎯 MISSION REPORT"))
    try:
        dashboard.advance_validation(f"report:summary:{len(confirmed)}")
    except Exception:
        pass

    # Nuclei findings summary
    if nuclei_findings:
        console.print("[bold cyan][\n] NUCLEI SCANNING RESULTS")
        severity_counts = {}
        for f in nuclei_findings:
            sev = f.get("info", {}).get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in severity_counts:
                color = SEV_COLOR.get(sev, "white")
                console.print(f"  [{color}]• {sev.upper()}: {severity_counts[sev]}[/]")
        
        # Top findings table
        t = Table(title="🔍 TOP NUCLEI FINDINGS", show_lines=False, box=None)
        t.add_column("#", style="dim", width=3)
        t.add_column("Severity", width=10)
        t.add_column("Name", width=40, overflow="fold")
        t.add_column("URL", width=50, overflow="fold")
        
        for i, f in enumerate(nuclei_findings[:15], 1):
            sev = f.get("info", {}).get("severity", "info").lower()
            name = f.get("info", {}).get("name", "Unknown")[:40]
            url = (f.get("matched-at") or f.get("url") or "")[:50]
            color = SEV_COLOR.get(sev, "white")
            t.add_row(str(i), f"[{color}]{sev.upper()}[/]", name, url)
        
        console.print(t)
        try:
            dashboard.advance_validation(f"report:nuclei:{len(nuclei_findings)}")
        except Exception:
            pass

    # Validated findings
    if valid:
        t = Table(title="🔥 VALIDATED VULNERABILITIES", show_lines=False, box=None)
        t.add_column("#", style="dim", width=3)
        t.add_column("Severity", width=10)
        t.add_column("Type", width=30, overflow="fold")
        t.add_column("URL", width=50, overflow="fold")
        t.add_column("Conf", justify="right", width=5)
        
        for i, f in enumerate(valid[:20], 1):
            sev = (f.get("info", {}).get("severity") or f.get("severity", "info")).lower()
            typ = f.get("type") or f.get("info", {}).get("name", "nuclei")
            url = (f.get("matched-at") or f.get("url") or f.get("host", "?"))[:50]
            conf = str(f.get("confidence", 0))
            color = SEV_COLOR.get(sev, "white")
            t.add_row(str(i), f"[{color}]{sev.upper()}[/]", typ[:30], url, conf)
        
        console.print(t)
    else:
        console.print("[yellow]⚠️  No validated findings[/]")
    try:
        dashboard.advance_validation(f"report:validated:{len(valid)}")
    except Exception:
        pass

    # Save JSON report
    out = Path(session.path).with_suffix(".report.json")
    with open(out, "w") as f:
        json.dump({
            "target": data["target"],
            "summary": {
                "subdomains": len(data.get("subdomains", [])),
                "alive": len(data.get("alive_hosts", [])),
                "endpoints": len(data.get("endpoints", [])),
                "nuclei_findings": len(nuclei_findings),
                "validated_findings": len(valid),
                "confirmed_vulnerabilities": len(confirmed),
            },
            "nuclei_findings": nuclei_findings[:50],  # Top 50
            "validated_findings": valid[:50],
            "confirmed_vulnerabilities": confirmed[:50],
        }, f, indent=2, default=str)
    
    console.print(f"\n📄 Full report saved: [cyan]{out}[/]")
    try:
        dashboard.advance_validation(f"report:saved:{len(confirmed)}")
    except Exception:
        pass
