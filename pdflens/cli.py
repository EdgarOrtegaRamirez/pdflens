"""
PDFLens CLI — command-line interface for PDF analysis and security scanning.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .metadata import extract_metadata
from .pdf_parser import PDFParseError, parse_pdf_file
from .report import generate_json_report, generate_markdown_report, generate_text_report
from .security import Severity, analyze_security
from .structure import analyze_structure

console = Console()


def _print_error(msg: str):
    console.print(f"[bold red]Error:[/bold red] {msg}", err=True)


@click.group()
@click.version_option(version="1.0.0", prog_name="pdflens")
def main():
    """PDFLens — PDF Analysis & Security Toolkit

    Analyze PDF documents for metadata, structure, and security threats.
    """
    pass


@main.command()
@click.argument("pdf_file", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["text", "json", "markdown"]),
    default="text",
    help="Output format",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file (default: stdout)")
@click.option("--findings-only", is_flag=True, help="Show only security findings")
def analyze(pdf_file: str, output_format: str, output: str | None, findings_only: bool):
    """Perform full analysis of a PDF document."""
    try:
        pdf = parse_pdf_file(pdf_file)
    except (PDFParseError, FileNotFoundError, OSError) as e:
        _print_error(str(e))
        sys.exit(1)

    metadata = extract_metadata(pdf)
    security = analyze_security(pdf)
    structure = analyze_structure(pdf)

    if output_format == "json":
        report = generate_json_report(metadata, security, structure)
    elif output_format == "markdown":
        report = generate_markdown_report(metadata, security, structure)
    else:
        report = generate_text_report(metadata, security, structure)

    if output:
        Path(output).write_text(report, encoding="utf-8")
        console.print(f"[green]Report written to {output}[/green]")
    else:
        click.echo(report)


@main.command()
@click.argument("pdf_file", type=click.Path(exists=True))
def meta(pdf_file: str):
    """Extract metadata from a PDF document."""
    try:
        pdf = parse_pdf_file(pdf_file)
    except (PDFParseError, FileNotFoundError, OSError) as e:
        _print_error(str(e))
        sys.exit(1)

    metadata = extract_metadata(pdf)
    table = Table(title="PDF Metadata")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("PDF Version", metadata.pdf_version)
    table.add_row("File Size", _format_size(metadata.file_size))
    table.add_row("Pages", str(metadata.page_count))
    table.add_row("Linearized", "Yes" if metadata.is_linearized else "No")
    table.add_row("Encrypted", "Yes" if metadata.is_encrypted else "No")
    table.add_row("Objects", str(metadata.object_count))
    table.add_row("Streams", str(metadata.stream_count))
    table.add_row("Fonts", str(metadata.font_count))
    table.add_row("Images", str(metadata.image_count))
    table.add_row("Annotations", str(metadata.annotation_count))
    if metadata.title:
        table.add_row("Title", metadata.title)
    if metadata.author:
        table.add_row("Author", metadata.author)
    if metadata.creator:
        table.add_row("Creator", metadata.creator)
    if metadata.producer:
        table.add_row("Producer", metadata.producer)
    if metadata.creation_date:
        table.add_row("Created", metadata.creation_date)
    if metadata.modification_date:
        table.add_row("Modified", metadata.modification_date)

    console.print(table)


@main.command()
@click.argument("pdf_file", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def security(pdf_file: str, as_json: bool):
    """Analyze PDF for security threats."""
    try:
        pdf = parse_pdf_file(pdf_file)
    except (PDFParseError, FileNotFoundError, OSError) as e:
        _print_error(str(e))
        sys.exit(1)

    report = analyze_security(pdf)
    summary = report.summary()

    if as_json:
        output = {
            "summary": summary,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "category": f.category,
                    "object_num": f.object_num,
                    "details": f.details,
                }
                for f in report.findings
            ],
        }
        click.echo(json.dumps(output, indent=2, ensure_ascii=False, default=str))
        return

    risk_colors = {
        "safe": "green",
        "low": "yellow",
        "medium": "dark_orange",
        "high": "red",
        "critical": "bold red",
    }
    risk_labels = {
        "safe": "✅ SAFE",
        "low": "⚠️  LOW RISK",
        "medium": "⚠️  MEDIUM RISK",
        "high": "🚨 HIGH RISK",
        "critical": "🔴 CRITICAL RISK",
    }

    risk_color = risk_colors.get(summary["risk_level"], "white")
    risk_label = risk_labels.get(summary["risk_level"], summary["risk_level"])

    console.print(
        Panel(
            f"[{risk_color}]{risk_label}[/]\n"
            f"Risk Score: {summary['risk_score']} | Findings: {summary['total_findings']}",
            title="Security Analysis",
            border_style=risk_color,
        )
    )

    if report.findings:
        severity_colors = {
            Severity.INFO: "dim",
            Severity.LOW: "yellow",
            Severity.MEDIUM: "dark_orange",
            Severity.HIGH: "red",
            Severity.CRITICAL: "bold red",
        }
        for i, finding in enumerate(report.findings, 1):
            color = severity_colors.get(finding.severity, "white")
            console.print(f"  [{color}]{i:3d}. [{finding.severity.value.upper():8s}][/] {finding.title}")
            console.print(f"       {finding.description}")
            if finding.object_num is not None:
                console.print(f"       [dim]Object: {finding.object_num}[/]")
    else:
        console.print("[green]No security issues found.[/green]")


@main.command()
@click.argument("pdf_file", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def structure(pdf_file: str, as_json: bool):
    """Analyze PDF document structure."""
    try:
        pdf = parse_pdf_file(pdf_file)
    except (PDFParseError, FileNotFoundError, OSError) as e:
        _print_error(str(e))
        sys.exit(1)

    report = analyze_structure(pdf)

    if as_json:
        click.echo(json.dumps(report.summary(), indent=2, ensure_ascii=False, default=str))
        return

    console.print(
        Panel(
            f"Objects: {report.total_object_count} | "
            f"Streams: {report.total_stream_count} | "
            f"Pages: {report.total_page_count}\n"
            f"Fonts: {report.total_font_count} | "
            f"Images: {report.total_image_count} | "
            f"Annotations: {report.total_annotation_count}",
            title="Document Structure",
        )
    )

    # Page sizes
    if report.page_sizes:
        console.print("\n[bold]Page Sizes:[/bold]")
        for size, count in sorted(report.page_sizes.items(), key=lambda x: -x[1]):
            console.print(f"  {size:15s}  {count} page{'s' if count != 1 else ''}")

    # Fonts
    if report.fonts:
        console.print(f"\n[bold]Fonts ({len(report.fonts)}):[/bold]")
        for font in report.fonts[:15]:
            std = " [dim][standard][/]" if font.is_standard else ""
            touni = " [dim][ToUnicode][/]" if font.has_to_unicode else ""
            console.print(f"  {font.base_font:30s}  {font.font_type}{std}{touni}")
        if len(report.fonts) > 15:
            console.print(f"  [dim]... and {len(report.fonts) - 15} more[/]")

    # Images
    if report.images:
        console.print(f"\n[bold]Images ({len(report.images)}):[/bold]")
        for img in report.images[:10]:
            console.print(f"  {img.width}x{img.height}  {img.bits_per_component}bpc  {img.color_space or 'unknown'}")
        if len(report.images) > 10:
            console.print(f"  [dim]... and {len(report.images) - 10} more[/]")


@main.command()
@click.argument("pdf_file", type=click.Path(exists=True))
@click.option("--limit", "-n", default=100, help="Max findings to show")
def check(pdf_file: str, limit: int):
    """Quick security check — exit code indicates risk level.

    Exit codes: 0=safe, 1=low, 2=medium, 3=high, 4=critical
    """
    try:
        pdf = parse_pdf_file(pdf_file)
    except (PDFParseError, FileNotFoundError, OSError) as e:
        _print_error(str(e))
        sys.exit(1)

    report = analyze_security(pdf)
    summary = report.summary()

    risk_exit = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    exit_code = risk_exit.get(summary["risk_level"], 0)

    if summary["risk_level"] == "safe":
        console.print("[green]✓ SAFE[/green] — No security issues found")
    else:
        findings = summary["total_findings"]
        score = summary["risk_score"]
        console.print(f"[bold]— {findings} findings (score: {score})")
        for finding in report.findings[:limit]:
            console.print(f"  [{finding.severity.value}] {finding.title}")

    sys.exit(exit_code)


def _format_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


if __name__ == "__main__":
    main()
