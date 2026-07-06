"""
PDF Report Generation — generates reports in multiple formats
(text, JSON, Markdown) from analysis results.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .metadata import PDFMetadata
from .security import SecurityReport, Severity
from .structure import StructureReport


def generate_text_report(
    metadata: PDFMetadata,
    security: SecurityReport,
    structure: StructureReport,
) -> str:
    """Generate a human-readable text report."""
    lines = []
    lines.append("=" * 60)
    lines.append("PDF ANALYSIS REPORT")
    lines.append("=" * 60)
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")

    # Metadata
    lines.append("─" * 60)
    lines.append("DOCUMENT METADATA")
    lines.append("─" * 60)
    lines.append(f"  PDF Version:     {metadata.pdf_version}")
    lines.append(f"  File Size:       {_format_size(metadata.file_size)}")
    lines.append(f"  Pages:           {metadata.page_count}")
    lines.append(f"  Linearized:      {'Yes' if metadata.is_linearized else 'No'}")
    lines.append(f"  Encrypted:       {'Yes' if metadata.is_encrypted else 'No'}")
    if metadata.title:
        lines.append(f"  Title:           {metadata.title}")
    if metadata.author:
        lines.append(f"  Author:          {metadata.author}")
    if metadata.creator:
        lines.append(f"  Creator:         {metadata.creator}")
    if metadata.producer:
        lines.append(f"  Producer:        {metadata.producer}")
    if metadata.creation_date:
        lines.append(f"  Created:         {metadata.creation_date}")
    if metadata.modification_date:
        lines.append(f"  Modified:        {metadata.modification_date}")
    lines.append("")

    # Security
    lines.append("─" * 60)
    lines.append("SECURITY ANALYSIS")
    lines.append("─" * 60)
    summary = security.summary()
    risk_color = {
        "safe": "✓ SAFE",
        "low": "⚠ LOW RISK",
        "medium": "⚠ MEDIUM RISK",
        "high": "✗ HIGH RISK",
        "critical": "✗ CRITICAL RISK",
    }
    lines.append(f"  Risk Level:      {risk_color.get(summary['risk_level'], summary['risk_level'])}")
    lines.append(f"  Risk Score:      {summary['risk_score']}/100+")
    lines.append(f"  Total Findings:  {summary['total_findings']}")
    for sev, count in summary.get("by_severity", {}).items():
        lines.append(f"    {sev.upper():12s}  {count}")
    lines.append("")

    if security.findings:
        lines.append("  Findings:")
        for i, finding in enumerate(security.findings, 1):
            severity_marker = {
                Severity.INFO: "ℹ",
                Severity.LOW: "△",
                Severity.MEDIUM: "▲",
                Severity.HIGH: "✗",
                Severity.CRITICAL: "✗",
            }
            marker = severity_marker.get(finding.severity, "?")
            lines.append(f"  {i:3d}. [{finding.severity.value.upper():8s}] {marker} {finding.title}")
            lines.append(f"       {finding.description}")
            if finding.object_num is not None:
                lines.append(f"       Object: {finding.object_num}")
        lines.append("")

    # Structure
    lines.append("─" * 60)
    lines.append("DOCUMENT STRUCTURE")
    lines.append("─" * 60)
    lines.append(f"  Objects:         {structure.total_object_count}")
    lines.append(f"  Streams:         {structure.total_stream_count}")
    lines.append(f"  Fonts:           {structure.total_font_count}")
    lines.append(f"  Images:          {structure.total_image_count}")
    lines.append(f"  Annotations:     {structure.total_annotation_count}")
    lines.append(f"  Has Forms:       {'Yes' if structure.has_forms else 'No'}")
    lines.append(f"  Has Bookmarks:   {'Yes' if structure.has_bookmarks else 'No'}")
    lines.append(f"  Has JavaScript:  {'Yes' if structure.has_javascript else 'No'}")
    lines.append("")

    if structure.page_sizes:
        lines.append("  Page Sizes:")
        for size, count in sorted(structure.page_sizes.items(), key=lambda x: -x[1]):
            lines.append(f"    {size:15s}  {count} page{'s' if count != 1 else ''}")
        lines.append("")

    if structure.fonts:
        lines.append("  Fonts:")
        for font in structure.fonts[:20]:
            std = " [standard]" if font.is_standard else ""
            lines.append(f"    {font.base_font:30s}  {font.font_type:15s}{std}")
        if len(structure.fonts) > 20:
            lines.append(f"    ... and {len(structure.fonts) - 20} more")
        lines.append("")

    if structure.images:
        lines.append("  Images:")
        for img in structure.images[:10]:
            lines.append(f"    {img.width}x{img.height}  {img.bits_per_component}bpc  {img.color_space or 'unknown'}")
        if len(structure.images) > 10:
            lines.append(f"    ... and {len(structure.images) - 10} more")
        lines.append("")

    # Object type distribution
    if structure.object_type_distribution:
        lines.append("─" * 60)
        lines.append("OBJECT TYPE DISTRIBUTION")
        lines.append("─" * 60)
        for otype, count in sorted(structure.object_type_distribution.items(), key=lambda x: -x[1]):
            lines.append(f"  {otype:20s}  {count}")
        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)


def generate_json_report(
    metadata: PDFMetadata,
    security: SecurityReport,
    structure: StructureReport,
) -> str:
    """Generate a JSON report."""
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metadata": {
            "pdf_version": metadata.pdf_version,
            "file_size": metadata.file_size,
            "page_count": metadata.page_count,
            "title": metadata.title,
            "author": metadata.author,
            "subject": metadata.subject,
            "keywords": metadata.keywords,
            "creator": metadata.creator,
            "producer": metadata.producer,
            "creation_date": metadata.creation_date,
            "modification_date": metadata.modification_date,
            "is_linearized": metadata.is_linearized,
            "is_encrypted": metadata.is_encrypted,
        },
        "security": security.summary(),
        "security_findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "category": f.category,
                "object_num": f.object_num,
                "details": f.details,
            }
            for f in security.findings
        ],
        "structure": structure.summary(),
        "fonts": [
            {
                "name": f.name,
                "base_font": f.base_font,
                "type": f.font_type,
                "encoding": f.encoding,
                "has_to_unicode": f.has_to_unicode,
                "is_standard": f.is_standard,
            }
            for f in structure.fonts
        ],
        "images": [
            {
                "width": i.width,
                "height": i.height,
                "bits_per_component": i.bits_per_component,
                "color_space": i.color_space,
                "filter": i.filter,
                "size_bytes": i.size_bytes,
            }
            for i in structure.images
        ],
        "pages": [
            {
                "page_num": p.page_num,
                "width": p.width,
                "height": p.height,
                "rotation": p.rotation,
                "font_count": p.font_count,
                "image_count": p.image_count,
                "annotation_count": p.annotation_count,
            }
            for p in structure.pages
        ],
    }
    return json.dumps(report, indent=2, ensure_ascii=False, default=str)


def generate_markdown_report(
    metadata: PDFMetadata,
    security: SecurityReport,
    structure: StructureReport,
) -> str:
    """Generate a Markdown report."""
    lines = []
    lines.append("# PDF Analysis Report")
    lines.append("")
    lines.append(f"*Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*")
    lines.append("")

    # Metadata
    lines.append("## Document Metadata")
    lines.append("")
    lines.append("| Property | Value |")
    lines.append("|----------|-------|")
    lines.append(f"| PDF Version | {metadata.pdf_version} |")
    lines.append(f"| File Size | {_format_size(metadata.file_size)} |")
    lines.append(f"| Pages | {metadata.page_count} |")
    lines.append(f"| Linearized | {'Yes' if metadata.is_linearized else 'No'} |")
    lines.append(f"| Encrypted | {'Yes' if metadata.is_encrypted else 'No'} |")
    if metadata.title:
        lines.append(f"| Title | {metadata.title} |")
    if metadata.author:
        lines.append(f"| Author | {metadata.author} |")
    if metadata.creator:
        lines.append(f"| Creator | {metadata.creator} |")
    if metadata.producer:
        lines.append(f"| Producer | {metadata.producer} |")
    if metadata.creation_date:
        lines.append(f"| Created | {metadata.creation_date} |")
    if metadata.modification_date:
        lines.append(f"| Modified | {metadata.modification_date} |")
    lines.append("")

    # Security
    lines.append("## Security Analysis")
    lines.append("")
    summary = security.summary()
    risk_badge = {
        "safe": "✅ Safe",
        "low": "⚠️ Low Risk",
        "medium": "⚠️ Medium Risk",
        "high": "🚨 High Risk",
        "critical": "🔴 Critical Risk",
    }
    lines.append(f"**Risk Level:** {risk_badge.get(summary['risk_level'], summary['risk_level'])}  ")
    lines.append(f"**Risk Score:** {summary['risk_score']}  ")
    lines.append(f"**Findings:** {summary['total_findings']}")
    lines.append("")

    if security.findings:
        lines.append("| # | Severity | Title | Object |")
        lines.append("|---|----------|-------|--------|")
        for i, f in enumerate(security.findings, 1):
            obj = str(f.object_num) if f.object_num is not None else "-"
            lines.append(f"| {i} | {f.severity.value.upper()} | {f.title} | {obj} |")
        lines.append("")

        lines.append("### Detailed Findings")
        lines.append("")
        for i, f in enumerate(security.findings, 1):
            lines.append(f"#### {i}. {f.title}")
            lines.append(f"**Severity:** {f.severity.value.upper()} | **Category:** {f.category}")
            lines.append("")
            lines.append(f"{f.description}")
            if f.details:
                lines.append("")
                lines.append("```json")
                lines.append(json.dumps(f.details, indent=2, ensure_ascii=False, default=str))
                lines.append("```")
            lines.append("")

    # Structure
    lines.append("## Document Structure")
    lines.append("")
    lines.append("| Property | Value |")
    lines.append("|----------|-------|")
    lines.append(f"| Objects | {structure.total_object_count} |")
    lines.append(f"| Streams | {structure.total_stream_count} |")
    lines.append(f"| Fonts | {structure.total_font_count} |")
    lines.append(f"| Images | {structure.total_image_count} |")
    lines.append(f"| Annotations | {structure.total_annotation_count} |")
    lines.append(f"| Forms | {'Yes' if structure.has_forms else 'No'} |")
    lines.append(f"| Bookmarks | {'Yes' if structure.has_bookmarks else 'No'} |")
    lines.append(f"| JavaScript | {'Yes' if structure.has_javascript else 'No'} |")
    lines.append("")

    if structure.fonts:
        lines.append("### Fonts")
        lines.append("")
        lines.append("| Font | Type | Standard | ToUnicode |")
        lines.append("|------|------|----------|-----------|")
        for font in structure.fonts[:30]:
            std = "✓" if font.is_standard else ""
            touni = "✓" if font.has_to_unicode else ""
            lines.append(f"| {font.base_font} | {font.font_type} | {std} | {touni} |")
        if len(structure.fonts) > 30:
            lines.append(f"| ... | ... | ... | ... | *{len(structure.fonts) - 30} more* |")
        lines.append("")

    if structure.images:
        lines.append("### Images")
        lines.append("")
        lines.append("| Dimensions | BPC | Color Space | Size |")
        lines.append("|------------|-----|-------------|------|")
        for img in structure.images[:20]:
            cs = img.color_space or "unknown"
            sz = _format_size(img.size_bytes) if img.size_bytes else "-"
            lines.append(f"| {img.width}x{img.height} | {img.bits_per_component} | {cs} | {sz} |")
        if len(structure.images) > 20:
            lines.append(f"| ... | ... | ... | *{len(structure.images) - 20} more* |")
        lines.append("")

    return "\n".join(lines)


def _format_size(size_bytes: int) -> str:
    """Format file size in human-readable form."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
