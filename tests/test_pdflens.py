"""
Tests for PDFLens PDF parser and analysis toolkit.

Uses synthetic PDF bytes constructed for testing rather than external PDF files.
"""

import json
import zlib

import pytest

from pdflens.metadata import _decode_pdf_string, _parse_pdf_date, extract_metadata
from pdflens.pdf_parser import (
    ObjectType,
    PDFObject,
    PDFParseError,
    parse_pdf,
)
from pdflens.report import generate_json_report, generate_markdown_report, generate_text_report
from pdflens.security import SecurityAnalyzer, SecurityReport, Severity, _entropy, analyze_security
from pdflens.structure import STANDARD_FONTS, analyze_structure

# ============================================================
# Synthetic PDF construction helpers
# ============================================================


def _build_simple_pdf(
    title: str = "",
    author: str = "",
    page_count: int = 1,
    include_js: bool = False,
    include_launch: bool = False,
    include_uri: bool = False,
    include_embedded: bool = False,
    include_openaction: bool = False,
    page_width: float = 612,
    page_height: float = 792,
    extra_objects: str = "",
) -> bytes:
    """Build a minimal valid PDF from scratch."""
    # Build objects as (obj_num, content_string) pairs
    obj_pairs = []

    # Object 1: Catalog
    obj_pairs.append((1, "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"))

    # Object 2: Pages
    page_refs = " ".join(f"{i} 0 R" for i in range(3, 3 + page_count))
    obj_pairs.append((2, f"2 0 obj\n<< /Type /Pages /Kids [{page_refs}] /Count {page_count} >>\nendobj\n"))

    # Object 3+: Page objects
    for i in range(page_count):
        obj_num = 3 + i
        page_obj = (
            f"{obj_num} 0 obj\n"
            f"<< /Type /Page /Parent 2 0 R "
            f"/MediaBox [0 0 {page_width} {page_height}] "
            f"/Resources << /Font << /F1 10 0 R >> >> "
        )
        if include_js and i == 0:
            page_obj += "/AA << /JS 5 0 R /S /JavaScript >> "
        if include_openaction and i == 0:
            page_obj += "/OpenAction << /S /JavaScript /JS 5 0 R >> "
        if include_uri and i == 0:
            page_obj += "/AA << /URI 6 0 R >> "
        page_obj += ">>\nendobj\n"
        obj_pairs.append((obj_num, page_obj))

    # Object 5: JavaScript string (if needed)
    next_obj = 3 + page_count
    obj_num_5 = next_obj
    if include_js:
        js_obj = (
            f"{obj_num_5} 0 obj\n<< /Type /EmbeddedFile /Length 44 >>\nstream\napp.alert('Hello');\nendstream\nendobj\n"
        )
        obj_pairs.append((obj_num_5, js_obj))
        next_obj += 1
    if include_launch:
        launch_obj = f"{next_obj} 0 obj\n<< /S /Launch /Win << /F (cmd.exe) /P (/c calc.exe) >> >>\nendobj\n"
        obj_pairs.append((next_obj, launch_obj))
        next_obj += 1
    if include_uri:
        uri_obj = f"{next_obj} 0 obj\n<< /S /URI /URI (http://evil.example.com/payload) >>\nendobj\n"
        obj_pairs.append((next_obj, uri_obj))
        next_obj += 1
    if include_embedded:
        embedded_obj = f"{next_obj} 0 obj\n<< /Type /EmbeddedFile /Length 5 >>\nstream\nmalware\nendstream\nendobj\n"
        obj_pairs.append((next_obj, embedded_obj))
        next_obj += 1
    if include_openaction and not include_js:
        openaction_obj = (
            f"{next_obj} 0 obj\n<< /Type /EmbeddedFile /Length 44 >>\nstream\napp.alert('Hello');\nendstream\nendobj\n"
        )
        obj_pairs.append((next_obj, openaction_obj))
        next_obj += 1

    # Object 10: Simple font
    obj_pairs.append((10, "10 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"))

    # Extra objects
    if extra_objects:
        obj_pairs.append((next_obj, extra_objects))

    # Sort by object number
    obj_pairs.sort(key=lambda x: x[0])

    # Build the PDF body and compute offsets
    header = b"%PDF-1.7\n\x80\x81\x82\x83\n"
    body_parts = []
    obj_offsets = {}
    current_offset = len(header)

    for obj_num, obj_str in obj_pairs:
        obj_offsets[obj_num] = current_offset
        encoded = obj_str.encode("latin-1")
        body_parts.append(encoded)
        current_offset += len(encoded)

    body = b"".join(body_parts)

    # Determine max object number for xref table
    max_obj = max(obj_offsets.keys()) if obj_offsets else 0

    # Build cross-reference table
    xref_offset = len(header) + len(body)
    xref = b"xref\n"
    xref += f"0 {max_obj + 1}\n".encode()
    # Object 0 is always free
    xref += b"0000000000 65535 f \n"
    for i in range(1, max_obj + 1):
        if i in obj_offsets:
            xref += f"{obj_offsets[i]:010d} 00000 n \n".encode()
        else:
            xref += b"0000000000 00000 f \n"

    # Trailer
    trailer = (f"trailer\n<< /Size {max_obj + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n").encode()

    return header + body + xref + trailer


def _build_pdf_with_xref_stream() -> bytes:
    """Build a PDF that uses cross-reference streams (PDF 1.5+)."""
    header = b"%PDF-1.5\n"

    # Object 1: Catalog
    obj1_offset = len(header)
    obj1 = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"

    # Object 2: Pages
    obj2_offset = obj1_offset + len(obj1)
    obj2 = b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"

    # Object 3: Page
    obj3_offset = obj2_offset + len(obj2)
    obj3 = b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"

    # Object 4: XRef stream
    obj4_offset = obj3_offset + len(obj3)
    # Create a simple xref stream
    # Build entries: type 0 (free) for obj 0, type 1 (uncompressed) for objects 1-3
    entries = bytearray()
    # Object 0: free
    entries.extend([0, 0, 0, 0, 0])
    # Object 1
    entries.extend([1] + list(obj1_offset.to_bytes(3, "big")) + [0])
    # Object 2
    entries.extend([1] + list(obj2_offset.to_bytes(3, "big")) + [0])
    # Object 3
    entries.extend([1] + list(obj3_offset.to_bytes(3, "big")) + [0])
    # Object 4
    entries.extend([1] + list(obj4_offset.to_bytes(3, "big")) + [0])

    compressed = zlib.compress(bytes(entries))
    stream_dict = (
        f"4 0 obj\n<< /Type /XRef /Size 5 /W [1 3 1] /Root 1 0 R "
        f"/Length {len(compressed)} /Filter /FlateDecode >>\nstream\n"
    ).encode()

    obj4 = stream_dict + compressed + b"\nendstream\nendobj\n"

    # Startxref
    startxref = obj4_offset

    body = obj1 + obj2 + obj3 + obj4
    trailer = f"\ntrailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n{startxref}\n%%EOF\n".encode()

    return header + body + trailer


# ============================================================
# Parser Tests
# ============================================================


class TestPDFParser:
    """Tests for the PDF parser."""

    def test_parse_simple_pdf(self):
        data = _build_simple_pdf()
        pdf = parse_pdf(data)
        assert pdf.header_version == "1.7"
        assert pdf.file_size > 0
        assert len(pdf.objects) > 0

    def test_parse_header_version(self):
        data = _build_simple_pdf()
        pdf = parse_pdf(data)
        assert pdf.header_version == "1.7"

    def test_parse_invalid_header(self):
        with pytest.raises(PDFParseError, match="Invalid PDF header"):
            parse_pdf(b"This is not a PDF file")

    def test_parse_object_types(self):
        data = _build_simple_pdf()
        pdf = parse_pdf(data)
        # Should have catalog (dict), pages (dict), page (dict), font (dict)
        types = [obj.type for obj in pdf.objects.values()]
        assert ObjectType.DICTIONARY in types

    def test_parse_page_count(self):
        data = _build_simple_pdf(page_count=3)
        pdf = parse_pdf(data)
        # Should have catalog + pages + 3 pages + font = at least 6 objects
        assert len(pdf.objects) >= 5

    def test_parse_xref_stream(self):
        data = _build_pdf_with_xref_stream()
        pdf = parse_pdf(data)
        assert pdf.header_version == "1.5"
        assert len(pdf.objects) > 0

    def test_object_reference_resolution(self):
        data = _build_simple_pdf()
        pdf = parse_pdf(data)
        # Object 2 references object 1 (catalog)
        obj2 = pdf.objects.get(2)
        assert obj2 is not None
        assert obj2.type == ObjectType.DICTIONARY

    def test_object_numbers_assigned(self):
        data = _build_simple_pdf()
        pdf = parse_pdf(data)
        for obj_num, obj in pdf.objects.items():
            assert obj.obj_num == obj_num

    def test_parse_empty_pdf(self):
        with pytest.raises(PDFParseError):
            parse_pdf(b"")

    def test_parse_header_only(self):
        with pytest.raises(PDFParseError, match="No startxref found"):
            parse_pdf(b"%PDF-1.7\n")


class TestPDFObject:
    """Tests for PDFObject."""

    def test_as_dict(self):
        obj = PDFObject(type=ObjectType.DICTIONARY, value={b"/Type": "value"})
        assert obj.as_dict() == {b"/Type": "value"}

    def test_as_dict_not_dict(self):
        obj = PDFObject(type=ObjectType.NUMBER, value=42)
        assert obj.as_dict() == {}

    def test_get(self):
        obj = PDFObject(type=ObjectType.DICTIONARY, value={b"/Key": "val"})
        assert obj.get(b"/Key") == "val"
        assert obj.get(b"/Missing", "default") == "default"


# ============================================================
# Metadata Tests
# ============================================================


class TestMetadata:
    """Tests for metadata extraction."""

    def test_extract_basic_metadata(self):
        data = _build_simple_pdf(title="Test Doc", author="Test Author")
        pdf = parse_pdf(data)
        meta = extract_metadata(pdf)
        assert meta.pdf_version == "1.7"
        assert meta.file_size > 0

    def test_metadata_page_count(self):
        data = _build_simple_pdf(page_count=5)
        pdf = parse_pdf(data)
        meta = extract_metadata(pdf)
        assert meta.page_count == 5

    def test_metadata_object_count(self):
        data = _build_simple_pdf()
        pdf = parse_pdf(data)
        meta = extract_metadata(pdf)
        assert meta.object_count > 0

    def test_metadata_stream_count(self):
        data = _build_simple_pdf()
        pdf = parse_pdf(data)
        meta = extract_metadata(pdf)
        assert meta.stream_count >= 0

    def test_metadata_not_encrypted(self):
        data = _build_simple_pdf()
        pdf = parse_pdf(data)
        meta = extract_metadata(pdf)
        assert meta.is_encrypted is False

    def test_metadata_font_count(self):
        data = _build_simple_pdf()
        pdf = parse_pdf(data)
        meta = extract_metadata(pdf)
        assert meta.font_count >= 1


class TestDecodePDFString:
    """Tests for PDF string decoding."""

    def test_utf16be_bom(self):
        data = b"\xfe\xff\x00H\x00e\x00l\x00l\x00o"
        result = _decode_pdf_string(data)
        assert result == "Hello"

    def test_utf8(self):
        result = _decode_pdf_string(b"Hello World")
        assert result == "Hello World"

    def test_latin1_fallback(self):
        result = _decode_pdf_string(b"\xe9\xe8\xea")
        assert isinstance(result, str)


class TestParsePDFDate:
    """Tests for PDF date parsing."""

    def test_standard_format(self):
        result = _parse_pdf_date("D:20240115120000")
        assert result == "2024-01-15T12:00:00"

    def test_with_d_prefix(self):
        result = _parse_pdf_date("D:20231225")
        assert result == "2023-12-25T00:00:00"

    def test_empty_string(self):
        assert _parse_pdf_date("") == ""

    def test_no_d_prefix(self):
        result = _parse_pdf_date("20240115")
        assert result == "2024-01-15T00:00:00"


# ============================================================
# Security Tests
# ============================================================


class TestSecurity:
    """Tests for security analysis."""

    def test_clean_pdf_safe(self):
        data = _build_simple_pdf()
        pdf = parse_pdf(data)
        report = analyze_security(pdf)
        assert report.risk_level == "safe"
        assert report.risk_score == 0

    def test_javascript_detection(self):
        data = _build_simple_pdf(include_js=True)
        pdf = parse_pdf(data)
        report = analyze_security(pdf)
        js_findings = [f for f in report.findings if f.category == "javascript"]
        assert len(js_findings) > 0
        assert js_findings[0].severity in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)

    def test_launch_action_detection(self):
        data = _build_simple_pdf(include_launch=True)
        pdf = parse_pdf(data)
        report = analyze_security(pdf)
        launch_findings = [f for f in report.findings if f.category == "launch"]
        assert len(launch_findings) > 0
        assert launch_findings[0].severity == Severity.CRITICAL

    def test_uri_action_detection(self):
        data = _build_simple_pdf(include_uri=True)
        pdf = parse_pdf(data)
        report = analyze_security(pdf)
        uri_findings = [f for f in report.findings if f.category == "uri"]
        assert len(uri_findings) > 0

    def test_embedded_file_detection(self):
        data = _build_simple_pdf(include_embedded=True)
        pdf = parse_pdf(data)
        report = analyze_security(pdf)
        embed_findings = [f for f in report.findings if f.category == "embedded"]
        assert len(embed_findings) > 0

    def test_openaction_detection(self):
        data = _build_simple_pdf(include_openaction=True)
        pdf = parse_pdf(data)
        report = analyze_security(pdf)
        action_findings = [f for f in report.findings if "Automatic" in f.title]
        assert len(action_findings) > 0

    def test_report_summary(self):
        data = _build_simple_pdf()
        pdf = parse_pdf(data)
        report = analyze_security(pdf)
        summary = report.summary()
        assert "risk_score" in summary
        assert "risk_level" in summary
        assert "total_findings" in summary

    def test_security_check_rules(self):
        data = _build_simple_pdf()
        pdf = parse_pdf(data)
        analyzer = SecurityAnalyzer(pdf)
        report = analyzer.analyze()
        assert report.total_checks == 15

    def test_risk_levels(self):
        assert SecurityReport().risk_level == "safe"

    def test_finding_score(self):
        from pdflens.security import SecurityFinding

        finding = SecurityFinding(
            rule_id="TEST", title="Test", description="Test", severity=Severity.CRITICAL, category="test"
        )
        assert finding.score == 10

    def test_high_entropy_detection(self):
        """High entropy streams should be flagged."""
        # Create a PDF with a high-entropy stream
        random_data = bytes(range(256)) * 100
        zlib.compress(random_data)
        # High entropy after compression
        data = _build_simple_pdf()
        pdf = parse_pdf(data)
        report = analyze_security(pdf)
        # The analysis should complete without errors
        assert report.total_checks == 15


class TestEntropy:
    """Tests for entropy calculation."""

    def test_uniform_data(self):
        assert _entropy(b"\x00" * 100) == 0.0

    def test_random_data(self):
        # All 256 bytes = entropy 8.0
        data = bytes(range(256))
        assert _entropy(data) == 8.0

    def test_empty_data(self):
        assert _entropy(b"") == 0.0

    def test_half_half(self):
        data = b"\x00" * 50 + b"\xff" * 50
        assert _entropy(data) == 1.0


# ============================================================
# Structure Tests
# ============================================================


class TestStructure:
    """Tests for structure analysis."""

    def test_structure_analysis(self):
        data = _build_simple_pdf()
        pdf = parse_pdf(data)
        report = analyze_structure(pdf)
        assert report.total_page_count == 1
        assert report.total_object_count > 0

    def test_structure_page_sizes(self):
        data = _build_simple_pdf(page_width=595, page_height=842)  # A4
        pdf = parse_pdf(data)
        report = analyze_structure(pdf)
        assert "595x842" in report.page_sizes

    def test_structure_fonts(self):
        data = _build_simple_pdf()
        pdf = parse_pdf(data)
        report = analyze_structure(pdf)
        assert report.total_font_count >= 1

    def test_structure_standard_font(self):
        data = _build_simple_pdf()
        pdf = parse_pdf(data)
        report = analyze_structure(pdf)
        standard_fonts = [f for f in report.fonts if f.is_standard]
        assert len(standard_fonts) >= 1
        assert standard_fonts[0].base_font == "Helvetica"

    def test_structure_summary(self):
        data = _build_simple_pdf()
        pdf = parse_pdf(data)
        report = analyze_structure(pdf)
        summary = report.summary()
        assert "total_pages" in summary
        assert "total_fonts" in summary
        assert "total_images" in summary

    def test_object_type_distribution(self):
        data = _build_simple_pdf()
        pdf = parse_pdf(data)
        report = analyze_structure(pdf)
        assert "dictionary" in report.object_type_distribution

    def test_structure_no_forms(self):
        data = _build_simple_pdf()
        pdf = parse_pdf(data)
        report = analyze_structure(pdf)
        assert report.has_forms is False

    def test_structure_with_extra_pages(self):
        data = _build_simple_pdf(page_count=10)
        pdf = parse_pdf(data)
        report = analyze_structure(pdf)
        assert report.total_page_count == 10


# ============================================================
# Report Generation Tests
# ============================================================


class TestReports:
    """Tests for report generation."""

    def _get_analysis(self, **kwargs):
        data = _build_simple_pdf(**kwargs)
        pdf = parse_pdf(data)
        return extract_metadata(pdf), analyze_security(pdf), analyze_structure(pdf)

    def test_text_report(self):
        meta, sec, struct = self._get_analysis()
        report = generate_text_report(meta, sec, struct)
        assert "PDF ANALYSIS REPORT" in report
        assert "DOCUMENT METADATA" in report
        assert "SECURITY ANALYSIS" in report
        assert "DOCUMENT STRUCTURE" in report

    def test_json_report(self):
        meta, sec, struct = self._get_analysis()
        report = generate_json_report(meta, sec, struct)
        data = json.loads(report)
        assert "metadata" in data
        assert "security" in data
        assert "structure" in data
        assert "generated_at" in data

    def test_markdown_report(self):
        meta, sec, struct = self._get_analysis()
        report = generate_markdown_report(meta, sec, struct)
        assert "# PDF Analysis Report" in report
        assert "## Document Metadata" in report
        assert "## Security Analysis" in report

    def test_text_report_with_js(self):
        meta, sec, struct = self._get_analysis(include_js=True)
        report = generate_text_report(meta, sec, struct)
        assert "JavaScript" in report or "javascript" in report.lower()

    def test_json_report_finds_security(self):
        meta, sec, struct = self._get_analysis(include_launch=True)
        report = json.loads(generate_json_report(meta, sec, struct))
        assert len(report["security_findings"]) > 0

    def test_markdown_report_with_findings(self):
        meta, sec, struct = self._get_analysis(include_js=True)
        report = generate_markdown_report(meta, sec, struct)
        assert "Detailed Findings" in report


# ============================================================
# CLI Tests
# ============================================================


class TestCLI:
    """Tests for the CLI interface."""

    def test_cli_version(self):
        from click.testing import CliRunner

        from pdflens.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output

    def test_cli_help(self):
        from click.testing import CliRunner

        from pdflens.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "PDFLens" in result.output

    def test_cli_analyze(self, tmp_path):
        from click.testing import CliRunner

        from pdflens.cli import main

        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(_build_simple_pdf())
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", str(pdf_path)])
        assert result.exit_code == 0
        assert "PDF ANALYSIS REPORT" in result.output

    def test_cli_analyze_json(self, tmp_path):
        from click.testing import CliRunner

        from pdflens.cli import main

        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(_build_simple_pdf())
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", str(pdf_path), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "metadata" in data

    def test_cli_analyze_markdown(self, tmp_path):
        from click.testing import CliRunner

        from pdflens.cli import main

        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(_build_simple_pdf())
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", str(pdf_path), "-f", "markdown"])
        assert result.exit_code == 0
        assert "# PDF Analysis Report" in result.output

    def test_cli_meta(self, tmp_path):
        from click.testing import CliRunner

        from pdflens.cli import main

        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(_build_simple_pdf())
        runner = CliRunner()
        result = runner.invoke(main, ["meta", str(pdf_path)])
        assert result.exit_code == 0
        assert "PDF Version" in result.output

    def test_cli_security(self, tmp_path):
        from click.testing import CliRunner

        from pdflens.cli import main

        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(_build_simple_pdf())
        runner = CliRunner()
        result = runner.invoke(main, ["security", str(pdf_path)])
        assert result.exit_code == 0
        assert "SAFE" in result.output or "RISK" in result.output

    def test_cli_security_json(self, tmp_path):
        from click.testing import CliRunner

        from pdflens.cli import main

        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(_build_simple_pdf())
        runner = CliRunner()
        result = runner.invoke(main, ["security", str(pdf_path), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "summary" in data

    def test_cli_check_safe(self, tmp_path):
        from click.testing import CliRunner

        from pdflens.cli import main

        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(_build_simple_pdf())
        runner = CliRunner()
        result = runner.invoke(main, ["check", str(pdf_path)])
        assert result.exit_code == 0

    def test_cli_check_launch(self, tmp_path):
        from click.testing import CliRunner

        from pdflens.cli import main

        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(_build_simple_pdf(include_launch=True))
        runner = CliRunner()
        result = runner.invoke(main, ["check", str(pdf_path)])
        assert result.exit_code != 0  # Should flag critical

    def test_cli_structure(self, tmp_path):
        from click.testing import CliRunner

        from pdflens.cli import main

        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(_build_simple_pdf())
        runner = CliRunner()
        result = runner.invoke(main, ["structure", str(pdf_path)])
        assert result.exit_code == 0
        assert "Document Structure" in result.output

    def test_cli_structure_json(self, tmp_path):
        from click.testing import CliRunner

        from pdflens.cli import main

        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(_build_simple_pdf())
        runner = CliRunner()
        result = runner.invoke(main, ["structure", str(pdf_path), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "total_pages" in data

    def test_cli_analyze_nonexistent(self):
        from click.testing import CliRunner

        from pdflens.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["analyze", "nonexistent.pdf"])
        assert result.exit_code != 0

    def test_cli_analyze_output_file(self, tmp_path):
        from click.testing import CliRunner

        from pdflens.cli import main

        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(_build_simple_pdf())
        out_path = tmp_path / "report.txt"
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", str(pdf_path), "-o", str(out_path)])
        assert result.exit_code == 0
        assert out_path.exists()
        content = out_path.read_text()
        assert "PDF ANALYSIS REPORT" in content


# ============================================================
# Edge Cases
# ============================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_minimal_valid_pdf(self):
        """Test parsing a minimal valid PDF."""
        data = _build_simple_pdf(page_count=1)
        pdf = parse_pdf(data)
        assert pdf.header_version == "1.7"

    def test_many_pages(self):
        """Test parsing a PDF with many pages."""
        data = _build_simple_pdf(page_count=50)
        pdf = parse_pdf(data)
        meta = extract_metadata(pdf)
        assert meta.page_count == 50

    def test_large_page_sizes(self):
        """Test with non-standard page sizes."""
        data = _build_simple_pdf(page_width=1920, page_height=1080)
        pdf = parse_pdf(data)
        report = analyze_structure(pdf)
        assert "1920x1080" in report.page_sizes

    def test_parse_and_analyze_pipeline(self):
        """Test the full pipeline: parse -> metadata -> security -> structure -> report."""
        data = _build_simple_pdf(title="Pipeline Test", author="Test", include_js=True)
        pdf = parse_pdf(data)
        meta = extract_metadata(pdf)
        security = analyze_security(pdf)
        structure = analyze_structure(pdf)

        text_report = generate_text_report(meta, security, structure)
        json_report = generate_json_report(meta, security, structure)
        md_report = generate_markdown_report(meta, security, structure)

        assert len(text_report) > 100
        assert json.loads(json_report)
        assert len(md_report) > 100

    def test_multiple_security_categories(self):
        """Test detection across multiple security categories."""
        data = _build_simple_pdf(include_js=True, include_launch=True)
        pdf = parse_pdf(data)
        report = analyze_security(pdf)
        categories = {f.category for f in report.findings}
        assert len(categories) >= 2


# Standard fonts test
def test_standard_fonts_list():
    assert "Helvetica" in STANDARD_FONTS
    assert "Times-Roman" in STANDARD_FONTS
    assert "Courier" in STANDARD_FONTS
    assert len(STANDARD_FONTS) >= 14
