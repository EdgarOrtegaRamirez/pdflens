"""PDFLens — PDF Analysis & Security Toolkit"""

__version__ = "1.0.0"

from .pdf_parser import parse_pdf, parse_pdf_file, ParsedPDF, PDFParser, PDFParseError
from .metadata import extract_metadata, PDFMetadata
from .security import analyze_security, SecurityReport, SecurityAnalyzer
from .structure import analyze_structure, StructureReport
from .report import generate_text_report, generate_json_report, generate_markdown_report
