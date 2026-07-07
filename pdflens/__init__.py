"""PDFLens — PDF Analysis & Security Toolkit"""

__version__ = "1.0.0"

from .metadata import PDFMetadata as PDFMetadata
from .metadata import extract_metadata as extract_metadata
from .pdf_parser import ParsedPDF as ParsedPDF
from .pdf_parser import PDFParseError as PDFParseError
from .pdf_parser import PDFParser as PDFParser
from .pdf_parser import parse_pdf as parse_pdf
from .pdf_parser import parse_pdf_file as parse_pdf_file
from .report import generate_json_report as generate_json_report
from .report import generate_markdown_report as generate_markdown_report
from .report import generate_text_report as generate_text_report
from .security import SecurityAnalyzer as SecurityAnalyzer
from .security import SecurityReport as SecurityReport
from .security import analyze_security as analyze_security
from .structure import StructureReport as StructureReport
from .structure import analyze_structure as analyze_structure

__all__ = [
    "PDFMetadata",
    "extract_metadata",
    "ParsedPDF",
    "PDFParseError",
    "PDFParser",
    "parse_pdf",
    "parse_pdf_file",
    "generate_json_report",
    "generate_markdown_report",
    "generate_text_report",
    "SecurityAnalyzer",
    "SecurityReport",
    "analyze_security",
    "StructureReport",
    "analyze_structure",
]
