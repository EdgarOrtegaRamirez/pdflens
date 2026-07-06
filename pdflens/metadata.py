"""
PDF metadata extraction — reads document info, page count, creation details,
and other metadata from the PDF trailer and info dictionary.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

from .pdf_parser import ObjectType, ParsedPDF, PDFObject


@dataclass
class PDFMetadata:
    """Comprehensive metadata extracted from a PDF."""
    # Document info
    title: str = ""
    author: str = ""
    subject: str = ""
    keywords: str = ""
    creator: str = ""  # Application that created the original
    producer: str = ""  # Application that produced the PDF
    creation_date: str = ""
    modification_date: str = ""
    # Technical
    pdf_version: str = ""
    file_size: int = 0
    page_count: int = 0
    is_linearized: bool = False
    is_encrypted: bool = False
    has_xref_streams: bool = False
    # Statistics
    object_count: int = 0
    stream_count: int = 0
    font_count: int = 0
    image_count: int = 0
    annotation_count: int = 0
    # Raw info dict values
    raw_info: dict = field(default_factory=dict)


def _resolve(obj: PDFObject, objects: dict) -> PDFObject:
    """Recursively resolve a reference."""
    if obj.type == ObjectType.REF:
        ref_num = obj.value[0]
        if ref_num in objects:
            return objects[ref_num]
    return obj


def _get_name_str(val: PDFObject | bytes | None) -> str:
    """Extract a string from a name or bytes."""
    if isinstance(val, bytes):
        return val.decode("latin-1", errors="replace")
    if isinstance(val, PDFObject):
        if val.type == ObjectType.NAME and isinstance(val.value, bytes):
            return val.value.decode("latin-1", errors="replace")
        if val.type == ObjectType.STRING_LITERAL and isinstance(val.value, bytes):
            return val.value.decode("latin-1", errors="replace")
    return ""


def _get_string(val: PDFObject | None, objects: dict) -> str:
    """Extract a text string from a PDF string object."""
    if val is None:
        return ""
    val = _resolve(val, objects)
    if val.type == ObjectType.STRING_LITERAL and isinstance(val.value, bytes):
        return _decode_pdf_string(val.value)
    if val.type == ObjectType.STRING_HEX and isinstance(val.value, bytes):
        return _decode_pdf_string(val.value)
    if val.type == ObjectType.NAME and isinstance(val.value, bytes):
        return val.value.decode("latin-1", errors="replace")
    return ""


def _decode_pdf_string(data: bytes) -> str:
    """Decode a PDF text string, handling UTF-16BE BOM and PDFDocEncoding."""
    if len(data) >= 2 and data[0] == 0xFE and data[1] == 0xFF:
        # UTF-16BE with BOM
        return data[2:].decode("utf-16-be", errors="replace")
    # Try UTF-8 first, then latin-1
    try:
        return data.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return data.decode("latin-1", errors="replace")


def _parse_pdf_date(date_str: str) -> str:
    """Parse a PDF date string (D:YYYYMMDDHHmmSS) into ISO format."""
    if not date_str:
        return ""
    # Remove D: prefix
    s = date_str.strip()
    if s.startswith("D:"):
        s = s[2:]
    # Match common patterns
    match = re.match(r"(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?(\d{2})?", s)
    if match:
        y, m, d = match.group(1), match.group(2), match.group(3)
        h = match.group(4) or "00"
        mi = match.group(5) or "00"
        sec = match.group(6) or "00"
        return f"{y}-{m}-{d}T{h}:{mi}:{sec}"
    return date_str


def extract_metadata(pdf: ParsedPDF) -> PDFMetadata:
    """Extract comprehensive metadata from a parsed PDF."""
    meta = PDFMetadata()
    meta.pdf_version = pdf.header_version
    meta.file_size = pdf.file_size
    meta.object_count = len(pdf.objects)
    meta.stream_count = len(pdf.streams)

    # Get trailer info
    root_ref = pdf.trailer.get(b"/Root")
    info_ref = pdf.trailer.get(b"/Info")
    encrypt_ref = pdf.trailer.get(b"/Encrypt")

    meta.is_encrypted = encrypt_ref is not None

    # Check for xref streams (PDF 1.5+)
    for obj in pdf.objects.values():
        if obj.type == ObjectType.DICTIONARY and isinstance(obj.value, dict):
            if b"/Type" in obj.value:
                type_val = obj.value[b"/Type"]
                if type_val.type == ObjectType.NAME and type_val.value == b"/XRef":
                    meta.has_xref_streams = True
                    break

    # Get info dictionary
    if info_ref is not None:
        info_obj = _resolve(info_ref, pdf.objects)
        if info_obj.type == ObjectType.DICTIONARY and isinstance(info_obj.value, dict):
            info_dict = info_obj.value
            meta.title = _get_string(info_dict.get(b"/Title"), pdf.objects)
            meta.author = _get_string(info_dict.get(b"/Author"), pdf.objects)
            meta.subject = _get_string(info_dict.get(b"/Subject"), pdf.objects)
            meta.keywords = _get_string(info_dict.get(b"/Keywords"), pdf.objects)
            meta.creator = _get_string(info_dict.get(b"/Creator"), pdf.objects)
            meta.producer = _get_string(info_dict.get(b"/Producer"), pdf.objects)
            meta.creation_date = _parse_pdf_date(_get_string(info_dict.get(b"/CreationDate"), pdf.objects))
            meta.modification_date = _parse_pdf_date(_get_string(info_dict.get(b"/ModDate"), pdf.objects))
            meta.raw_info = {k.decode("latin-1", errors="replace"): str(v) for k, v in info_dict.items()}

    # Count pages and resources from page tree
    if root_ref is not None:
        root_obj = _resolve(root_ref, pdf.objects)
        if root_obj.type == ObjectType.DICTIONARY and isinstance(root_obj.value, dict):
            pages_ref = root_obj.value.get(b"/Pages")
            if pages_ref is not None:
                pages_obj = _resolve(pages_ref, pdf.objects)
                if pages_obj.type == ObjectType.DICTIONARY and isinstance(pages_obj.value, dict):
                    count_val = pages_obj.value.get(b"/Count")
                    if count_val and count_val.type == ObjectType.NUMBER:
                        meta.page_count = int(count_val.value)
                    # Count fonts and images in page tree
                    _count_resources(pages_obj, pdf.objects, meta)

    # Check linearization
    if pdf.objects:
        first_obj = pdf.objects.get(1)
        if first_obj and first_obj.type == ObjectType.DICTIONARY and isinstance(first_obj.value, dict):
            if b"/Linearized" in first_obj.value:
                meta.is_linearized = True

    # Count annotations by scanning all page objects
    meta.annotation_count = _count_annotations(pdf.objects)

    return meta


def _count_resources(pages_obj: PDFObject, objects: dict, meta: PDFMetadata):
    """Recursively count fonts and images in page tree."""
    if pages_obj.type != ObjectType.DICTIONARY:
        return
    pages_dict = pages_obj.value if isinstance(pages_obj.value, dict) else {}

    kids = pages_dict.get(b"/Kids")
    if kids and kids.type == ObjectType.ARRAY:
        for kid_ref in kids.value:
            kid = _resolve(kid_ref, objects)
            if kid.type == ObjectType.DICTIONARY and isinstance(kid.value, dict):
                kid_dict = kid.value
                type_val = kid_dict.get(b"/Type")
                if type_val and type_val.type == ObjectType.NAME and type_val.value == b"/Page":
                    resources = kid_dict.get(b"/Resources")
                    if resources:
                        resources = _resolve(resources, objects)
                        _count_in_resources(resources, objects, meta)
                else:
                    _count_resources(kid, objects, meta)


def _count_in_resources(resources: PDFObject, objects: dict, meta: PDFMetadata):
    """Count fonts and images in a Resources dictionary."""
    if resources.type != ObjectType.DICTIONARY:
        return
    res_dict = resources.value if isinstance(resources.value, dict) else {}

    fonts = res_dict.get(b"/Font")
    if fonts:
        fonts = _resolve(fonts, objects)
        if fonts.type == ObjectType.DICTIONARY and isinstance(fonts.value, dict):
            meta.font_count += len(fonts.value)

    xobjects = res_dict.get(b"/XObject")
    if xobjects:
        xobjects = _resolve(xobjects, objects)
        if xobjects.type == ObjectType.DICTIONARY and isinstance(xobjects.value, dict):
            for xobj_ref in xobjects.value.values():
                xobj = _resolve(xobj_ref, objects)
                if xobj.type == ObjectType.DICTIONARY and isinstance(xobj.value, dict):
                    subtype = xobj.value.get(b"/Subtype")
                    if subtype and subtype.type == ObjectType.NAME:
                        if subtype.value in (b"/Image", b"/Form"):
                            meta.image_count += 1


def _count_annotations(objects: dict) -> int:
    """Count annotations across all page objects."""
    count = 0
    for obj in objects.values():
        if obj.type != ObjectType.DICTIONARY:
            continue
        obj_dict = obj.value if isinstance(obj.value, dict) else {}
        type_val = obj_dict.get(b"/Type")
        if type_val and type_val.type == ObjectType.NAME and type_val.value == b"/Page":
            annots = obj_dict.get(b"/Annots")
            if annots:
                annots_resolved = _resolve(annots, objects)
                if annots_resolved.type == ObjectType.ARRAY:
                    count += len(annots_resolved.value)
    return count
