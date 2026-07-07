"""
PDF Structure Analysis — examines the internal structure of PDF documents
including page tree, fonts, images, annotations, and resource usage.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .pdf_parser import ObjectType, ParsedPDF, PDFObject


@dataclass
class FontInfo:
    """Information about a font in the PDF."""

    name: str = ""
    base_font: str = ""
    font_type: str = ""  # Type0, Type1, TrueType, CIDFontType0, CIDFontType2
    encoding: str = ""
    has_to_unicode: bool = False
    is_standard: bool = False
    object_num: int = 0


@dataclass
class ImageInfo:
    """Information about an image in the PDF."""

    width: int = 0
    height: int = 0
    bits_per_component: int = 0
    color_space: str = ""
    filter: str = ""
    object_num: int = 0
    size_bytes: int = 0


@dataclass
class PageInfo:
    """Information about a page."""

    page_num: int = 0
    width: float = 0
    height: float = 0
    rotation: int = 0
    font_count: int = 0
    image_count: int = 0
    annotation_count: int = 0
    has_annotations: bool = False
    has_form_xobjects: bool = False
    mediabox: list[float] = field(default_factory=list)


@dataclass
class StructureReport:
    """Complete structure analysis report."""

    pages: list[PageInfo] = field(default_factory=list)
    fonts: list[FontInfo] = field(default_factory=list)
    images: list[ImageInfo] = field(default_factory=list)
    total_page_count: int = 0
    total_font_count: int = 0
    total_image_count: int = 0
    total_annotation_count: int = 0
    total_object_count: int = 0
    total_stream_count: int = 0
    has_forms: bool = False
    has_bookmarks: bool = False
    has_attachments: bool = False
    has_javascript: bool = False
    has_embedded_files: bool = False
    page_sizes: dict[str, int] = field(default_factory=dict)
    object_type_distribution: dict[str, int] = field(default_factory=dict)
    max_depth: int = 0

    def summary(self) -> dict:
        return {
            "total_pages": self.total_page_count,
            "total_fonts": self.total_font_count,
            "total_images": self.total_image_count,
            "total_annotations": self.total_annotation_count,
            "total_objects": self.total_object_count,
            "total_streams": self.total_stream_count,
            "has_forms": self.has_forms,
            "has_bookmarks": self.has_bookmarks,
            "has_attachments": self.has_attachments,
            "has_javascript": self.has_javascript,
            "has_embedded_files": self.has_embedded_files,
            "page_sizes": self.page_sizes,
            "object_types": self.object_type_distribution,
            "max_page_tree_depth": self.max_depth,
        }


def _resolve(obj: PDFObject, objects: dict) -> PDFObject:
    """Resolve a reference."""
    if obj.type == ObjectType.REF and isinstance(obj.value, tuple):
        ref_num = obj.value[0]
        if ref_num in objects:
            return objects[ref_num]
    return obj


def _get_name(val: PDFObject | None) -> str:
    """Extract name string."""
    if val is None:
        return ""
    if isinstance(val, bytes):
        s = val.decode("latin-1", errors="replace")
        return s.lstrip("/")
    if val.type == ObjectType.NAME and isinstance(val.value, bytes):
        s = val.value.decode("latin-1", errors="replace")
        return s.lstrip("/")
    return ""


STANDARD_FONTS = {
    "Courier",
    "Courier-Bold",
    "Courier-Oblique",
    "Courier-BoldOblique",
    "Helvetica",
    "Helvetica-Bold",
    "Helvetica-Oblique",
    "Helvetica-BoldOblique",
    "Times-Roman",
    "Times-Bold",
    "Times-Italic",
    "Times-BoldItalic",
    "Symbol",
    "ZapfDingbats",
    "CourierNew",
    "CourierNew,Bold",
    "CourierNew,Italic",
    "CourierNew,BoldItalic",
    "Arial",
    "Arial,Bold",
    "Arial,Italic",
    "Arial,BoldItalic",
    "TimesNewRoman",
    "TimesNewRoman,Bold",
    "TimesNewRoman,Italic",
    "TimesNewRoman,BoldItalic",
}


def analyze_structure(pdf: ParsedPDF) -> StructureReport:
    """Analyze the internal structure of a parsed PDF."""
    report = StructureReport()
    report.total_object_count = len(pdf.objects)
    report.total_stream_count = len(pdf.streams)

    # Count object types
    type_names = {
        ObjectType.BOOLEAN: "boolean",
        ObjectType.NUMBER: "number",
        ObjectType.STRING_LITERAL: "string_literal",
        ObjectType.STRING_HEX: "string_hex",
        ObjectType.NAME: "name",
        ObjectType.ARRAY: "array",
        ObjectType.DICTIONARY: "dictionary",
        ObjectType.STREAM: "stream",
        ObjectType.REF: "reference",
        ObjectType.NULL: "null",
    }
    for obj in pdf.objects.values():
        tname = type_names.get(obj.type, "unknown")
        report.object_type_distribution[tname] = report.object_type_distribution.get(tname, 0) + 1

    # Analyze page tree
    root_ref = pdf.trailer.get(b"/Root")
    if root_ref is not None:
        root = _resolve(root_ref, pdf.objects)
        if root.type == ObjectType.DICTIONARY and isinstance(root.value, dict):
            pages_ref = root.value.get(b"/Pages")
            if pages_ref is not None:
                pages_obj = _resolve(pages_ref, pdf.objects)
                if pages_obj.type == ObjectType.DICTIONARY and isinstance(pages_obj.value, dict):
                    count_val = pages_obj.value.get(b"/Count")
                    if count_val and count_val.type == ObjectType.NUMBER:
                        report.total_page_count = int(count_val.value)
                    _analyze_page_tree(pages_obj, pdf.objects, report, depth=0)

            # Check for outlines (bookmarks)
            outline_ref = root.value.get(b"/Outlines")
            if outline_ref:
                report.has_bookmarks = True

            # Check for AcroForm
            if b"/AcroForm" in root.value:
                report.has_forms = True

    # Analyze fonts and images
    _collect_fonts(pdf.objects, report)
    _collect_images(pdf.objects, report)

    # Check for embedded files
    for obj in pdf.objects.values():
        if obj.type == ObjectType.DICTIONARY and isinstance(obj.value, dict):
            type_val = obj.value.get(b"/Type")
            if type_val and type_val.type == ObjectType.NAME and type_val.value == b"/EmbeddedFile":
                report.has_embedded_files = True
                report.has_attachments = True
            # Check for JavaScript
            if b"/JS" in obj.value:
                report.has_javascript = True

    # Calculate unique page sizes
    for page in report.pages:
        if page.width > 0 and page.height > 0:
            size_key = f"{page.width:.0f}x{page.height:.0f}"
            report.page_sizes[size_key] = report.page_sizes.get(size_key, 0) + 1

    return report


def _analyze_page_tree(node: PDFObject, objects: dict, report: StructureReport, depth: int):
    """Recursively analyze the page tree."""
    if node.type != ObjectType.DICTIONARY:
        return
    node_dict = node.value if isinstance(node.value, dict) else {}

    if depth > report.max_depth:
        report.max_depth = depth

    type_val = node_dict.get(b"/Type")
    is_page = type_val and type_val.type == ObjectType.NAME and type_val.value == b"/Page"

    if is_page:
        page = _extract_page_info(node_dict, objects, len(report.pages) + 1)
        report.pages.append(page)
        report.total_annotation_count += page.annotation_count
        return

    # Recurse into children
    kids = node_dict.get(b"/Kids")
    if kids:
        kids_resolved = _resolve(kids, objects)
        if kids_resolved.type == ObjectType.ARRAY:
            for kid_ref in kids_resolved.value:
                kid = _resolve(kid_ref, objects)
                _analyze_page_tree(kid, objects, report, depth + 1)


def _extract_page_info(page_dict: dict, objects: dict, page_num: int) -> PageInfo:
    """Extract info from a page dictionary."""
    page = PageInfo(page_num=page_num)

    # MediaBox
    mediabox = page_dict.get(b"/MediaBox")
    if mediabox:
        mediabox = _resolve(mediabox, objects)
        if mediabox.type == ObjectType.ARRAY and len(mediabox.value) >= 4:
            try:
                coords = []
                for v in mediabox.value[:4]:
                    if v.type == ObjectType.NUMBER:
                        coords.append(float(v.value))
                    else:
                        coords.append(0.0)
                page.mediabox = coords
                page.width = coords[2] - coords[0]
                page.height = coords[3] - coords[1]
            except (ValueError, TypeError, IndexError):
                pass

    # Rotation
    rotate = page_dict.get(b"/Rotate")
    if rotate and rotate.type == ObjectType.NUMBER:
        page.rotation = int(rotate.value)

    # Count resources
    resources = page_dict.get(b"/Resources")
    if resources:
        resources = _resolve(resources, objects)
        if resources.type == ObjectType.DICTIONARY and isinstance(resources.value, dict):
            fonts = resources.value.get(b"/Font")
            if fonts:
                fonts = _resolve(fonts, objects)
                if fonts.type == ObjectType.DICTIONARY:
                    page.font_count = len(fonts.value)

            xobjects = resources.value.get(b"/XObject")
            if xobjects:
                xobjects = _resolve(xobjects, objects)
                if xobjects.type == ObjectType.DICTIONARY:
                    for xobj_ref in xobjects.value.values():
                        xobj = _resolve(xobj_ref, objects)
                        if xobj.type == ObjectType.DICTIONARY and isinstance(xobj.value, dict):
                            subtype = xobj.value.get(b"/Subtype")
                            if subtype and subtype.type == ObjectType.NAME:
                                if subtype.value == b"/Image":
                                    page.image_count += 1
                                elif subtype.value == b"/Form":
                                    page.has_form_xobjects = True

    # Annotations
    annots = page_dict.get(b"/Annots")
    if annots:
        annots = _resolve(annots, objects)
        if annots.type == ObjectType.ARRAY:
            page.annotation_count = len(annots.value)
            page.has_annotations = True

    return page


def _collect_fonts(objects: dict, report: StructureReport):
    """Collect font information from all objects."""
    seen_fonts: set[int] = set()
    for obj_num, obj in objects.items():
        if obj.type != ObjectType.DICTIONARY or not isinstance(obj.value, dict):
            continue
        obj.value.get(b"/Type")
        subtype = obj.value.get(b"/Subtype")
        if not subtype or subtype.type != ObjectType.NAME:
            continue
        # Direct font objects
        if subtype.value in (b"/Type0", b"/Type1", b"/TrueType", b"/CIDFontType0", b"/CIDFontType2"):
            if obj_num in seen_fonts:
                continue
            seen_fonts.add(obj_num)

            font = FontInfo(object_num=obj_num)
            font.font_type = subtype.value.decode("latin-1", errors="replace").lstrip("/")

            base_font = obj.value.get(b"/BaseFont")
            if base_font:
                font.base_font = _get_name(base_font)
                font.name = font.base_font
                font.is_standard = font.base_font in STANDARD_FONTS

            encoding = obj.value.get(b"/Encoding")
            if encoding:
                font.encoding = _get_name(encoding) if encoding.type == ObjectType.NAME else "complex"

            to_unicode = obj.value.get(b"/ToUnicode")
            font.has_to_unicode = to_unicode is not None

            report.fonts.append(font)

    report.total_font_count = len(report.fonts)


def _collect_images(objects: dict, report: StructureReport):
    """Collect image information from all objects."""
    seen_images: set[int] = set()
    for obj_num, obj in objects.items():
        if obj.type != ObjectType.STREAM:
            continue
        stream_dict = obj.stream_dict or {}
        if isinstance(obj.value, dict):
            stream_dict = obj.value

        subtype = stream_dict.get(b"/Subtype")
        if not (subtype and subtype.type == ObjectType.NAME and subtype.value == b"/Image"):
            continue
        if obj_num in seen_images:
            continue
        seen_images.add(obj_num)

        image = ImageInfo(object_num=obj_num)

        width = stream_dict.get(b"/Width")
        if width and width.type == ObjectType.NUMBER:
            image.width = int(width.value)

        height = stream_dict.get(b"/Height")
        if height and height.type == ObjectType.NUMBER:
            image.height = int(height.value)

        bpc = stream_dict.get(b"/BitsPerComponent")
        if bpc and bpc.type == ObjectType.NUMBER:
            image.bits_per_component = int(bpc.value)

        cs = stream_dict.get(b"/ColorSpace")
        if cs:
            image.color_space = _get_name(cs)

        filt = stream_dict.get(b"/Filter")
        if filt:
            if filt.type == ObjectType.NAME:
                image.filter = _get_name(filt)
            elif filt.type == ObjectType.ARRAY and filt.value:
                image.filter = _get_name(filt.value[0])

        if obj.stream_data:
            image.size_bytes = len(obj.stream_data)

        report.images.append(image)

    report.total_image_count = len(report.images)
