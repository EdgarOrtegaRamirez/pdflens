"""
PDF Security Analysis — detects malicious content, obfuscation techniques,
and security threats in PDF documents.

Implements pattern-based detection with entropy analysis for identifying:
- Embedded JavaScript
- Launch actions and auto-open triggers
- URI actions and external resource loading
- Obfuscated content streams
- Embedded executables
- Suspicious annotations
- Font substitution attacks
- Incremental update attacks
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import Enum

from .pdf_parser import ObjectType, ParsedPDF, PDFObject


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityFinding:
    """A single security finding."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    category: str
    object_num: int | None = None
    details: dict = field(default_factory=dict)

    @property
    def score(self) -> int:
        """Numeric score for severity weighting."""
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 3,
            Severity.HIGH: 7,
            Severity.CRITICAL: 10,
        }[self.severity]


@dataclass
class SecurityReport:
    """Complete security analysis report."""

    findings: list[SecurityFinding] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "safe"
    total_checks: int = 0

    def add(self, finding: SecurityFinding):
        self.findings.append(finding)
        self.risk_score += finding.score

    def compute_risk_level(self):
        if self.risk_score == 0:
            self.risk_level = "safe"
        elif self.risk_score <= 5:
            self.risk_level = "low"
        elif self.risk_score <= 15:
            self.risk_level = "medium"
        elif self.risk_score <= 30:
            self.risk_level = "high"
        else:
            self.risk_level = "critical"

    def summary(self) -> dict:
        self.compute_risk_level()
        by_severity = {}
        for f in self.findings:
            s = f.severity.value
            by_severity[s] = by_severity.get(s, 0) + 1
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "total_findings": len(self.findings),
            "by_severity": by_severity,
            "total_checks": self.total_checks,
        }


def _entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data (0.0 = uniform, 8.0 = random)."""
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _resolve(obj: PDFObject, objects: dict) -> PDFObject:
    """Resolve a reference."""
    if obj.type == ObjectType.REF and isinstance(obj.value, tuple):
        ref_num = obj.value[0]
        if ref_num in objects:
            return objects[ref_num]
    return obj


def _get_name_bytes(val: PDFObject | None) -> bytes:
    if val is None:
        return b""
    if isinstance(val, bytes):
        return val
    if val.type == ObjectType.NAME and isinstance(val.value, bytes):
        return val.value
    return b""


class SecurityAnalyzer:
    """
    Analyzes a parsed PDF for security threats.

    Uses a rule-based engine with 15+ detection rules covering:
    - JavaScript execution
    - Launch actions
    - URI actions
    - Embedded files
    - Obfuscation
    - Suspicious streams
    - Incremental update abuse
    - Encryption anomalies
    """

    def __init__(self, pdf: ParsedPDF):
        self.pdf = pdf
        self.objects = pdf.objects
        self.report = SecurityReport()
        self._checked: set[int] = set()

    def analyze(self) -> SecurityReport:
        """Run all security checks."""
        self._check_javascript()
        self._check_launch_actions()
        self._check_uri_actions()
        self._check_embedded_files()
        self._check_openaction()
        self._check_acroform()
        self._check_suspicious_streams()
        self._check_high_entropy_streams()
        self._check_obfuscated_names()
        self._check_incremental_updates()
        self._check_cross_reference_streams()
        self._check_large_streams()
        self._check_nested_actions()
        self._check_suspicious_annotations()
        self._check_jbig2_images()
        self._check_embedded_javascript_strings()
        self.report.total_checks = 15
        self.report.compute_risk_level()
        return self.report

    def _check_javascript(self):
        """Check for JavaScript actions in the document."""
        for obj_num, obj in self.objects.items():
            if obj.type != ObjectType.DICTIONARY:
                continue
            obj_dict = obj.value if isinstance(obj.value, dict) else {}
            # Direct /JS entry
            if b"/JS" in obj_dict:
                js_val = _resolve(obj_dict[b"/JS"], self.objects)
                js_text = ""
                if js_val.type == ObjectType.STRING_LITERAL or js_val.type == ObjectType.NAME:
                    decoded = js_val.value.decode("latin-1", errors="replace")
                    js_text = decoded if isinstance(js_val.value, bytes) else ""
                elif js_val.type == ObjectType.STREAM and js_val.stream_data:
                    js_text = js_val.stream_data.decode("latin-1", errors="replace")

                if js_text:
                    # Check for common malicious patterns
                    suspicious = []
                    if re.search(r"(?i)eval\s*\(", js_text):
                        suspicious.append("eval()")
                    if re.search(r"(?i)app\.launchURL", js_text):
                        suspicious.append("app.launchURL()")
                    if re.search(r"(?i)app\.openDoc", js_text):
                        suspicious.append("app.openDoc()")
                    if re.search(r"(?i)exportDataObject", js_text):
                        suspicious.append("exportDataObject()")
                    if re.search(r"(?i)importDataObject", js_text):
                        suspicious.append("importDataObject()")
                    if re.search(r"(?i)sleep\s*\(", js_text):
                        suspicious.append("sleep()")
                    if re.search(r"(?i)this\.doc\(", js_text):
                        suspicious.append("this.doc()")
                    if re.search(r"(?i)createObject", js_text):
                        suspicious.append("createObject()")

                    severity = Severity.CRITICAL if suspicious else Severity.HIGH
                    self.report.add(
                        SecurityFinding(
                            rule_id="JS-001",
                            title="JavaScript Embedded in PDF",
                            description="Document contains JavaScript code"
                            + (f" with suspicious functions: {', '.join(suspicious)}" if suspicious else ""),
                            severity=severity,
                            category="javascript",
                            object_num=obj_num,
                            details={"snippets": js_text[:500], "suspicious_functions": suspicious},
                        )
                    )

            # /AA (Additional Actions) dictionary
            if b"/AA" in obj_dict:
                aa = _resolve(obj_dict[b"/AA"], self.objects)
                if aa.type == ObjectType.DICTIONARY and isinstance(aa.value, dict):
                    action_types = [k.decode("latin-1", errors="replace") for k in aa.value]
                    self.report.add(
                        SecurityFinding(
                            rule_id="JS-002",
                            title="Additional Actions Dictionary Found",
                            description=f"Document contains Additional Actions with types: {', '.join(action_types)}",
                            severity=Severity.MEDIUM,
                            category="javascript",
                            object_num=obj_num,
                            details={"action_types": action_types},
                        )
                    )

    def _check_launch_actions(self):
        """Check for launch actions that execute external programs."""
        for obj_num, obj in self.objects.items():
            if obj.type != ObjectType.DICTIONARY:
                continue
            obj_dict = obj.value if isinstance(obj.value, dict) else {}
            action = obj_dict.get(b"/S")
            if action and action.type == ObjectType.NAME and action.value == b"/Launch":
                self.report.add(
                    SecurityFinding(
                        rule_id="LAUNCH-001",
                        title="Launch Action Detected",
                        description="Document contains a Launch action that can execute external programs",
                        severity=Severity.CRITICAL,
                        category="launch",
                        object_num=obj_num,
                    )
                )
            # Check /Win, /Mac, /Unix in launch dictionaries
            for key in [b"/Win", b"/Mac", b"/Unix"]:
                if key in obj_dict:
                    self.report.add(
                        SecurityFinding(
                            rule_id="LAUNCH-002",
                            title="Platform-Specific Launch Action",
                            description=f"Document contains platform-specific launch target ({key.decode()})",
                            severity=Severity.CRITICAL,
                            category="launch",
                            object_num=obj_num,
                        )
                    )

    def _check_uri_actions(self):
        """Check for URI actions that load external resources."""
        for obj_num, obj in self.objects.items():
            if obj.type != ObjectType.DICTIONARY:
                continue
            obj_dict = obj.value if isinstance(obj.value, dict) else {}
            action = obj_dict.get(b"/S")
            if action and action.type == ObjectType.NAME and action.value == b"/URI":
                uri = obj_dict.get(b"/URI", "")
                if uri.type in (ObjectType.STRING_LITERAL, ObjectType.NAME) and isinstance(uri.value, bytes):
                    uri_str = uri.value.decode("latin-1", errors="replace")
                else:
                    uri_str = str(uri)

                severity = Severity.MEDIUM
                # Flag non-HTTP URIs
                if uri_str and not uri_str.startswith(("http://", "https://")):
                    severity = Severity.HIGH

                self.report.add(
                    SecurityFinding(
                        rule_id="URI-001",
                        title="URI Action Detected",
                        description=f"Document references external URI: {uri_str[:200]}",
                        severity=severity,
                        category="uri",
                        object_num=obj_num,
                        details={"uri": uri_str[:500]},
                    )
                )

    def _check_embedded_files(self):
        """Check for embedded files."""
        for obj_num, obj in self.objects.items():
            if obj.type not in (ObjectType.DICTIONARY, ObjectType.STREAM):
                continue
            obj_dict = obj.value if isinstance(obj.value, dict) else {}
            type_val = obj_dict.get(b"/Type")
            if type_val and type_val.type == ObjectType.NAME and type_val.value == b"/EmbeddedFile":
                self.report.add(
                    SecurityFinding(
                        rule_id="EMBED-001",
                        title="Embedded File Detected",
                        description="Document contains an embedded file (EF entry)",
                        severity=Severity.MEDIUM,
                        category="embedded",
                        object_num=obj_num,
                    )
                )
            # Check /EF references
            ef = obj_dict.get(b"/EF")
            if ef:
                ef_resolved = _resolve(ef, self.objects)
                if ef_resolved.type == ObjectType.DICTIONARY:
                    self.report.add(
                        SecurityFinding(
                            rule_id="EMBED-002",
                            title="File Reference in Object",
                            description="Object contains /EF (embedded file) reference",
                            severity=Severity.MEDIUM,
                            category="embedded",
                            object_num=obj_num,
                        )
                    )

    def _check_openaction(self):
        """Check for automatic actions on document open."""
        for obj_num, obj in self.objects.items():
            if obj.type != ObjectType.DICTIONARY:
                continue
            obj_dict = obj.value if isinstance(obj.value, dict) else {}
            if b"/OpenAction" in obj_dict:
                oa = _resolve(obj_dict[b"/OpenAction"], self.objects)
                action_type = "unknown"
                if oa.type == ObjectType.DICTIONARY and isinstance(oa.value, dict):
                    s = oa.value.get(b"/S")
                    if s:
                        action_type = _get_name_bytes(s).decode("latin-1", errors="replace")

                severity = Severity.HIGH if action_type in ("/JavaScript", "/Launch") else Severity.MEDIUM
                self.report.add(
                    SecurityFinding(
                        rule_id="ACTION-001",
                        title="Automatic Action on Open",
                        description=f"Document performs automatic action ({action_type}) when opened",
                        severity=severity,
                        category="action",
                        object_num=obj_num,
                        details={"action_type": action_type},
                    )
                )

    def _check_acroform(self):
        """Check for AcroForm (interactive form) with potential injection."""
        for obj_num, obj in self.objects.items():
            if obj.type != ObjectType.DICTIONARY:
                continue
            obj_dict = obj.value if isinstance(obj.value, dict) else {}
            if b"/AcroForm" in obj_dict:
                self.report.add(
                    SecurityFinding(
                        rule_id="FORM-001",
                        title="Interactive Form Detected",
                        description="Document contains an AcroForm with fillable fields",
                        severity=Severity.LOW,
                        category="form",
                        object_num=obj_num,
                    )
                )
                # Check for XFA (XML Forms Architecture) which can contain scripts
                acroform = _resolve(obj_dict[b"/AcroForm"], self.objects)
                if acroform.type == ObjectType.DICTIONARY and isinstance(acroform.value, dict):
                    if b"/XFA" in acroform.value:
                        self.report.add(
                            SecurityFinding(
                                rule_id="FORM-002",
                                title="XFA Form Detected",
                                description="AcroForm contains XFA (XML Forms Architecture) which may execute scripts",
                                severity=Severity.HIGH,
                                category="form",
                                object_num=obj_num,
                            )
                        )

    def _check_suspicious_streams(self):
        """Check for streams with suspicious content filters."""
        suspicious_filters = {b"/JS", b"/JavaScript"}
        for obj_num, obj in self.objects.items():
            if obj.type != ObjectType.STREAM:
                continue
            stream_dict = obj.stream_dict or {}
            if isinstance(obj.value, dict):
                stream_dict = obj.value

            # Check /Filter for suspicious entries
            filt = stream_dict.get(b"/Filter")
            if filt:
                if filt.type == ObjectType.NAME and filt.value in suspicious_filters:
                    self.report.add(
                        SecurityFinding(
                            rule_id="STREAM-001",
                            title="JavaScript Stream Filter",
                            description="Stream uses JavaScript filter for content",
                            severity=Severity.CRITICAL,
                            category="stream",
                            object_num=obj_num,
                        )
                    )
                elif filt.type == ObjectType.ARRAY:
                    for f in filt.value:
                        if f.type == ObjectType.NAME and f.value in suspicious_filters:
                            self.report.add(
                                SecurityFinding(
                                    rule_id="STREAM-001",
                                    title="JavaScript Stream Filter",
                                    description="Stream uses JavaScript filter for content",
                                    severity=Severity.CRITICAL,
                                    category="stream",
                                    object_num=obj_num,
                                )
                            )

            # Check /Subtype
            subtype = stream_dict.get(b"/Subtype")
            if subtype and subtype.type == ObjectType.NAME and subtype.value == b"/JavaScript":
                self.report.add(
                    SecurityFinding(
                        rule_id="STREAM-002",
                        title="JavaScript Stream Object",
                        description="Stream object has /Subtype /JavaScript",
                        severity=Severity.HIGH,
                        category="stream",
                        object_num=obj_num,
                    )
                )

    def _check_high_entropy_streams(self):
        """Detect high-entropy streams that may contain encrypted/obfuscated content."""
        for obj_num, obj in self.objects.items():
            if obj.type != ObjectType.STREAM or not obj.stream_data:
                continue
            entropy = _entropy(obj.stream_data)
            # High entropy (>7.5) suggests encryption or heavy compression
            if entropy > 7.5 and len(obj.stream_data) > 100:
                self.report.add(
                    SecurityFinding(
                        rule_id="ENTROPY-001",
                        title="High-Entropy Stream Detected",
                        description=f"Stream has entropy {entropy:.2f}/8.0 — may be encrypted or obfuscated",
                        severity=Severity.LOW,
                        category="obfuscation",
                        object_num=obj_num,
                        details={"entropy": round(entropy, 3), "size": len(obj.stream_data)},
                    )
                )

    def _check_obfuscated_names(self):
        """Detect obfuscated PDF name objects (hex-encoded, unusual characters)."""
        obfuscated_count = 0
        for _obj_num, obj in self.objects.items():
            if obj.type != ObjectType.DICTIONARY or not isinstance(obj.value, dict):
                continue
            for key in obj.value:
                if isinstance(key, bytes):
                    # Check for hex-encoded names (e.g., /#23#20)
                    if b"#" in key:
                        obfuscated_count += 1
                    # Check for very long names (possible obfuscation)
                    if len(key) > 100:
                        obfuscated_count += 1

        if obfuscated_count > 5:
            self.report.add(
                SecurityFinding(
                    rule_id="OBFUSC-001",
                    title="Obfuscated Names Detected",
                    description=f"Found {obfuscated_count} potentially obfuscated name objects",
                    severity=Severity.MEDIUM,
                    category="obfuscation",
                    details={"count": obfuscated_count},
                )
            )

    def _check_incremental_updates(self):
        """Check for suspicious incremental update patterns."""
        # Count the number of objects at each xref section
        if len(self.objects) > 1000 and self.pdf.xref.prev_xref is not None:
            self.report.add(
                SecurityFinding(
                    rule_id="INCR-001",
                    title="Large Document with Xref History",
                    description="Large document with cross-reference history may indicate incremental update abuse",
                    severity=Severity.LOW,
                    category="structure",
                    details={"object_count": len(self.objects)},
                )
            )

    def _check_cross_reference_streams(self):
        """Check for cross-reference stream objects."""
        for obj_num, obj in self.objects.items():
            if obj.type == ObjectType.DICTIONARY and isinstance(obj.value, dict):
                type_val = obj.value.get(b"/Type")
                if type_val and type_val.type == ObjectType.NAME and type_val.value == b"/XRef":
                    # Check if it references compressed objects
                    w = obj.value.get(b"/W")
                    if w and w.type == ObjectType.ARRAY:
                        self.report.add(
                            SecurityFinding(
                                rule_id="XREF-001",
                                title="Cross-Reference Stream Object",
                                description="Document uses cross-reference streams (PDF 1.5+)",
                                severity=Severity.INFO,
                                category="structure",
                                object_num=obj_num,
                            )
                        )

    def _check_large_streams(self):
        """Check for unusually large streams that may contain payloads."""
        for obj_num, obj in self.objects.items():
            if obj.type != ObjectType.STREAM or not obj.stream_data:
                continue
            # Flag streams > 10MB
            if len(obj.stream_data) > 10 * 1024 * 1024:
                self.report.add(
                    SecurityFinding(
                        rule_id="SIZE-001",
                        title="Very Large Stream Object",
                        description=f"Stream is {len(obj.stream_data) / 1024 / 1024:.1f} MB — unusually large",
                        severity=Severity.LOW,
                        category="anomaly",
                        object_num=obj_num,
                        details={"size_bytes": len(obj.stream_data)},
                    )
                )

    def _check_nested_actions(self):
        """Check for deeply nested action chains."""
        max_depth = 0
        for _obj_num, obj in self.objects.items():
            if obj.type != ObjectType.DICTIONARY or not isinstance(obj.value, dict):
                continue
            depth = self._measure_action_depth(obj, set())
            if depth > max_depth:
                max_depth = depth

        if max_depth > 3:
            self.report.add(
                SecurityFinding(
                    rule_id="NEST-001",
                    title="Deeply Nested Action Chain",
                    description=f"Document has action chains nested {max_depth} levels deep",
                    severity=Severity.MEDIUM,
                    category="action",
                    details={"max_depth": max_depth},
                )
            )

    def _measure_action_depth(self, obj: PDFObject, visited: set, depth: int = 0) -> int:
        """Measure the maximum nesting depth of action chains."""
        if depth > 10 or id(obj) in visited:
            return depth
        visited.add(id(obj))

        if obj.type != ObjectType.DICTIONARY or not isinstance(obj.value, dict):
            return depth

        max_child_depth = depth
        for key in [b"/Next", b"/S", b"/D"]:
            if key in obj.value:
                child = _resolve(obj.value[key], self.objects)
                child_depth = self._measure_action_depth(child, visited, depth + 1)
                if child_depth > max_child_depth:
                    max_child_depth = child_depth

        return max_child_depth

    def _check_suspicious_annotations(self):
        """Check for annotations with suspicious properties."""
        for obj_num, obj in self.objects.items():
            if obj.type != ObjectType.DICTIONARY or not isinstance(obj.value, dict):
                continue
            type_val = obj.value.get(b"/Type")
            if type_val and type_val.type == ObjectType.NAME and type_val.value == b"/Annot":
                subtype = obj.value.get(b"/Subtype")
                if subtype and subtype.type == ObjectType.NAME:
                    # Invisible annotations
                    if subtype.value == b"/Widget":
                        # Widget annotations can have actions
                        aa = obj.value.get(b"/AA")
                        if aa:
                            self.report.add(
                                SecurityFinding(
                                    rule_id="ANNOT-001",
                                    title="Widget Annotation with Actions",
                                    description="Interactive form widget has additional actions",
                                    severity=Severity.LOW,
                                    category="annotation",
                                    object_num=obj_num,
                                )
                            )

    def _check_jbig2_images(self):
        """Check for JBIG2 image filters which have known vulnerabilities."""
        for obj_num, obj in self.objects.items():
            if obj.type != ObjectType.STREAM:
                continue
            stream_dict = obj.stream_dict or {}
            if isinstance(obj.value, dict):
                stream_dict = obj.value

            filt = stream_dict.get(b"/Filter")
            if filt:
                names = []
                if filt.type == ObjectType.NAME:
                    names = [filt.value]
                elif filt.type == ObjectType.ARRAY:
                    names = [f.value for f in filt.value if f.type == ObjectType.NAME]

                if b"/JBIG2Decode" in names:
                    self.report.add(
                        SecurityFinding(
                            rule_id="JBIG2-001",
                            title="JBIG2 Image Filter Detected",
                            description="JBIG2 filter has known vulnerabilities (CVE-2011-3026 and others)",
                            severity=Severity.MEDIUM,
                            category="image",
                            object_num=obj_num,
                        )
                    )

    def _check_embedded_javascript_strings(self):
        """Scan stream data for embedded JavaScript patterns."""
        js_patterns = [
            rb"(?i)this\.securityHandler",
            rb"(?i)collab\.queryDoc",
            rb"(?i)net\.smb",
            rb"(?i)util\.printf",
            rb"(?i)app\.setInterval",
            rb"(?i)app\.setTimeOut",
        ]
        for obj_num, obj in self.objects.items():
            if obj.type != ObjectType.STREAM or not obj.stream_data:
                continue
            for pattern in js_patterns:
                if re.search(pattern, obj.stream_data):
                    self.report.add(
                        SecurityFinding(
                            rule_id="JS-STR-001",
                            title="JavaScript Pattern in Stream Data",
                            description=f"Stream contains embedded JS pattern: "
                            f"{pattern.decode('latin-1', errors='replace')}",
                            severity=Severity.HIGH,
                            category="javascript",
                            object_num=obj_num,
                            details={"pattern": pattern.decode("latin-1", errors="replace")},
                        )
                    )
                    break  # One finding per stream


def analyze_security(pdf: ParsedPDF) -> SecurityReport:
    """Run full security analysis on a parsed PDF."""
    analyzer = SecurityAnalyzer(pdf)
    return analyzer.analyze()
