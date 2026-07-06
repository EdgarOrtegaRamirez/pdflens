# PDFLens

PDF Analysis & Security Toolkit — a CLI tool and Python library for deeply analyzing PDF documents.

## Features

- **PDF Parser**: Hand-written binary parser that reads PDF structure without external dependencies
- **Metadata Extraction**: Title, author, creation date, PDF version, page count, fonts, images
- **Security Analysis**: 15+ detection rules for JavaScript, launch actions, URI actions, embedded files, obfuscation, and more
- **Structure Analysis**: Page tree, font inventory, image catalog, annotation count, object type distribution
- **Multiple Output Formats**: Text, JSON, Markdown reports
- **CI/CD Integration**: Exit codes indicate risk level for pipeline integration

## Quick Start

```bash
# Install
pip install pdflens

# Full analysis
pdflens analyze document.pdf

# Security check only
pdflens security document.pdf

# Quick check (exit code = risk level)
pdflens check document.pdf

# Get metadata
pdflens meta document.pdf

# Export as JSON
pdflens analyze document.pdf -f json -o report.json
```

## Commands

| Command | Description |
|---------|-------------|
| `pdflens analyze` | Full analysis (metadata + security + structure) |
| `pdflens meta` | Extract document metadata |
| `pdflens security` | Security threat analysis |
| `pdflens structure` | Document structure analysis |
| `pdflens check` | Quick security check with exit codes |

## Security Detection Rules

| Rule | Description | Severity |
|------|-------------|----------|
| JS-001 | JavaScript embedded in PDF | HIGH/CRITICAL |
| JS-002 | Additional Actions dictionary | MEDIUM |
| LAUNCH-001 | Launch action (executes programs) | CRITICAL |
| LAUNCH-002 | Platform-specific launch target | CRITICAL |
| URI-001 | URI action (external resource) | MEDIUM/HIGH |
| EMBED-001/002 | Embedded files | MEDIUM |
| ACTION-001 | Automatic action on open | MEDIUM/HIGH |
| FORM-001/002 | AcroForm / XFA detection | LOW/HIGH |
| STREAM-001/002 | Suspicious stream filters | HIGH/CRITICAL |
| ENTROPY-001 | High-entropy (obfuscated) streams | LOW |
| OBFUSC-001 | Obfuscated name objects | MEDIUM |
| JBIG2-001 | JBIG2 filter (known vulnerabilities) | MEDIUM |
| JS-STR-001 | JavaScript patterns in stream data | HIGH |

## Risk Levels

| Level | Score Range | Exit Code |
|-------|-------------|-----------|
| SAFE | 0 | 0 |
| LOW | 1-5 | 1 |
| MEDIUM | 6-15 | 2 |
| HIGH | 16-30 | 3 |
| CRITICAL | 31+ | 4 |

## Python API

```python
from pdflens import parse_pdf_file, extract_metadata, analyze_security, analyze_structure

pdf = parse_pdf_file("document.pdf")

metadata = extract_metadata(pdf)
security = analyze_security(pdf)
structure = analyze_structure(pdf)

print(f"Pages: {metadata.page_count}")
print(f"Risk: {security.summary()['risk_level']}")
print(f"Fonts: {structure.total_font_count}")
```

## Architecture

```
pdflens/
├── pdf_parser.py    # Hand-written PDF binary parser (objects, xref, streams)
├── metadata.py      # Metadata extraction from info dictionary
├── security.py      # 15+ rule security analysis engine
├── structure.py     # Page tree, font, image, and resource analysis
├── report.py        # Text/JSON/Markdown report generation
└── cli.py           # Click CLI with 5 commands
```

## License

MIT
