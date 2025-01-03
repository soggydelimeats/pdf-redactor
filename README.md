# PDF PII Redactor

A Python-based GUI application for redacting Personal Identifiable Information (PII) from PDF documents. This tool provides visual black-box redaction with customizable options.

## Features

- Detects and redacts multiple types of PII:
  - Social Security Numbers (SSN)
  - Email addresses
  - Phone numbers
  - Credit card numbers
  - Dates of birth
  - IP addresses
  - US postal addresses
- Preview PII detection before redaction
- Customizable redaction color
- Progress tracking
- Maintains original PDF formatting
- Creates a new redacted PDF file (preserves original)

## Requirements

- Python 3.x
- PyMuPDF (fitz)
- tkinter (usually comes with Python)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/pdf-redactor.git
cd pdf-redactor
```

2. Install required packages:
```bash
pip install PyMuPDF
```

## Usage

1. Run the application:
```bash
python main.py
```

2. Use the interface to:
   - Select a PDF file
   - Choose which types of PII to redact
   - Preview detected PII
   - Customize redaction color (optional)
   - Process the document

The redacted PDF will be saved in the same directory as the input file with "_redacted_[timestamp]" appended to the filename.

## Supported PII Patterns

- SSN: XXX-XX-XXXX
- Email: standard email format
- Phone: (XXX) XXX-XXXX, XXX-XXX-XXXX, etc.
- Credit Card: XXXX-XXXX-XXXX-XXXX
- Date of Birth: MM/DD/YYYY, MM-DD-YYYY
- IP Address: XXX.XXX.XXX.XXX
- US Address: Street, City, State ZIP

## Security Note

While this tool attempts to identify and redact PII, it's recommended to manually verify the redacted document before sharing sensitive information.

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 
