# CyberGuard AI

A digital security platform that analyzes URLs, messages, and files for threats using the VirusTotal API and local heuristic analysis.

## Features

- **URL Analysis** — checks suspicious links via VirusTotal (72+ engines)
- **Message Analysis** — detects phishing, fake urgency, and shortened links
- **File Analysis** — upload and scan with SHA-256 hash + VirusTotal
- **Scan History** — local log of recent scans (localStorage)
- **Heuristic Fallback** — offline analysis when the API is unavailable

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | HTML + CSS + JS (single-file) |
| External API | VirusTotal v3 |
| Backend (optional) | Python / Flask |

## Project Structure

```
/
├── index.html          # Full frontend app
├── cyberguard-ai/
│   ├── app.py          # Flask server
│   ├── requirements.txt
│   ├── services/
│   │   ├── url_analyzer.py
│   │   ├── message_analyzer.py
│   │   ├── file_analyzer.py
│   │   └── claude_service.py
│   └── tests/
│       ├── test_url_analyzer.py
│       └── test_message_analyzer.py
```

## Running Locally

### Frontend (open directly in browser)
```bash
open index.html
```

### Backend Flask (optional)
```bash
cd cyberguard-ai
pip install -r requirements.txt
python app.py
```

## Design

Dark editorial aesthetic: `#050505` background, `#FF4500` orange-red accent, Playfair Display + Inter typography, noise overlay, reveal animations.
