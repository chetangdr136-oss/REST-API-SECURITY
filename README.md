# REST API Security Assessment Tool

A Python-based educational tool for assessing common REST API security weaknesses on systems you own or have explicit permission to test.

## Features
- HTTP security-header review
- CORS configuration review
- Authentication enforcement check (compares an unauthenticated request with an optional authenticated request)
- Basic input-validation probe using a harmless unexpected input
- Basic rate-limit observation using a small, configurable request burst
- Risk-rated findings and downloadable PDF report
- Included intentionally vulnerable demo API for a safe classroom demonstration

## Project structure
```text
REST_API_Security_Assessment/
├── app.py                 # Streamlit user interface
├── scanner.py             # Assessment engine
├── demo_api.py            # Local demonstration API
├── report.py              # PDF report generator
├── requirements.txt
├── README.md
└── docs/
    ├── PROJECT_REPORT.md
    └── VIVA_GUIDE.md
```

## 1. Setup
Use Python 3.10 or newer.

### Windows
```powershell
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### macOS / Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 2. Start the safe demo API
Open a terminal in the project folder:
```bash
python demo_api.py
```
It listens on `http://127.0.0.1:5001`.

Demo endpoints:
- `GET /` — API information
- `GET /api/public` — public endpoint
- `GET /api/profile` — intentionally exposed profile endpoint (demo weakness)
- `GET /api/search?q=hello` — search endpoint
- `GET /health` — health check

The demo API is intentionally insecure for learning. Do not expose it to the internet.

## 3. Start the assessment dashboard
Open a second terminal:
```bash
streamlit run app.py
```
Open the local address printed by Streamlit (usually `http://localhost:8501`).

Enter `http://127.0.0.1:5001` and click **Run assessment**. The app will show findings and offer a PDF report.

## 4. Optional authentication comparison
The dashboard includes an optional Bearer token field. For an API that expects a bearer token, enter a test token you are authorized to use. The tool compares the response with and without that token; it does not attempt to guess credentials.

## 5. CLI use
```bash
python scanner.py http://127.0.0.1:5001
```
Optional:
```bash
python scanner.py http://127.0.0.1:5001 --token YOUR_TEST_TOKEN
```

## Assessment scope and limitations
This is a learning-oriented baseline checker, not a replacement for a professional penetration test. It does not prove that an API is secure or insecure in every case. Authorization testing requires a known test account and endpoint-specific expected permissions. SQL injection is not actively exploited; this tool intentionally avoids destructive payloads. Rate-limit testing is a small observation, not a stress test.

## Responsible use
Only assess APIs you own or have explicit written permission to test. Keep the demo API bound to localhost. Do not use this tool against public targets without authorization.
