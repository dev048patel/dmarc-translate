# dmarc-translate
 
> Reads your DMARC reports and tells you, in plain English, who's faking your email — and when it's safe to block them.
 
## The problem
 
Email has no built-in way to verify who actually sent it — anyone can write any name in the "From" field, and most mail servers just deliver it anyway. A fix for this exists (called DMARC), but almost nobody finishes setting it up, because the reports it produces are a wall of raw technical data — IP addresses, pass/fail codes, no explanation — and one wrong move can accidentally block your own real email. So most domains leave it half-configured, offering zero real protection, forever.
 
## What this does
 
- Automatically pulls in DMARC reports from a dedicated mailbox
- Parses the confusing technical data (XML reports full of IPs, pass/fail codes)
- Turns it into a plain-English summary: who's sending mail as you, and whether it's really you
- Tells you exactly when it's safe to move from "monitor only" to full enforcement, without breaking your own legitimate email
## Why it matters
 
- Most domains (~69%) have no real DMARC protection today — the tooling gap, not lack of awareness, is the actual blocker
- Business email impersonation caused over $3 billion in reported US losses in 2025 alone
- Google, Yahoo, and Microsoft now require DMARC for bulk senders — this is becoming mandatory, not optional
## Status
 
This is an active work in progress, built as a two-person student project.
 
- [x] Phase 1 — Domain & DNS setup
- [ ] Phase 2 — Report ingestion pipeline (in progress)
- [ ] Phase 3 — Risk scoring logic
- [ ] Phase 4 — Plain-English explanation engine
- [ ] Phase 5 — Dashboard
## Tech stack
 
- **Python** — core logic and ingestion
- **parsedmarc** — DMARC report parsing
- **SQLite** — storage
- **FastAPI** — dashboard (planned)
## How it works (high level)
 
1. A dedicated mailbox receives DMARC reports automatically from mail providers (Google, Yahoo, Microsoft, etc.)
2. A script logs in, downloads new reports, and parses them
3. Results get stored in a simple database
4. A scoring engine flags real threats vs. false alarms
5. A dashboard shows a plain-English summary and a clear next action
## Getting started
 
```bash
git clone <repo-url>
cd dmarc-translate
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```
 
Copy `.env.example` to `.env` and fill in your mailbox credentials, then run:
 
```bash
python3 fetch_reports.py
```
 
## Built by
 
A two-person student project exploring practical, non-AI cybersecurity tooling.
 
## License
 
MIT (or update as preferred)
 
