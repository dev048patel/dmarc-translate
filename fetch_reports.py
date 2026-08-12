"""
Fetch DMARC reports from an IMAP inbox, parse them with parsedmarc,
and store aggregate + forensic results in a local SQLite database.

Usage:
    python fetch_reports.py

Configuration comes entirely from .env (see .env.example).
"""

import json
import logging
import os
import sqlite3

from dotenv import load_dotenv
import parsedmarc

load_dotenv()

IMAP_HOST = os.getenv("IMAP_HOST", "imap.gmail.com")
IMAP_PORT = int(os.getenv("IMAP_PORT", "993"))
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
APP_PASSWORD = os.getenv("APP_PASSWORD")
REPORTS_FOLDER = os.getenv("REPORTS_FOLDER", "INBOX")
ARCHIVE_FOLDER = os.getenv("ARCHIVE_FOLDER", "INBOX/DMARC-Archive")
DB_PATH = os.getenv("DB_PATH", "reports.db")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS aggregate_reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id   TEXT    UNIQUE NOT NULL,
    org_name    TEXT,
    org_email   TEXT,
    begin_date  INTEGER,
    end_date    INTEGER,
    domain      TEXT,
    adkim       TEXT,
    aspf        TEXT,
    p           TEXT,
    sp          TEXT,
    pct         INTEGER,
    fetched_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS aggregate_report_records (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id       TEXT    NOT NULL REFERENCES aggregate_reports(report_id),
    source_ip       TEXT,
    message_count   INTEGER,
    disposition     TEXT,
    dkim_result     TEXT,
    spf_result      TEXT,
    header_from     TEXT,
    envelope_from   TEXT,
    dkim_auth_domain  TEXT,
    dkim_auth_result  TEXT,
    spf_auth_domain   TEXT,
    spf_auth_result   TEXT
);

CREATE TABLE IF NOT EXISTS forensic_reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    feedback_id     TEXT    UNIQUE,
    feedback_type   TEXT,
    arrival_date    TEXT,
    source_ip       TEXT,
    subject         TEXT,
    delivery_result TEXT,
    raw_json        TEXT,
    fetched_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
"""


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA)
    conn.commit()


# ---------------------------------------------------------------------------
# Storage helpers
# ---------------------------------------------------------------------------

def _store_aggregate(conn: sqlite3.Connection, report: dict) -> None:
    meta = report.get("report_metadata", {})
    policy = report.get("policy_published", {})
    report_id = meta.get("report_id")
    if not report_id:
        log.warning("Skipping aggregate report with no report_id")
        return

    try:
        conn.execute(
            """
            INSERT OR IGNORE INTO aggregate_reports
                (report_id, org_name, org_email, begin_date, end_date,
                 domain, adkim, aspf, p, sp, pct)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report_id,
                meta.get("org_name"),
                meta.get("email"),
                meta.get("begin_date"),
                meta.get("end_date"),
                policy.get("domain"),
                policy.get("adkim"),
                policy.get("aspf"),
                policy.get("p"),
                policy.get("sp"),
                policy.get("pct"),
            ),
        )

        for record in report.get("records", []):
            row = record.get("row", {})
            policy_eval = record.get("policy_evaluated", {})
            identifiers = record.get("identifiers", {})
            auth = record.get("auth_results", {})

            dkim_auths = auth.get("dkim") or []
            spf_auths = auth.get("spf") or []
            dkim_auth = dkim_auths[0] if dkim_auths else {}
            spf_auth = spf_auths[0] if spf_auths else {}

            conn.execute(
                """
                INSERT INTO aggregate_report_records
                    (report_id, source_ip, message_count, disposition,
                     dkim_result, spf_result, header_from, envelope_from,
                     dkim_auth_domain, dkim_auth_result,
                     spf_auth_domain, spf_auth_result)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report_id,
                    row.get("source_ip"),
                    row.get("count"),
                    policy_eval.get("disposition"),
                    policy_eval.get("dkim"),
                    policy_eval.get("spf"),
                    identifiers.get("header_from"),
                    identifiers.get("envelope_from"),
                    dkim_auth.get("domain"),
                    dkim_auth.get("result"),
                    spf_auth.get("domain"),
                    spf_auth.get("result"),
                ),
            )

        conn.commit()
        log.info("Stored aggregate report %s (%s)", report_id, policy.get("domain"))

    except sqlite3.Error as exc:
        log.error("DB error storing aggregate report %s: %s", report_id, exc)
        conn.rollback()


def _store_forensic(conn: sqlite3.Connection, report: dict) -> None:
    # parsedmarc uses "feedback_id" when present; fall back to arrival_date
    feedback_id = report.get("feedback_id") or report.get("arrival_date") or str(id(report))

    try:
        conn.execute(
            """
            INSERT OR IGNORE INTO forensic_reports
                (feedback_id, feedback_type, arrival_date, source_ip,
                 subject, delivery_result, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                feedback_id,
                report.get("feedback_type"),
                report.get("arrival_date"),
                report.get("source_ip"),
                report.get("subject"),
                report.get("delivery_result"),
                json.dumps(report, default=str),
            ),
        )
        conn.commit()
        log.info("Stored forensic report %s", feedback_id)

    except sqlite3.Error as exc:
        log.error("DB error storing forensic report %s: %s", feedback_id, exc)
        conn.rollback()


# ---------------------------------------------------------------------------
# Main fetch routine
# ---------------------------------------------------------------------------

def fetch_and_store() -> None:
    if not EMAIL_ADDRESS or not APP_PASSWORD:
        raise RuntimeError(
            "EMAIL_ADDRESS and APP_PASSWORD must be set in .env — see .env.example"
        )

    log.info("Connecting to %s:%s as %s", IMAP_HOST, IMAP_PORT, EMAIL_ADDRESS)
    log.info("Reading from folder: %s", REPORTS_FOLDER)

    connection = parsedmarc.IMAPConnection(
        host=IMAP_HOST,
        user=EMAIL_ADDRESS,
        password=APP_PASSWORD,
        port=IMAP_PORT,
        ssl=True,
    )

    results = parsedmarc.get_dmarc_reports_from_mailbox(
        connection=connection,
        reports_folder=REPORTS_FOLDER,
        archive_folder=ARCHIVE_FOLDER,
        delete=False,   # move to archive instead of deleting
    )

    aggregate = results.get("aggregate_reports", [])
    forensic = results.get("failure_reports", [])
    log.info(
        "Fetched %d aggregate report(s) and %d forensic report(s)",
        len(aggregate),
        len(forensic),
    )

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        init_db(conn)
        for report in aggregate:
            _store_aggregate(conn, report)
        for report in forensic:
            _store_forensic(conn, report)

    log.info("All reports stored in %s", DB_PATH)


if __name__ == "__main__":
    fetch_and_store()
