from __future__ import annotations

import argparse
import logging
import math
import time
from collections.abc import Callable

from sqlalchemy.orm import Session

from app.db.session import get_session_factory
from app.integrations.smtp_transport import EmailDeliveryError
from app.models.email_outbox import EmailOutbox
from app.services.email_outbox import (
    claim_email_jobs,
    mark_email_job_delivered,
    mark_email_job_failed,
)
from app.services.email_outbox_delivery import deliver_email_job

logger = logging.getLogger(__name__)

CLAIM_LEASE_SECONDS = 300
MAX_ATTEMPTS = 8


def process_one_email_job(
    session_factory: Callable[[], Session],
    *,
    deliverer: Callable[[EmailOutbox], None] | None = None,
) -> bool:
    """Claim and process at most one email job."""
    with session_factory() as session:
        jobs = claim_email_jobs(
            session,
            batch_size=1,
            lease_seconds=CLAIM_LEASE_SECONDS,
            max_attempts=MAX_ATTEMPTS,
        )

        if not jobs:
            # Commit even when nothing was claimed: claim_email_jobs() may have
            # marked crash-exhausted jobs as failed, and that must be persisted.
            session.commit()
            return False

        claimed_job = jobs[0]
        job_id = claimed_job.id
        lock_token = claimed_job.lock_token

        if lock_token is None:
            raise RuntimeError("Claimed email job has no lock token.")

        delivery_job = EmailOutbox(
            id=claimed_job.id,
            event_type=claimed_job.event_type,
            encrypted_payload=claimed_job.encrypted_payload,
        )

        session.commit()

    error_code: str | None = None
    transient = False

    try:
        (deliverer or deliver_email_job)(delivery_job)
    except EmailDeliveryError as exc:
        error_code = exc.code
        transient = exc.transient
    except Exception:
        error_code = "email_delivery_internal_error"
        transient = True
        logger.error("Unexpected email delivery failure: job_id=%s.", job_id)

    with session_factory() as session:
        if error_code is None:
            updated = mark_email_job_delivered(
                session,
                job_id,
                lock_token,
            )
        else:
            updated = mark_email_job_failed(
                session,
                job_id,
                lock_token,
                error_code,
                transient=transient,
                max_attempts=MAX_ATTEMPTS,
            )

        session.commit()

    if not updated:
        logger.warning(
            "Email job finalization skipped; claim is no longer active: job_id=%s.",
            job_id,
        )
    elif error_code is None:
        logger.info("Email job delivered: job_id=%s.", job_id)
    else:
        logger.info(
            "Email job failure recorded: job_id=%s error_code=%s transient=%s.",
            job_id,
            error_code,
            transient,
        )

    return True


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Value must be a positive number.") from exc

    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("Value must be a positive number.")

    return parsed


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Process encrypted RelaySphere transactional email jobs."
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Process at most one available job, then exit.",
    )
    parser.add_argument(
        "--poll-interval",
        type=_positive_float,
        default=5.0,
        metavar="SECONDS",
        help="Seconds to wait when no job is available (default: 5).",
    )
    return parser


def main() -> int:
    args = build_argument_parser().parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    session_factory = get_session_factory()

    if args.once:
        process_one_email_job(session_factory)
        return 0

    logger.info("Email outbox worker started.")

    try:
        while True:
            processed = process_one_email_job(session_factory)

            if not processed:
                time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        logger.info("Email outbox worker stopped.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
