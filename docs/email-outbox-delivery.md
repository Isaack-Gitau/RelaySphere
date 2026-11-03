# Email outbox delivery guarantees

## Summary

Transactional emails are delivered **at least once**, never exactly once.
A recipient can occasionally receive the same message twice.

## Why duplicates can happen

1. **Crash after SMTP acceptance.** If a worker crashes after the SMTP server
   accepts a message but before the database records delivery, the job is
   reclaimed and sent again.
2. **Lease expiry during slow delivery.** A job is leased for 300 seconds.
   SMTP timeouts apply to each network operation, not to the whole delivery,
   so a slow server can keep a delivery running past the lease. Another
   worker may then reclaim and send the same job.
3. **Finalization after lease expiry.** Recording success or failure requires
   a matching lock token and an unexpired lease. A delivery that succeeds
   after the lease expired is not recorded and is sent again.

A retry sends the same stored payload, so duplicate verification emails carry
the same single-use token and are harmless.

## Current settings

- Claim lease: 300 seconds (`CLAIM_LEASE_SECONDS`, `app/workers/email_outbox_worker.py`).
- Maximum attempts: 8 (`MAX_ATTEMPTS`, same file).
- SMTP timeout: default 10 seconds, maximum 60, applied per blocking network
  operation (`smtp_timeout_seconds`).
- Retry backoff: exponential from 30 seconds, capped at 6 hours, with jitter.

## Lease sizing

A STARTTLS delivery makes about a dozen sequential network operations. At the
default 10-second timeout the worst case is about 120 seconds, which fits
inside the 300-second lease. A unit test enforces this relationship.

If `smtp_timeout_seconds` is raised above about 25 seconds, the worst case can
exceed the lease and the duplicate scenarios above become possible. At the
configured maximum of 60 seconds the worst case is about 720 seconds. Raise
`CLAIM_LEASE_SECONDS` together with the timeout.

A longer lease slows recovery from worker crashes: an abandoned job becomes
claimable again only after the lease expires.

## Crash handling

Every claim increments `attempt_count`. When an expired job has already used
all 8 attempts, `claim_email_jobs()` marks it `failed` with the error code
`email_delivery_attempts_exhausted` and clears its encrypted payload and lock
fields instead of reclaiming it. The worker commits this change even when no
job was claimed.

## Open decisions

- Whether finalization should accept a matching lock token after the lease expires.
- Lease renewal is not implemented.

## Operations

To inspect failed jobs, query `id`, `event_type`, `attempt_count`, and
`last_error_code` from `email_outbox` where `status = 'failed'`. Never select
`encrypted_payload`.
