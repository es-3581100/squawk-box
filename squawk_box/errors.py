class LedgerError(RuntimeError):
    """Base ledger failure."""


class IntakeRejected(LedgerError):
    """Submission is not eligible for canonical append."""


class ReplayBlocked(LedgerError):
    """Canonical history cannot be replayed safely."""
