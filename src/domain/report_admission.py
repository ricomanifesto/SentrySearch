"""A bounded report-creation budget, shared by API processes through storage."""

REPORT_CREATION_WINDOW_SECONDS = 3600
REPORT_CREATIONS_PER_WINDOW = 6
MAX_GENERATING_REPORTS_PER_USER = 2
ADMISSION_PRUNE_BATCH = 100


class ReportAdmissionLimitError(Exception):
    def __init__(self, *, retry_after: int):
        super().__init__("Report creation limit reached")
        self.retry_after = max(1, retry_after)
