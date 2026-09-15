"""Finding data model — OWASP 2025 compliant."""
from th0rsc4n.core.owasp_mapping import get_owasp_2025


class Finding:
    """Representasi 1 temuan."""

    SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "SAFE"]

    def __init__(self, category, severity, message, mitigation="",
                 evidence="", url="", module="", owasp_code=None,
                 owasp_category=None):
        self.category = category
        self.severity = severity.upper()
        self.message = message
        self.mitigation = mitigation
        self.evidence = evidence
        self.url = url
        self.module = module

        # OWASP 2025 mapping
        if owasp_code and owasp_category:
            self.owasp_2025_code = owasp_code
            self.owasp_2025_category = owasp_category
        else:
            code, cat = get_owasp_2025(module or category)
            self.owasp_2025_code = code
            self.owasp_2025_category = cat

    def to_dict(self):
        return {
            "category": self.category,
            "severity": self.severity,
            "message": self.message,
            "mitigation": self.mitigation,
            "evidence": self.evidence,
            "url": self.url,
            "module": self.module,
            "owasp_2025_code": self.owasp_2025_code,
            "owasp_2025_category": self.owasp_2025_category,
        }

    def __repr__(self):
        return f"<Finding [{self.severity}] [{self.owasp_2025_code}] {self.message[:50]}>"
