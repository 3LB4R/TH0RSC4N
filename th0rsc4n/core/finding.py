class Finding:
    """Representasi 1 temuan."""
    
    SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "SAFE"]
    
    def __init__(self, category, severity, message, mitigation="", evidence="", url=""):
        self.category = category
        self.severity = severity.upper()
        self.message = message
        self.mitigation = mitigation
        self.evidence = evidence
        self.url = url
    
    def to_dict(self):
        return {
            "category": self.category,
            "severity": self.severity,
            "message": self.message,
            "mitigation": self.mitigation,
            "evidence": self.evidence,
            "url": self.url,
        }
    
    def __repr__(self):
        return f"<Finding [{self.severity}] {self.message[:50]}>"