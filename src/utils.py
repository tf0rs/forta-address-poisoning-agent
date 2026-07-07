import logging


ALERT_TYPES = [
    "ADDRESS-POISONING-ZERO-VALUE",
    "ADDRESS-POISONING-LOW-VALUE",
    "ADDRESS-POISONING-FAKE-TOKEN",
]


class AlertTracker:
    """Tracks anomaly scores and known phishing contracts for each alert type."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.denominator_count = 0
        self.alert_counts = {t: 0 for t in ALERT_TYPES}
        self.phishing_contracts = {t: set() for t in ALERT_TYPES}

    def increment_denominator(self):
        self.denominator_count += 1

    def record_alert(self, alert_type):
        self.alert_counts[alert_type] += 1
        return self.get_score(alert_type)

    def get_score(self, alert_type):
        return (1.0 * self.alert_counts[alert_type]) / self.denominator_count

    def add_phishing_contract(self, alert_type, contract):
        self.phishing_contracts[alert_type].add(contract)

    def check_known_contract(self, to_address):
        for alert_type in ALERT_TYPES:
            if to_address in self.phishing_contracts[alert_type]:
                return alert_type
        return ""


def get_unique_log_contracts(logs):
    """Extract the unique set of contract addresses from transaction logs."""
    return set(log['address'] for log in logs)


def log_detected_phishing(from_addr, to_addr):
    logging.info(
        f"Detected phishing transaction from EOA: {from_addr}, "
        f"and Contract: {to_addr}"
    )
