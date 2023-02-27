from forta_agent import Finding, FindingSeverity, FindingType, EntityType

    
class AddressPoisoningFinding:    
    
    def create_finding(w3, transaction_event, anomaly_score, log_length):
        finding = Finding(
                    {
                        "name": "Possible Address Poisoning",
                        "description": f"Possible address poisoning transaction",
                        "alert_id": "ADDRESS-POISONING",
                        "type": FindingType.Suspicious,
                        "severity": FindingSeverity.Medium,
                        "metadata": {
                            "phishing_eoa": transaction_event.from_,
                            "phishing_contract": transaction_event.to,
                            "logs_length": log_length,
                            "addresses": list(transaction_event.addresses.keys()),
                            "anomaly_score": anomaly_score
                        },
                        "labels": [
                            {
                                "entityType": EntityType.Address,
                                "entity": transaction_event.from_,
                                "label": "attacker",
                                "confidence": 0.7
                            },
                            {
                                "entityType": EntityType.Address,
                                "entity": transaction_event.to,
                                "label": "attacker",
                                "confidence": 0.7
                            },
                            {
                                "entityType": EntityType.Transaction,
                                "entity": transaction_event.transaction.hash,
                                "label": "address-poisoning",
                                "confidence": 0.7
                            },
                        ]
                    }  
                )

        return finding