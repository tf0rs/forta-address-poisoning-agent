from forta_agent import Finding, FindingSeverity, FindingType, EntityType

    
class AddressPoisoningFinding:

    def create_finding(transaction_event, anomaly_score, log_length, attackers, victims, alert_type):
        finding = Finding(
                    {
                        "name": "Possible Address Poisoning",
                        "description": "Possible address poisoning transaction",
                        "alert_id": alert_type,
                        "type": FindingType.Suspicious,
                        "severity": FindingSeverity.Medium,
                        "metadata": {
                            "phishing_eoa": transaction_event.from_,
                            "phishing_contract": transaction_event.to,
                            "logs_length": log_length,
                            "attacker_addresses": attackers,
                            "victim_addresses": victims,
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
                                "entity": transaction_event.hash,
                                "label": "address-poisoning",
                                "confidence": 0.7
                            },
                        ]
                    }  
                )

        return finding