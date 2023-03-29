from unittest.mock import MagicMock
import agent
from forta_agent import FindingSeverity, FindingType, create_transaction_event, TransactionEvent
from web3_mock import *
from rules import AddressPoisoningRules
from etherscan_mock import EtherscanMock


w3 = Web3Mock()
etherscan = EtherscanMock()
heuristic = AddressPoisoningRules()

class TestAddressPoisoningAgent:

    def test_transfer_to_eoa(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'to': NEW_EOA,
                'from': OLD_EOA,
                'hash': "0xpositive_zero"
            }
        })

        findings = agent.detect_address_poisoning(w3, etherscan, heuristic, tx_event)
        assert len(findings) == 0, "This should not have triggered a finding - not to a contract"


    def test_parse_logs_for_transfer_and_approval_info(self):
        pass


    def test_get_attacker_victim_lists(self):
        pass


    def test_check_for_similar_transfer(self):
        pass


    def test_is_zero_value_address_poisoning(self):
        agent.initialize()

        tx_event = MagicMock(spec=TransactionEvent)
        tx_event.transaction = {}
        tx_event.to = VERIFIED_CONTRACT
        tx_event.from_ = NEW_EOA
        tx_event.hash = "0xpositive_zero"
        tx_event.filter_log.return_value = [
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "attacker",
                    "from": "victim",
                    "value": "0"
                }
            },
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "attacker",
                    "from": "victim",
                    "value": "0"
                }
            }
        ]
        
        findings = agent.detect_address_poisoning(w3, etherscan, heuristic, tx_event)
        assert len(findings) == 1, "This should have triggered an alert - positive case"
        assert findings[0].alert_id == "ADDRESS-POISONING-ZERO-VALUE"


    def test_is_not_zero_value_address_poisoning(self):
        agent.initialize()

        tx_event = MagicMock(spec=TransactionEvent)
        tx_event.transaction = {}
        tx_event.to = VERIFIED_CONTRACT
        tx_event.from_ = NEW_EOA
        tx_event.hash = "0xnegative_zero"
        tx_event.filter_log.return_value = [
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "attacker",
                    "from": "victim",
                    "value": "0"
                }
            },
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "attacker",
                    "from": "victim",
                    "value": "0"
                }
            }
        ]

        findings = agent.detect_address_poisoning(w3, etherscan, heuristic, tx_event)
        assert len(findings) == 0, "This should not have triggered an alert - negative case"


    def test_is_low_value_address_poisoning(self):
        agent.initialize()

        tx_event = MagicMock(spec=TransactionEvent)
        tx_event.transaction = {}
        tx_event.to = VERIFIED_CONTRACT
        tx_event.from_ = NEW_EOA
        tx_event.hash = "0xpositive_low"
        tx_event.filter_log.return_value = [
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "attacker",
                    "from": "attacker_contract",
                    "value": "82300"
                }
            },
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "victim",
                    "from": "attacker",
                    "value": "82300"
                }
            }
        ]

        findings = agent.detect_address_poisoning(w3, etherscan, heuristic, tx_event)
        assert len(findings) == 1
        assert findings[0].alert_id == "ADDRESS-POISONING-LOW-VALUE"

    
    def test_is_not_low_value_address_poisoning(self):
        agent.initialize()

        tx_event = MagicMock(spec=TransactionEvent)
        tx_event.transaction = {}
        tx_event.to = VERIFIED_CONTRACT
        tx_event.from_ = NEW_EOA
        tx_event.hash = "0xnegative_low"
        tx_event.filter_log.return_value = [
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "user_a",
                    "from": "user_contract",
                    "value": "1600"
                }
            },
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "user_c",
                    "from": "user_b",
                    "value": "15000"
                }
            }
        ]

        findings = agent.detect_address_poisoning(w3, etherscan, heuristic, tx_event)
        assert len(findings) == 0, "This should not have triggered an alert - negative case"