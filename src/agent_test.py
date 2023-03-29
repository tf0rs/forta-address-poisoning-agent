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

        pass