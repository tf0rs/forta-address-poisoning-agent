from unittest.mock import MagicMock
import agent
from forta_agent import create_transaction_event, TransactionEvent
from web3_mock import *
from rules import AddressPoisoningRules
from blockexplorer_mock import BlockExplorerMock


w3 = Web3Mock()
blockexplorer = BlockExplorerMock(w3.eth.chain_id)
heuristic = AddressPoisoningRules()

class TestAddressPoisoningAgent:

    # Not sure if this is needed...
    def test_parse_logs_for_transfer_and_approval_info(self):
        agent.initialize()
        pass


    def test_transfer_to_eoa(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'to': NEW_EOA,
                'from': OLD_EOA,
                'hash': "0xpositive_zero"
            }
        })

        findings = agent.detect_address_poisoning(w3, blockexplorer, heuristic, tx_event)
        assert len(findings) == 0, "This should not have triggered a finding - not to a contract"


    def test_get_attacker_victim_lists_for_zero_value(self):
        agent.initialize()

        alert_type = "ZERO-VALUE-ADDRESS-POISONING"
        logs = [
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

        attackers, victims = agent.get_attacker_victim_lists(w3, logs, alert_type)
        assert len([a for a in attackers if "attacker" in a]) == len(attackers)
        assert len([v for v in victims if v == "victim"]) == len(victims)


    def test_get_attacker_victim_lists_for_low_value(self):
        agent.initialize()

        alert_type = "ADDRESS-POISONING-LOW-VALUE"
        logs = [
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

        attackers, victims = agent.get_attacker_victim_lists(w3, logs, alert_type)
        assert len([a for a in attackers if "attacker" in a]) == len(attackers)
        assert len([v for v in victims if v == "victim"]) == len(victims)
        assert len(attackers) - len(victims) == 1


    def test_positive_check_for_similar_transfer(self):
        agent.initialize()

        victims = ["victim"]
        logs = [
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

        check_result = agent.check_for_similar_transfer(blockexplorer, logs, victims)
        assert check_result, "This should find a matching value"
    
    
    def test_negative_check_for_similar_transfer(self):
        agent.initialize()

        victims = ["user_one"]
        logs = [
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "user_one",
                    "from": "user_two",
                    "value": "82300"
                }
            },
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "user_three",
                    "from": "user_four",
                    "value": "82300"
                }
            }
        ]

        check_result = agent.check_for_similar_transfer(blockexplorer, logs, victims)
        assert not check_result, "This should not find a matching value"


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
        
        findings = agent.detect_address_poisoning(w3, blockexplorer, heuristic, tx_event)
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

        findings = agent.detect_address_poisoning(w3, blockexplorer, heuristic, tx_event)
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

        findings = agent.detect_address_poisoning(w3, blockexplorer, heuristic, tx_event)
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
                    "to": "user_one",
                    "from": "user_two",
                    "value": "1600"
                }
            },
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "user_three",
                    "from": "user_four",
                    "value": "15000"
                }
            }
        ]

        findings = agent.detect_address_poisoning(w3, blockexplorer, heuristic, tx_event)
        assert len(findings) == 0, "This should not have triggered an alert - negative case"


    def test_is_fake_token_address_poisoning(self):
        agent.initialize()

        tx_event = MagicMock(spec=TransactionEvent)
        tx_event.transaction = {}
        tx_event.to = VERIFIED_CONTRACT
        tx_event.from_ = NEW_EOA
        tx_event.hash = "0xpositive_fake_token"
        tx_event.filter_log.return_value = [
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "attacker",
                    "from": "victim",
                    "value": "3000"
                }
            },
            {
                "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                "args": {
                    "to": "attacker",
                    "from": "victim",
                    "value": "4000"
                }
            }
        ]

        findings = agent.detect_address_poisoning(w3, blockexplorer, heuristic, tx_event)
        assert len(findings) == 1, "This should have triggered an alert - positive case"