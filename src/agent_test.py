import agent
from forta_agent import FindingSeverity, FindingType, create_transaction_event
from web3_mock import *
from rules import AddressPoisoningRules

w3 = Web3Mock()
heuristic = AddressPoisoningRules()


class TestAddressPoisoningAgent:

    def test_transfer_to_eoa(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'to': NEW_EOA,
                'from': OLD_EOA,
                'hash': "0xpositive"
            }
        })

        findings = agent.detect_address_poisoning(w3, heuristic, tx_event)
        assert len(findings) == 0, "This should not have triggered a finding - not to a contract"


    def test_is_address_poisoning(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'to': VERIFIED_CONTRACT,
                'from': NEW_EOA,
                'hash': "0xpositive"
            }
        })

        findings = agent.detect_address_poisoning(w3, heuristic, tx_event)
        assert len(findings) == 1, "This should have triggered an alert - positive case"


    def test_is_not_address_poisoning(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'to': VERIFIED_CONTRACT,
                'from': NEW_EOA,
                'hash': "0xnegative"
            }
        })

        findings = agent.detect_address_poisoning(w3, heuristic, tx_event)
        assert len(findings) == 0, "This should not have triggered an alert - negative case"