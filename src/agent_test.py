import agent
from forta_agent import FindingSeverity, FindingType, create_transaction_event
from web3_mock import Web3Mock, NEW_EOA, OLD_EOA
from rules_mock import AddressPoisoningRulesMock

w3 = Web3Mock()
heuristic = AddressPoisoningRulesMock()


class TestAddressPoisoningAgent:

    def test_transfer_to_eoa(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'to': NEW_EOA,
                'from': OLD_EOA,
                'hash': "0x8fc91a50a2614d323864655c2473ec19e58cb356a9f1d391888c472476c749f7"
            },
            'block': {
                'number': 1
            },
            'receipt': {
                'logs': []
            }
        })

        findings = agent.detect_address_poisoning(w3, tx_event)
        assert len(findings) == 0, "This should not have triggered a finding - not to a contract"
