from web3_mock import *
from rules import AddressPoisoningRules
from forta_agent import create_transaction_event

w3 = Web3Mock()
heuristic = AddressPoisoningRules()


class TestAddressPoisoningRules:

    def test_is_contract(self):
        assert heuristic.is_contract(w3, VERIFIED_CONTRACT) # This should be identified as a contract
        assert heuristic.is_contract(w3, NEW_EOA) is False # This should not be identified as a contract

    
    def test_have_addresses_been_detected(self):
        known_phishing_addresses = set([NEW_EOA, VERIFIED_CONTRACT])

        positive_case = create_transaction_event({
            'transaction': {
                'to': NEW_EOA,
                'from': VERIFIED_CONTRACT
            }
        })

        negative_case = create_transaction_event({
            'transaction': {
                'to': OLD_EOA,
                'from': VERIFIED_CONTRACT
            }
        })

        assert heuristic.have_addresses_been_detected(positive_case, known_phishing_addresses) # These addresses should be known.
        assert heuristic.have_addresses_been_detected(negative_case, known_phishing_addresses) is False # These addresses should not be known.


    def test_get_length_of_logs(self):
        positive_case = create_transaction_event({
            'logs': [{},{},{},{},{},{},{},{},{},{}]
        })

        negative_case = create_transaction_event({
            'logs':[{}]
        })

        assert heuristic.get_length_of_logs(w3, positive_case) > 5 
        assert heuristic.get_length_of_logs(w3, negative_case) < 5
