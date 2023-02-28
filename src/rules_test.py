from web3_mock import *
from rules import AddressPoisoningRules
from forta_agent import create_transaction_event

w3 = Web3Mock()
heuristic = AddressPoisoningRules()


class TestAddressPoisoningRules:

    def test_is_contract_contract(self):
        assert heuristic.is_contract(w3, VERIFIED_CONTRACT) # This should be identified as a contract


    def test_is_contract_eoa(self):
        assert heuristic.is_contract(w3, NEW_EOA) is False # This should not be identified as a contract

    
    def test_have_addresses_been_detected_positive(self):
        known_phishing_addresses = set([NEW_EOA, VERIFIED_CONTRACT])

        positive_case = create_transaction_event({
            'transaction': {
                'to': NEW_EOA,
                'from': VERIFIED_CONTRACT
            }
        })

        assert heuristic.have_addresses_been_detected(positive_case, known_phishing_addresses) # These addresses should be known.

    def test_have_addresses_been_detected_negative(self):
        known_phishing_addresses = set([NEW_EOA, VERIFIED_CONTRACT])

        negative_case = create_transaction_event({
            'transaction': {
                'to': OLD_EOA,
                'from': VERIFIED_CONTRACT
            }
        })

        assert heuristic.have_addresses_been_detected(negative_case, known_phishing_addresses) is False # These addresses should not be known.


    def test_get_length_of_logs_positive(self):
        assert heuristic.get_length_of_logs(w3, '0xpositive') >= 5


    def test_get_length_of_logs_negative(self):
        assert heuristic.get_length_of_logs(w3, '0xnegative') < 5


    def test_are_all_logs_stablecoins_positive(self):
        assert heuristic.are_all_logs_stablecoins(w3, '0xpositive', w3.eth.chain_id) >= 0.8


    def test_are_all_logs_stablecoins_negative(self):
        assert heuristic.are_all_logs_stablecoins(w3, '0xnegative', w3.eth.chain_id) < 0.8
