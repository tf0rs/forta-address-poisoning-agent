from web3_mock import *
from rules import AddressPoisoningRules
from forta_agent import create_transaction_event

w3 = Web3Mock()
heuristic = AddressPoisoningRules()


class TestAddressPoisoningRules:

    def test_is_contract_contract(self):
        assert heuristic.is_contract(w3, VERIFIED_CONTRACT) 


    def test_is_contract_eoa(self):
        assert heuristic.is_contract(w3, NEW_EOA) is False 

    
    def test_have_addresses_been_detected_positive(self):
        known_phishing_addresses = set([NEW_EOA, VERIFIED_CONTRACT])

        positive_case = create_transaction_event({
            'transaction': {
                'to': NEW_EOA,
                'from': VERIFIED_CONTRACT
            }
        })
        assert heuristic.have_addresses_been_detected(positive_case, known_phishing_addresses) 


    def test_have_addresses_been_detected_negative(self):
        known_phishing_addresses = set([NEW_EOA, VERIFIED_CONTRACT])

        negative_case = create_transaction_event({
            'transaction': {
                'to': OLD_EOA,
                'from': VERIFIED_CONTRACT
            }
        })
        assert heuristic.have_addresses_been_detected(negative_case, known_phishing_addresses) is False 


    def test_are_all_logs_stablecoins_positive(self):
        assert heuristic.are_all_logs_stablecoins(MOCK_TX_HASH_LOGS_MAPPING['0xpositive_zero']['logs'], w3.eth.chain_id) >= 0.8 


    def test_are_all_logs_stablecoins_negative(self):
        assert (heuristic.are_all_logs_stablecoins(MOCK_TX_HASH_LOGS_MAPPING['0xnegative_zero']['logs'], w3.eth.chain_id) >= 0.8) is False 


    def test_are_all_logs_transfers_positive(self):
        assert heuristic.are_all_logs_transfers_or_approvals(MOCK_TX_HASH_LOGS_MAPPING['0xpositive_zero']['logs']) is True


    def test_are_all_logs_transfers_negative(self):
        assert heuristic.are_all_logs_transfers_or_approvals(MOCK_TX_HASH_LOGS_MAPPING['0xnegative_zero']['logs']) is False


    def test_is_zero_value_tx_positive(self):
        assert heuristic.is_zero_value_tx(MOCK_TX_HASH_LOGS_MAPPING['0xpositive_zero']['logs']) is True


    def test_is_zero_value_tx_negative(self):
        assert heuristic.is_zero_value_tx(MOCK_TX_HASH_LOGS_MAPPING['0xnegative_zero']['logs']) is False