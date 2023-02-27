from hexbytes import HexBytes
from forta_agent import Web3
from src.agent import *
from src.constants import STABLECOIN_CONTRACTS


class AddressPoisoningRulesMock:

    def __init__(self) -> None:
        pass

    
    def is_contract():
        pass


    def have_addresses_been_detected(self, transaction_event, phishing_addresses):
        pass


    def get_length_of_logs(self, w3, transaction_hash):
        pass


    def are_all_logs_stablecoins(self, w3, transaction_hash):
        pass


    def are_all_logs_transfers(self, w3, transaction_hash):
        pass


    def is_zero_value_tx(self, w3, transaction_hash):
        pass