from hexbytes import HexBytes
from forta_agent import Web3
from src.agent import *
from src.constants import STABLECOIN_CONTRACTS


class AddressPoisoningRules:

    def __init__(self) -> None:
        pass

    
    def is_contract(self, w3, address):
        """
        this function determines whether address is a contract
        :return: is_contract: bool
        """
        if address is None:
            return True
        code = w3.eth.get_code(Web3.toChecksumAddress(address))
        return code != HexBytes('0x')


    # This allows us to avoid re-running the heuristic, if we have previously identified both addresses.
    def have_addresses_been_detected(self, transaction_event, phishing_addresses):
        """
        check if sender and receiver have previously been identified as phishing addresses
        :return: have_addresses_been_detected: bool
        """
        if transaction_event.from_ in phishing_addresses and transaction_event.to in phishing_addresses:
            return True
        else:
            return False


    # Check length of logs.
    def get_length_of_logs(self, w3, transaction_hash):
        logs = w3.eth.get_transaction_receipt(transaction_hash)['logs']
        return len(logs)


    def are_all_logs_stablecoins(self, w3, transaction_hash):
        logs = w3.eth.get_transaction_receipt(transaction_hash)['logs']
        stablecoin_count = 0

        for log in logs:
            if log['address'] in STABLECOIN_CONTRACTS:
                stablecoin_count += 1

        return (1.0 * stablecoin_count) / len(logs)

        
    def are_all_logs_transfers(self, w3, transaction_hash):
        logs = w3.eth.get_transaction_receipt(transaction_hash)['logs']
        transfer_hash = HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")

        for log in logs:
            if log['topics'][0] != transfer_hash:
                return False
            else:
                return True


    def is_zero_value_tx(self, w3, transaction_hash):
        logs = w3.eth.get_transaction_receipt(transaction_hash)['logs']

        for log in logs:
            if log['data'] != "0x0000000000000000000000000000000000000000000000000000000000000000":
                return False
            else:
                return True