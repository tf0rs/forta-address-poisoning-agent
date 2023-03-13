from hexbytes import HexBytes
from forta_agent import Web3
from src.constants import STABLECOIN_CONTRACTS


class AddressPoisoningRules:

    @staticmethod
    def is_contract(w3, address):
        """
        this function determines whether address is a contract
        :return: is_contract: bool
        """
        if address is None:
            return True
        code = w3.eth.get_code(Web3.toChecksumAddress(address))
        return code != HexBytes('0x')


    @staticmethod
    def have_addresses_been_detected(transaction_event, phishing_addresses):
        """
        check if sender and receiver have previously been identified as phishing addresses
        :return: have_addresses_been_detected: bool
        """
        if transaction_event.to in phishing_addresses:
            return True
        else:
            return False


    @staticmethod
    def are_all_logs_stablecoins(logs, chain_id):
        stablecoin_count = 0

        if len(logs) == 0:
            return 0

        for log in logs:
            if str.lower(log['address']) in STABLECOIN_CONTRACTS[chain_id]:
                stablecoin_count += 1

        return (1.0 * stablecoin_count) / len(logs)


    @staticmethod    
    def are_all_logs_transfers_or_approvals(logs):
        accepted_hashes = [
            HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"),
            HexBytes("0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925")
        ]
        
        for log in logs:
            if log['topics'][0] not in accepted_hashes:
                print(log['topics'][0])
                return False
            else:
                continue
        return True

    
    @staticmethod
    def is_zero_value_tx(logs):

        for log in logs:
            if log['data'] != "0x0000000000000000000000000000000000000000000000000000000000000000":
                return False
            else:
                continue
        return True