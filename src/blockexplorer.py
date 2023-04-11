from src.keys import *
import requests

class BlockExplorer():

    def __init__(self, chain_id):
        if chain_id == 1:
            self.host = "https://api.etherscan.io/api"
            self.api_key = ETHERSCAN_API_KEY
        elif chain_id == 137:
            self.host = "https://api.polygonscan.com/api"
            self.api_key = POLYGON_API_KEY
        elif chain_id == 56:
            self.host = "https://api.bscscan.com/api"
            self.api_key = BSC_API_KEY
        elif chain_id == 42161:
            self.host = "https://api.arbiscan.io"
            self.api_key = ARBITRUM_API_KEY
        elif chain_id == 10:
            self.host = "https://api-optimistic.etherscan.io"
            self.api_key = OPTIMISM_API_KEY
        elif chain_id == 250:
            self.host = "https://api.ftmscan.com"
            self.api_key = FANTOM_API_KEY
        elif chain_id == 43114:
            self.host = "https://api.snowtrace.io"
            self.api_key = AVALANCHE_API_KEY


    def make_token_history_query(self, address_info):
        params = {
            "module": "account",
            "action": "tokentx",
            "contractaddress": address_info[1],
            "address": address_info[0],
            "apikey": self.api_key
        }

        response = requests.get(self.host, params=params)
        values = [transfer['value'] for transfer in response.json()['result'] if transfer['from'] == str.lower(address_info[0])]
        
        return values[-5:]