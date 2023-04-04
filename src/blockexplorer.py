from src.keys import ETHERSCAN_API_KEY, POLYGON_API_KEY, BSC_API_KEY
import requests

class BlockExplorer():

    def __init__(self, chain_id):
        if chain_id == 1:
            self.host = "https://api.etherscan.io/api"
            self.api_key = ETHERSCAN_API_KEY
        elif chain_id == 137:
            self.host = "https://api.polygonscan.com"
            self.api_key = POLYGON_API_KEY
        elif chain_id == 56:
            self.host = "https://api.bscscan.com"
            self.api_key = BSC_API_KEY


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