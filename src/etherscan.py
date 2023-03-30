from src.keys import ETHERSCAN_API_KEY
import requests

class Etherscan():

    def __init__(self):
        self.key = ETHERSCAN_API_KEY
        self.endpoint = "https://api.etherscan.io/api"


    def make_etherscan_token_history_query(self, address_info):
        params = {
            "module": "account",
            "action": "tokentx",
            "contractaddress": address_info[1],
            "address": address_info[0],
            "apikey": self.key
        }

        response = requests.get(self.endpoint, params=params)
        values = [transfer['value'] for transfer in response.json()['result'] if transfer['from'] == str.lower(address_info[0])]
        
        return values[-5:]