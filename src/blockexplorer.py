from src.keys import *
import requests
import logging
import json

# Bound outbound block explorer calls so a slow/unresponsive API cannot hang the agent.
REQUEST_TIMEOUT_SECONDS = 15

CHAIN_EXPLORER_CONFIG = {
    1:     ("https://api.etherscan.io/api",            ETHERSCAN_API_KEY),
    137:   ("https://api.polygonscan.com/api",          POLYGON_API_KEY),
    56:    ("https://api.bscscan.com/api",              BSC_API_KEY),
    42161: ("https://api.arbiscan.io/api",              ARBITRUM_API_KEY),
    10:    ("https://api-optimistic.etherscan.io/api",  OPTIMISM_API_KEY),
    250:   ("https://api.ftmscan.com/api",              FANTOM_API_KEY),
    43114: ("https://api.snowtrace.io/api",             AVALANCHE_API_KEY),
}



class BlockExplorer():

    def __init__(self, chain_id):
        config = CHAIN_EXPLORER_CONFIG.get(chain_id)
        if config is None:
            logging.warning(f"Unsupported chain_id {chain_id} for block explorer; API queries will be unavailable")
            self.host = None
            self.api_key = None
        else:
            self.host, self.api_key = config


    def make_token_history_query(self, address_info):
        if self.host is None or self.api_key is None:
            raise RuntimeError("Block explorer not configured for this chain")

        params = {
            "module": "account",
            "action": "tokentx",
            "contractaddress": address_info[1],
            "address": address_info[0],
            "apikey": self.api_key
        }

        response = requests.get(self.host, params=params, timeout=REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status()

        data = response.json()
        if 'result' not in data or not isinstance(data['result'], list):
            raise ValueError(f"Unexpected block explorer response: status={data.get('status')}, message={data.get('message')}")

        values = [transfer['value'] for transfer in data['result'] if transfer['from'] == str.lower(address_info[0])]
        
        return values[-5:]


    def is_verified(self, address):
        if self.host is None or self.api_key is None:
            logging.warning("Block explorer not configured; cannot verify contract")
            return False

        params = {
            "module": "contract",
            "action": "getabi",
            "address": address,
            "apikey": self.api_key
        }
        try:
            response = requests.get(self.host, params=params, timeout=REQUEST_TIMEOUT_SECONDS)
        except requests.RequestException as e:
            logging.warning(f"Failed to check if contract is verified: {e}")
            return False

        if (response.status_code == 200):
            data = json.loads(response.text)
            if data['status'] == '1':
                logging.info("Contract is verified...exiting")
                return True
        else:
            logging.warning("Unable to check if contract is verified. Etherscan returned status code " + str(response.status_code))
        logging.info("Contract is not verified")
        return False
