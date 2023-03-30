import requests

class EtherscanMock():

    def __init__(self):
        self.key = ""
        self.endpoint = ""

    def make_etherscan_token_history_query(self, address_info):
        if address_info[0] == "victim":
            return [0, 10000, 5000, 0, 823400]
        else:
            return [0, 0, 0, 0, 0]