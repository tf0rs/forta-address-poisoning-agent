from forta_agent import get_json_rpc_url, Web3
from src.constants import STABLECOIN_CONTRACTS, STABLECOIN_TICKERS
from src.findings import AddressPoisoningFinding
from src.rules import AddressPoisoningRules
import logging
import sys

# Initialize web3
web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
heuristic = AddressPoisoningRules()

# Logging set up.
root = logging.getLogger()
root.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

# Anomaly score variables
DENOMINATOR_COUNT = 0
ALERT_COUNT = 0
PHISHING_ADDRESSES = set()


def initialize():
    """
    global variables for anomaly score initialized here, also tracking known phishing addresses improve efficiency.
    """
    global DENOMINATOR_COUNT
    DENOMINATOR_COUNT = 0

    global ALERT_COUNT
    ALERT_COUNT = 0

    global PHISHING_ADDRESSES
    PHISHING_ADDRESSES = set()


def detect_address_poisoning(w3, transaction_event):
    """
    PLACEHOLDER - INSERT HEURISTIC DESCRIPTION
    :return: detect_address_poisoning: list(Finding)
    """
    global DENOMINATOR_COUNT
    global ALERT_COUNT
    global PHISHING_ADDRESSES

    findings = []
    chain_id = w3.eth.chain_id

    if (heuristic.have_addresses_been_detected(transaction_event, PHISHING_ADDRESSES) 
    and heuristic.is_contract(w3, transaction_event.to)):
        logging.info(f"Tx is from previously detected addresses...")
        DENOMINATOR_COUNT += 1
        ALERT_COUNT += 1
        score = (1.0 * ALERT_COUNT) / DENOMINATOR_COUNT
        log_length = heuristic.get_length_of_logs(w3, transaction_event.hash)
        findings.append(AddressPoisoningFinding.create_finding(w3, transaction_event, score, log_length))
        logging.info(f"Global counts: {ALERT_COUNT, DENOMINATOR_COUNT}")
        logging.info(f"Phishing addresses -> {list(PHISHING_ADDRESSES)}")
        return findings
    elif heuristic.is_contract(w3, transaction_event.to):
        DENOMINATOR_COUNT += 1
        log_length = heuristic.get_length_of_logs(w3, transaction_event.hash)
        if (log_length >= 5 # The lowest example observed is 9 as of Feb 2023
        and heuristic.are_all_logs_stablecoins(w3, transaction_event.hash, chain_id) >= 0.8 # Most examples are solely stablecoins
        and heuristic.are_all_logs_transfers(w3, transaction_event.hash) # A proxy for transferFrom calls
        and heuristic.is_zero_value_tx(w3, transaction_event.hash)): # All logs should be transfer events for zero tokens
            logging.info(f"Detected phishing transaction from addresses: {[transaction_event.from_, transaction_event.to]}")
            ALERT_COUNT += 1
            PHISHING_ADDRESSES.update([transaction_event.from_, transaction_event.to])
            score = (1.0 * ALERT_COUNT) / DENOMINATOR_COUNT
            findings.append(AddressPoisoningFinding.create_finding(w3, transaction_event, score, log_length))
    logging.info(f"Global counts: {ALERT_COUNT, DENOMINATOR_COUNT}")
    logging.info(f"Phishing addresses -> {list(PHISHING_ADDRESSES)}")
    return findings


def provide_handle_transaction(w3):
    def handle_transaction(transaction_event):
        return detect_address_poisoning(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(transaction_event):
    return real_handle_transaction(transaction_event)
