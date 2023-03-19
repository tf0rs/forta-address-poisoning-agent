from forta_agent import get_json_rpc_url, Web3
from src.findings import AddressPoisoningFinding
from src.rules import AddressPoisoningRules
from src.constants import TRANSFER_EVENT_ABI, STABLECOIN_CONTRACTS
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
PHISHING_CONTRACTS = set()


def initialize():
    """
    global variables for anomaly score initialized here, also tracking known phishing addresses improve efficiency.
    """
    global DENOMINATOR_COUNT
    DENOMINATOR_COUNT = 0

    global ALERT_COUNT
    ALERT_COUNT = 0

    global PHISHING_CONTRACTS
    PHISHING_CONTRACTS = set()


def parse_logs_for_transfer_info(transaction_event, chain_id):
    transfer_logs = []
    for contract in STABLECOIN_CONTRACTS[chain_id]:
        try:
            token_transfer_logs = transaction_event.filter_log(TRANSFER_EVENT_ABI, contract)
            if len(token_transfer_logs) > 0:
                for log in token_transfer_logs:
                    transfer_logs.append(log)
        except Exception as e:
            logging.warning(f"Failed to decode logs: {e}")
    transfer_log_args = []
    for log in transfer_logs:
        transfer_log_args.append(log['args'])
    return transfer_log_args


def get_attacker_victim_lists(w3, decoded_logs):
    attackers = []
    victims = []
    for log in decoded_logs:
        from_tx_count = w3.eth.get_transaction_count(log['from'])
        to_tx_count = w3.eth.get_transaction_count(log['to'])
        if from_tx_count > to_tx_count:
            attackers.append(log['to'])
            victims.append(log['from'])
        else:
            attackers.append(log['from'])
            victims.append(log['to'])
    return attackers, victims


def detect_address_poisoning(w3, heuristic, transaction_event):
    """
    PLACEHOLDER - INSERT HEURISTIC DESCRIPTION
    :return: detect_address_poisoning: list(Finding)
    """
    global DENOMINATOR_COUNT
    global ALERT_COUNT
    global PHISHING_CONTRACTS

    findings = []
    chain_id = w3.eth.chain_id
    logs = w3.eth.get_transaction_receipt(transaction_event.hash)['logs']

    if (heuristic.have_addresses_been_detected(transaction_event, PHISHING_CONTRACTS) 
    and heuristic.is_contract(w3, transaction_event.to)):
        logging.info(f"Tx is from previously detected addresses...")
        DENOMINATOR_COUNT += 1
        ALERT_COUNT += 1
        score = (1.0 * ALERT_COUNT) / DENOMINATOR_COUNT
        log_length = len(logs)
        decoded_logs = parse_logs_for_transfer_info(transaction_event, chain_id)
        attackers, victims = get_attacker_victim_lists(w3, decoded_logs)
        findings.append(AddressPoisoningFinding.create_finding(transaction_event, score, log_length, attackers, victims))
        return findings

    elif heuristic.is_contract(w3, transaction_event.to):
        DENOMINATOR_COUNT += 1
        if chain_id == 137:
            logs = logs[:-1]
        log_length = len(logs)
        if (log_length >= 3 # The lowest example observed is 9 as of Feb 2023
        and heuristic.are_all_logs_stablecoins(logs, chain_id) >= 0.6 # Most examples are solely stablecoins
        and heuristic.are_all_logs_transfers_or_approvals(logs) # A proxy for transferFrom calls
        and heuristic.is_zero_value_tx(logs)): # All logs should be transfer events for zero tokens
            logging.info(f"Detected phishing transaction from addresses: {[transaction_event.from_, transaction_event.to]}")
            ALERT_COUNT += 1
            PHISHING_CONTRACTS.update([transaction_event.to])
            score = (1.0 * ALERT_COUNT) / DENOMINATOR_COUNT
            decoded_logs = parse_logs_for_transfer_info(transaction_event, chain_id)
            attackers, victims = get_attacker_victim_lists(w3, decoded_logs)
            logging.info(f"Attackers: {attackers}")
            logging.info(f"Victims: {victims}")
            findings.append(AddressPoisoningFinding.create_finding(transaction_event, score, log_length, attackers, victims))
    logging.info(f"Phishing contracts: {list(PHISHING_CONTRACTS)}")
    return findings


def provide_handle_transaction(w3, heuristic):
    def handle_transaction(transaction_event):
        return detect_address_poisoning(w3, heuristic, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3, heuristic)


def handle_transaction(transaction_event):
    return real_handle_transaction(transaction_event)
