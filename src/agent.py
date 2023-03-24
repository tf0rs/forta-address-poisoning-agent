from forta_agent import get_json_rpc_url, Web3
from src.findings import AddressPoisoningFinding
from src.rules import AddressPoisoningRules
from src.constants import APPROVAL_EVENT_ABI, TRANSFER_EVENT_ABI, STABLECOIN_CONTRACTS
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

# Store detected phishing contracts
ZERO_VALUE_PHISHING_CONTRACTS = set()
LOW_VALUE_PHISHING_CONTRACTS = set()
FAKE_TOKEN_PHISHING_CONTRACTS = set()


def initialize():
    """
    Global variables for anomaly score initialized here, but also tracking 
    known phishing contracts to improve efficiency.
    """
    global DENOMINATOR_COUNT
    DENOMINATOR_COUNT = 0

    global ALERT_COUNT
    ALERT_COUNT = 0

    global ZERO_VALUE_PHISHING_CONTRACTS
    ZERO_VALUE_PHISHING_CONTRACTS = set()

    global LOW_VALUE_PHISHING_CONTRACTS
    LOW_VALUE_PHISHING_CONTRACTS = set()

    global FAKE_TOKEN_PHISHING_CONTRACTS
    FAKE_TOKEN_PHISHING_CONTRACTS = set()


def parse_logs_for_transfer_and_approval_info(transaction_event, chain_id):
    transfer_logs = []

    for contract in STABLECOIN_CONTRACTS[chain_id]:
        try:
            token_transfer_logs = transaction_event.filter_log(TRANSFER_EVENT_ABI, contract)
            if len(token_transfer_logs) > 0:
                for log in token_transfer_logs:
                    transfer_logs.append(log)
        except Exception as e:
            logging.warning(f"Failed to decode transfer logs: {e}")
    
    transfer_log_args = [log['args'] for log in transfer_logs]

    return transfer_log_args


def get_attacker_victim_lists(w3, decoded_logs, alert_type):

    if alert_type == "ZERO-VALUE-ADDRESS-POISONING":
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
    elif alert_type == "ADDRESS-POISONING-LOW-VALUE":
        senders = [log['from'] for log in decoded_logs]
        receivers = [log['to'] for log in decoded_logs]
        attackers = senders
        victims = [x for x in receivers if x not in senders]
    elif alert_type == "ADDRESS-POISONING-FAKE-TOKEN":
        """PLACEHOLDER"""
        pass

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

    ALERT_TYPE = ""

    # Check if transaction is calling a previously detected phishing contract
    if heuristic.have_addresses_been_detected(transaction_event, ZERO_VALUE_PHISHING_CONTRACTS):
        logging.info(f"Tx is from known phishing contract: {transaction_event.to}")
        DENOMINATOR_COUNT += 1
        ALERT_COUNT += 1
        score = (1.0 * ALERT_COUNT) / DENOMINATOR_COUNT
        log_length = len(logs)
        transfer_logs = parse_logs_for_transfer_and_approval_info(transaction_event, chain_id)
        attackers, victims = get_attacker_victim_lists(w3, transfer_logs)
        findings.append(AddressPoisoningFinding.create_finding(transaction_event, score, log_length, attackers, victims))
        return findings

    elif heuristic.is_contract(w3, transaction_event.to):
        DENOMINATOR_COUNT += 1
        if chain_id == 137:
            logs = logs[:-1]
        log_length = len(logs)

        # Zero value address poisoning conditions...
        if (log_length >= 3 
        and heuristic.are_all_logs_stablecoins(logs, chain_id) >= 0.6 
        and heuristic.are_all_logs_transfers_or_approvals(logs) 
        and heuristic.is_zero_value_tx(logs)): 
            logging.info(f"Detected phishing transaction from addresses: {[transaction_event.from_, transaction_event.to]}")
            ALERT_TYPE = "ADDRESS-POISONING-ZERO-VALUE"
            ZERO_VALUE_PHISHING_CONTRACTS.update([transaction_event.to])

        # Low value address poisoning conditions...
        elif (log_length >= 10
        and heuristic.are_all_logs_stablecoins(logs, chain_id) >= 0.9
        and heuristic.are_all_logs_transfers_or_approvals(logs)
        and heuristic.is_data_field_repeated(logs)):
            logging.info(f"Detected phishing transaction from addresses: {[transaction_event.from_, transaction_event.to]}")
            ALERT_TYPE = "ADDRESS-POISONING-LOW-VALUE"
            LOW_VALUE_PHISHING_CONTRACTS.update([transaction_event.to])
        """
        ELIF -> PLACEHOLDER FOR FAKE TOKEN CONDITIONS
        """

    if ALERT_TYPE != "":
        ALERT_COUNT += 1
        score = (1.0 * ALERT_COUNT) / DENOMINATOR_COUNT
        transfer_logs = parse_logs_for_transfer_and_approval_info(transaction_event, chain_id)
        attackers, victims = get_attacker_victim_lists(w3, transfer_logs, ALERT_TYPE)
        findings.append(AddressPoisoningFinding.create_finding(transaction_event, score, log_length, attackers, victims, ALERT_TYPE))

    return findings


def provide_handle_transaction(w3, heuristic):
    def handle_transaction(transaction_event):
        return detect_address_poisoning(w3, heuristic, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3, heuristic)


def handle_transaction(transaction_event):
    return real_handle_transaction(transaction_event)
