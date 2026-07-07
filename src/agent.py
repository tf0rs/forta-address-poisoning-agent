from forta_agent import get_json_rpc_url, Web3
from src.findings import AddressPoisoningFinding
from src.rules import AddressPoisoningRules
from src.constants import *
from src.blockexplorer import BlockExplorer
from src.utils import AlertTracker, get_unique_log_contracts, log_detected_phishing
import logging
import sys

# Initialize web3
web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
heuristic = AddressPoisoningRules()
blockexplorer = BlockExplorer(web3.eth.chain_id)

# Logging set up.
root = logging.getLogger()
root.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

tracker = AlertTracker()


def initialize():
    """
    Global variables for anomaly score initialized here, but also tracking 
    known phishing contracts to improve efficiency.
    """
    tracker.reset()


def parse_logs_for_transfer_and_approval_info(transaction_event, contracts):
    transfer_logs = []

    for contract in contracts:
        try:
            token_transfer_logs = transaction_event.filter_log(TRANSFER_EVENT_ABI, contract)
            if len(token_transfer_logs) > 0:
                for log in token_transfer_logs:
                    transfer_logs.append(log)
        except Exception as e:
            logging.warning(f"Failed to decode transfer logs: {e}")

    return transfer_logs


def get_attacker_victim_lists(w3, decoded_logs, alert_type):
    log_args = [log['args'] for log in decoded_logs]
    attackers = []
    victims = []

    if (alert_type == "ADDRESS-POISONING-ZERO-VALUE" 
    or alert_type == "ADDRESS-POISONING-FAKE-TOKEN"):
        for log in log_args:
            try:
                from_tx_count = w3.eth.get_transaction_count(log['from'])
                to_tx_count = w3.eth.get_transaction_count(log['to'])
            except Exception as e:
                logging.warning(f"Failed to get transaction count for {log['from']} or {log['to']}: {e}")
                attackers.append(log['from'])
                victims.append(log['to'])
                continue
            if from_tx_count > to_tx_count:
                attackers.append(log['to'])
                victims.append(log['from'])
            else:
                attackers.append(log['from'])
                victims.append(log['to'])
        attackers = list(set(attackers))
        victims = list(set(victims))
    elif alert_type == "ADDRESS-POISONING-LOW-VALUE":
        senders = [str.lower(log['from']) for log in log_args]
        receivers = [str.lower(log['to']) for log in log_args]
        attackers = list(set(senders))
        victims = list(set([x for x in receivers if x not in senders]))

    return attackers, victims


def check_for_similar_transfer(blockexplorer, decoded_logs, victims):

    address_token_value_data = [(log['args']['to'], log['address'], log['args']['value']) for log in decoded_logs \
            if str.lower(log['args']['to']) in victims]

    def process_entry(entry):
        try:
            transfer_history = blockexplorer.make_token_history_query(entry)
        except Exception as e:
            logging.warning(f"Failed to retrieve transaction history from blockexplorer: {e}")
            transfer_history = None

        return (transfer_history is None, str(entry[2])[:3] not in str(transfer_history) if transfer_history is not None else False)

    results = [process_entry(entry) for entry in address_token_value_data]

    failed_queries = sum(result[0] for result in results)

    # Check if most queries fail...
    if failed_queries > (len(address_token_value_data) / 2):
        logging.info(f"Failed to retrieve tx history {failed_queries} times for {len(address_token_value_data)} addresses")
        return False

    # Check if any query has the transferred value not in the values sent by the receiving address
    if any(result[1] for result in results):
        return False

    return True



def detect_address_poisoning(w3, blockexplorer, heuristic, transaction_event):
    """
    Expanded to check for zero value phishing, low value phishing, and fake token phishing
    :return: detect_address_poisoning: list(Finding)
    """
    findings = []
    chain_id = w3.eth.chain_id

    try:
        logs = w3.eth.get_transaction_receipt(transaction_event.hash)['logs']
    except Exception as e:
        logging.error(f"Failed to get transaction receipt for {transaction_event.hash}: {e}")
        return findings

    # Return alert type if previously detected, but if not return empty string
    ALERT_TYPE = tracker.check_known_contract(transaction_event.to)

    # Check if transaction is calling a previously detected phishing contract
    if ALERT_TYPE != "":
        logging.info(f"Tx is from known phishing contract: {transaction_event.to}")
        tracker.increment_denominator()
        score = tracker.record_alert(ALERT_TYPE)

        if ALERT_TYPE == "ADDRESS-POISONING-FAKE-TOKEN":
            contracts = get_unique_log_contracts(logs)
        else:
            contracts = STABLECOIN_CONTRACTS[chain_id]

        transfer_logs = parse_logs_for_transfer_and_approval_info(transaction_event, contracts)
        attackers, victims = get_attacker_victim_lists(w3, transfer_logs, ALERT_TYPE)
        findings.append(
            AddressPoisoningFinding.create_finding(transaction_event, score, len(logs), attackers, victims, ALERT_TYPE)
        )
        return findings
    
    elif (heuristic.is_contract(w3, transaction_event.to) 
    # and not blockexplorer.is_verified(transaction_event.to)
    and not heuristic.are_tokens_minted(logs)):
        tracker.increment_denominator()
        
        if chain_id == 137:
            logs = logs[:-1]
        
        log_length = len(logs)
        
        # Zero value address poisoning heuristic ->
        if (log_length >= 3 
        and heuristic.are_all_logs_stablecoins(logs, chain_id) >= 0.4 
        and heuristic.are_all_logs_transfers_or_approvals(logs) 
        and heuristic.is_zero_value_tx(logs, chain_id)): 
            log_detected_phishing(transaction_event.from_, transaction_event.to)
            ALERT_TYPE = "ADDRESS-POISONING-ZERO-VALUE"
            score = tracker.record_alert(ALERT_TYPE)
            tracker.add_phishing_contract(ALERT_TYPE, transaction_event.to)
            transfer_logs = parse_logs_for_transfer_and_approval_info(transaction_event, STABLECOIN_CONTRACTS[chain_id])
            attackers, victims = get_attacker_victim_lists(w3, transfer_logs, ALERT_TYPE)
            attackers.extend([transaction_event.from_, transaction_event.to])

        # Fake token address poisoning heuristic ->
        elif (log_length >= 5
        and heuristic.are_all_logs_transfers_or_approvals(logs)
        and heuristic.are_tokens_using_known_symbols(w3, logs, chain_id)):
            log_detected_phishing(transaction_event.from_, transaction_event.to)
            ALERT_TYPE = "ADDRESS-POISONING-FAKE-TOKEN"
            score = tracker.record_alert(ALERT_TYPE)
            tracker.add_phishing_contract(ALERT_TYPE, transaction_event.to)
            fake_contracts = get_unique_log_contracts(logs)
            transfer_logs = parse_logs_for_transfer_and_approval_info(transaction_event, fake_contracts)
            attackers, victims = get_attacker_victim_lists(w3, transfer_logs, ALERT_TYPE)
            attackers.extend([transaction_event.from_, transaction_event.to])
       
        # Low value address poisoning heuristic ->
        elif (log_length >= 10
        and heuristic.are_all_logs_stablecoins(logs, chain_id) >= 0.9
        and heuristic.are_all_logs_transfers_or_approvals(logs)
        and heuristic.is_data_field_repeated(logs)):
            logging.info(f"Possible low-value address poisoning - making additional checks...")
            PENDING_ALERT_TYPE = "ADDRESS-POISONING-LOW-VALUE"
            transfer_logs = parse_logs_for_transfer_and_approval_info(transaction_event, STABLECOIN_CONTRACTS[chain_id])
            attackers, victims = get_attacker_victim_lists(w3, transfer_logs, PENDING_ALERT_TYPE)
            if ((len(attackers) - len(victims)) == 1
            and check_for_similar_transfer(blockexplorer, transfer_logs, victims)):
                log_detected_phishing(transaction_event.from_, transaction_event.to)
                ALERT_TYPE = PENDING_ALERT_TYPE
                score = tracker.record_alert(ALERT_TYPE)
                tracker.add_phishing_contract(ALERT_TYPE, transaction_event.to)
                attackers.append(transaction_event.from_)

    if ALERT_TYPE != "":
        logging.info("Appending finding...")
        try:
            findings.append(
                AddressPoisoningFinding.create_finding(transaction_event, score, log_length, attackers, victims, ALERT_TYPE)
            )
        except Exception as e:
            logging.error(f"Failed to create finding for {transaction_event.hash}: {e}")

    logging.info(f"Alert counts: {tuple(tracker.alert_counts[t] for t in tracker.alert_counts)}")
    return findings


def provide_handle_transaction(w3, blockexplorer, heuristic):
    def handle_transaction(transaction_event):
        try:
            return detect_address_poisoning(w3, blockexplorer, heuristic, transaction_event)
        except Exception as e:
            logging.error(f"Unhandled error processing transaction {transaction_event.hash}: {e}")
            return []

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3, blockexplorer, heuristic)


def handle_transaction(transaction_event):
    return real_handle_transaction(transaction_event)
