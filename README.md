# Address Poisoning Agent

## Description

This agent detects address poisoning, phishing transactions.

## Supported Chains

- Ethereum
- Binance Smart Chain
- Polygon

## Alerts

- ADDRESS-POISONING-ZERO-VALUE
  - Fired when a transaction consists of more than 3 zero-value Transfer events, primarily in stablecoins
  - Severity is always set to "medium"
  - Type is always set to "suspicious"
  - Other metadata includes the phishing eoa and contract involved, the length of the transaction logs, and attacker and victim addresses

- ADDRESS-POISONING-LOW-VALUE
  - *******PLACEHOLDER*********
  - Severity is always set to "medium"
  - Type is always set to "suspicious"
  - Other metadata includes the phishing eoa and contract involved, the length of the transaction logs, and attacker and victim addresses

- ADDRESS-POISONING-FAKE-TOKEN
  - *******PLACEHOLDER*********
  - Severity is always set to "medium"
  - Type is always set to "suspicious"
  - Other metadata includes the phishing eoa and contract involved, the length of the transaction logs, and attacker and victim addresses

## Test Data

The agent behaviour can be verified with the following transactions:

- ADDRESS-POISONING-ZERO-VALUE
  - 0x8fef1adea2ca09fc31eb6990c5aba7f4ed1bbab75b18524bd42978ceb136f2cb (50 transferFrom calls)
  - 0x759f75b3d5d134b986f379f26b0cb29b89e1098cc9c42b4e5dbe83ff83a6666a (9 transferFrom calls)

- ADDRESS-POISONING-LOW-VALUE
  - 0xbaa8ad798afc2abfd75def7b4ab8ee64032cc2c80c74bbf082aeca6b395efb4d
  - 
