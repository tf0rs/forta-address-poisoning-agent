# Address Poisoning Agent

## Description

This agent detects address poisoning, phishing transactions.

## Supported Chains

- Ethereum
- PLACEHOLDER

## Alerts

- ADDRESS-POISONING
  - Fired when a transaction consists of more than 5 zero-value transferFrom calls, primarily for stablecoins
  - Severity is always set to "low" (mention any conditions where it could be something else)
  - Type is always set to "info" (mention any conditions where it could be something else)
  - Mention any other type of metadata fields included with this alert

## Test Data

The agent behaviour can be verified with the following transactions:

- 0x8fef1adea2ca09fc31eb6990c5aba7f4ed1bbab75b18524bd42978ceb136f2cb (50 transferFrom calls)
- 0x759f75b3d5d134b986f379f26b0cb29b89e1098cc9c42b4e5dbe83ff83a6666a (9 transferFrom calls)
