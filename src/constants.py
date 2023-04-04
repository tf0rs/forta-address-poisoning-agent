STABLECOIN_CONTRACTS = {
    1: [
        '0xdac17f958d2ee523a2206206994597c13d831ec7',
        '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
        '0x6b175474e89094c44da98b954eedeac495271d0f',
        '0x0000000000085d4780B73119b644AE5ecd22b376'
    ],
    56: [
        '0x55d398326f99059ff775485246999027b3197955',
        '0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d',
        '0x8965349fb649a33a30cbfda057d8ec2c48abe2a2'
    ],
    137: [
        '0x2791bca1f2de4661ed88a30c99a7a9449aa84174',
        '0xdab529f40e671a1d4bf91361c21bf9f0c9712ab7',
        '0x8f3cf7ad23cd3cadbd9735aff958023239c6a063',
        '0xc2132d05d31c914a87c6611c10748aeb04b58e8f'
    ]
}

# ABIs for decoding relevant log events
TRANSFER_EVENT_ABI = '{"name":"Transfer","type":"event","anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}]}'
APPROVAL_EVENT_ABI = '{"name":"Approval","type":"event","anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}]}'
SYMBOL_CALL_ABI = [
    {
      "constant": True,
      "inputs": [],
      "name": "symbol",
      "outputs": [
          {"name": "",
            "type": "string"
          }
      ],
      "payable": False,
      "stateMutability": "view",
      "type": "function"
    }
]

OFFICIAL_SYMBOLS = {
    1: ['USDT', 'USDC', 'ETH', 'DAI'],
    56: [],
    137: []
}