from unittest.mock import patch, MagicMock
from blockexplorer import BlockExplorer


class TestBlockExplorer:

    def test_init_sets_host_per_chain(self):
        expected_hosts = {
            1: "https://api.etherscan.io/api",
            137: "https://api.polygonscan.com/api",
            56: "https://api.bscscan.com/api",
            42161: "https://api.arbiscan.io/api",
            10: "https://api-optimistic.etherscan.io/api",
            250: "https://api.ftmscan.com/api",
            43114: "https://api.snowtrace.io/api",
        }
        for chain_id, host in expected_hosts.items():
            explorer = BlockExplorer(chain_id)
            assert explorer.host == host, f"Unexpected host for chain {chain_id}"
            assert hasattr(explorer, "api_key")

    def test_init_unknown_chain_has_no_host(self):
        explorer = BlockExplorer(999999)
        assert not hasattr(explorer, "host")

    @patch("blockexplorer.requests")
    def test_make_token_history_query_filters_by_sender(self, mock_requests):
        address = "0xAbCdEf0000000000000000000000000000000001"
        token = "0xToken"

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "result": [
                {"from": str.lower(address), "value": "100"},
                {"from": "0xsomeoneelse", "value": "200"},
                {"from": str.lower(address), "value": "300"},
            ]
        }
        mock_requests.get.return_value = mock_response

        explorer = BlockExplorer(1)
        values = explorer.make_token_history_query((address, token))

        assert values == ["100", "300"], "Should only return values sent by the address"
        mock_requests.get.assert_called_once()

    @patch("blockexplorer.requests")
    def test_make_token_history_query_returns_last_five(self, mock_requests):
        address = "0xabc0000000000000000000000000000000000002"
        token = "0xToken"

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "result": [
                {"from": str.lower(address), "value": str(i)} for i in range(10)
            ]
        }
        mock_requests.get.return_value = mock_response

        explorer = BlockExplorer(1)
        values = explorer.make_token_history_query((address, token))

        assert values == ["5", "6", "7", "8", "9"], "Should return only the last five transfers"

    @patch("blockexplorer.requests")
    def test_is_verified_true_when_status_one(self, mock_requests):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"status": "1", "result": "some-abi"}'
        mock_requests.get.return_value = mock_response

        explorer = BlockExplorer(1)
        assert explorer.is_verified("0xcontract") is True

    @patch("blockexplorer.requests")
    def test_is_verified_false_when_status_not_one(self, mock_requests):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"status": "0", "result": "Contract source code not verified"}'
        mock_requests.get.return_value = mock_response

        explorer = BlockExplorer(1)
        assert explorer.is_verified("0xcontract") is False

    @patch("blockexplorer.requests")
    def test_is_verified_false_on_bad_status_code(self, mock_requests):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_requests.get.return_value = mock_response

        explorer = BlockExplorer(1)
        assert explorer.is_verified("0xcontract") is False
