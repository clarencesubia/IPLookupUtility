from unittest.mock import patch, MagicMock
from IPLookupUtility.iplookup import validate_ip_address
from IPLookupUtility.iplookup import subnet_checker
from IPLookupUtility.iplookup import ip_info_lookup


def test_validate_ip_address_valid():
    assert validate_ip_address("192.168.1.1")

def test_validate_ip_address_invalid():
    assert not validate_ip_address("999.999.999.999")

def test_subnet_checker_true():
    assert subnet_checker("192.168.1.0/24", "192.168.0.0/16")

def test_subnet_checker_false():
    assert not subnet_checker("10.0.0.0/8", "192.168.0.0/16")

@patch("requests.get")
def test_ip_info_lookup_mocked(mock_get):
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"ip": "8.8.8.8", "country": "US"}
    mock_get.return_value = mock_resp

    result = ip_info_lookup("8.8.8.8")
    assert result["ip"] == "8.8.8.8"
    assert result["country"] == "US"
