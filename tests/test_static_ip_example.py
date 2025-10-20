import pytest
import sys
from pathlib import Path

# Ensure repository root is on sys.path so tests can import the module directly
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from static_ip_example import (
    network_info,
    parse_cidr_from_ip_and_mask,
    generate_static_ip_examples,
    example_use_cases,
)


def test_parse_cidr_from_mask():
    assert parse_cidr_from_ip_and_mask("192.168.1.5", "255.255.255.0") == "24"


def test_network_info_with_prefix():
    info = network_info("10.0.0.5", "24")
    assert info["network_address"] == "10.0.0.0"
    assert info["broadcast_address"] == "10.0.0.255"
    assert info["total_hosts"] == 254


def test_network_info_with_mask():
    info = network_info("192.168.2.10", "255.255.255.0")
    assert info["network_address"] == "192.168.2.0"
    assert info["total_hosts"] == 254


def test_generate_examples_count():
    examples = generate_static_ip_examples("192.168.5.10", 3)
    assert len(examples) == 3
    for ip in examples:
        assert ip.startswith("192.168.5.")


def test_generate_examples_invalid_base():
    with pytest.raises(ValueError):
        generate_static_ip_examples("999.999.999.999", 2)


def test_example_use_cases_format():
    lines = example_use_cases("192.168.1.100")
    assert any("http://192.168.1.100:80" in l for l in lines)
