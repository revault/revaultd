import pytest
import random

from fixtures import *
from test_framework import serializations
from test_framework.utils import (
    TEST_PROFILING,
)


@pytest.mark.skipif(not TEST_PROFILING, reason="Profiling specific")
def test_revault_network_warmup_teardown(revault_network):
    """Profile the setup of the revault_network fixture."""
    pass


@pytest.mark.skipif(not TEST_PROFILING, reason="Profiling specific")
def test_revault_network_deployment(revault_network):
    """Profile the deployment of a dummy network."""
    revault_network.deploy(10, 5, 2, csv=12)
    pass


@pytest.mark.skipif(not TEST_PROFILING, reason="Profiling specific")
def test_revault_network_funding(revault_network):
    """Profile the funding of 20 vaults on a dummy network."""
    revault_network.deploy(10, 5, 2, csv=12)

    for amount in range(20):
        revault_network.fund((amount + 1) / 100)


@pytest.mark.skipif(not TEST_PROFILING, reason="Profiling specific")
def test_revault_network_securing(revault_network):
    """Profile the securing of 10 vaults on a dummy network."""
    revault_network.deploy(10, 5, 2, csv=12)

    vaults = []
    for amount in range(10):
        vaults.append(revault_network.fund((amount + 1) / 100))
    revault_network.secure_vaults(vaults)


@pytest.mark.skipif(not TEST_PROFILING, reason="Profiling specific")
def test_revault_network_activation(revault_network):
    """Profile the activation of 10 vaults on a dummy network."""
    revault_network.deploy(10, 5, 2, csv=12)

    vaults = []
    for amount in range(10):
        vaults.append(revault_network.fund((amount + 1) / 100))
    revault_network.activate_fresh_vaults(vaults)
