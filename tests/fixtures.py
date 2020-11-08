"""
Most of the code here is stolen from C-lightning's test suite. This is surely
Rusty Russell or Christian Decker who wrote most of this (I'd put some sats on
cdecker), so credits to them ! (MIT licensed)
"""
from bitcoin.core import COIN
from decimal import Decimal
from utils import BitcoinD, wait_for

import logging
import os
import pytest
import shutil
import tempfile

__attempts = {}


@pytest.fixture(scope="session")
def test_base_dir():
    d = os.getenv("TEST_DIR", "/tmp")

    directory = tempfile.mkdtemp(prefix='revaultd-tests-', dir=d)
    print("Running tests in {}".format(directory))

    yield directory

    if os.listdir(directory) == []:
        shutil.rmtree(directory)


@pytest.fixture
def directory(request, test_base_dir, test_name):
    """Return a per-test specific directory.

    This makes a unique test-directory even if a test is rerun multiple times.

    """
    global __attempts
    # Auto set value if it isn't in the dict yet
    __attempts[test_name] = __attempts.get(test_name, 0) + 1
    directory = os.path.join(test_base_dir,
                             "{}_{}".format(test_name, __attempts[test_name]))
    request.node.has_errors = False

    yield directory

    # This uses the status set in conftest.pytest_runtest_makereport to
    # determine whether we succeeded or failed. Outcome can be None if the
    # failure occurs during the setup phase, hence the use to getattr instead
    # of accessing it directly.
    rep_call = getattr(request.node, 'rep_call', None)
    outcome = 'passed' if rep_call is None else rep_call.outcome
    failed = not outcome or outcome != 'passed'

    if not failed:
        shutil.rmtree(directory)
    else:
        logging.debug("Test execution failed, leaving the test directory {}"
                      " intact.".format(directory))


@pytest.fixture
def test_name(request):
    yield request.function.__name__


@pytest.fixture
def bitcoind(directory):
    bitcoind = BitcoinD(bitcoin_dir=directory)
    bitcoind.startup()

    while bitcoind.rpc.getbalance() < 50:
        bitcoind.rpc.generatetoaddress(1, bitcoind.getnewaddress())

    yield bitcoind

    bitcoind.cleanup()


@pytest.fixture
def bitcoinds(directory):
    # FIXME: do it in a less hacky manner
    n_bitcoind = 5
    bitcoinds = [BitcoinD(bitcoin_dir="{}/{}".format(directory, i))
                 for i in range(n_bitcoind)]

    for bitcoind in bitcoinds:
        bitcoind.startup()

    # Connect everyone..
    for bit in bitcoinds:
        for i in range(len(bitcoinds)):
            bit.rpc.addnode("127.0.0.1:{}".format(bitcoinds[i]
                                                  .p2pport), "add")

    wait_for(lambda: all(bit.rpc.getconnectioncount() > 3
                         for bit in bitcoinds))

    # Hand some funds to everyone (10 utxos)
    rounds = 111 // n_bitcoind + 1
    for _ in range(rounds):
        for bitcoind in bitcoinds:
            bitcoind.rpc.generatetoaddress(1, bitcoind.rpc.getnewaddress())
            blockcount = bitcoind.rpc.getblockcount()
            wait_for(lambda: all(bit.rpc.getblockcount() == blockcount
                                 for bit in bitcoinds))

    yield bitcoinds

    for bitcoind in bitcoinds:
        bitcoind.cleanup()
