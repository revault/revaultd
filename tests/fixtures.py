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

    # FIXME: use lightningd's teardown checks for errors
    try:
        shutil.rmtree(directory)
    except Exception:
        files = [os.path.join(dp, f) for dp, dn, fn in os.walk(directory) for f in fn]
        print("Directory still contains files:", files)
        raise


@pytest.fixture
def test_name(request):
    yield request.function.__name__


@pytest.fixture
def bitcoind(directory):
    bitcoind = BitcoinD(bitcoin_dir=directory)
    bitcoind.startup()

    bitcoind.rpc.createwallet("revaultd-tests", False, False, "", True)
    while bitcoind.rpc.getbalance() < 50:
        bitcoind.rpc.generatetoaddress(1, bitcoind.rpc.getnewaddress())

    yield bitcoind

    bitcoind.cleanup()
