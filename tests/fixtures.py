"""
Most of the code here is stolen from C-lightning's test suite. This is surely
Rusty Russell or Christian Decker who wrote most of this (I'd put some sats on
cdecker), so credits to them ! (MIT licensed)
"""
from utils import (
    BitcoinD, ManagerRevaultd, StakeholderRevaultd, get_participants,
    RevaultNetwork, TEST_DEBUG, POSTGRES_USER, POSTGRES_PASS, POSTGRES_HOST,
    POSTGRES_IS_SETUP
)

import logging
import os
import pytest
import shutil
import tempfile
import time

__attempts = {}


@pytest.fixture(scope="session")
def test_base_dir():
    d = os.getenv("TEST_DIR", "/tmp")

    directory = tempfile.mkdtemp(prefix='revaultd-tests-', dir=d)
    print("Running tests in {}".format(directory))

    yield directory

    content = os.listdir(directory)
    if content == []:
        shutil.rmtree(directory)
    else:
        print(f"Leaving base dir '{directory}' as it still contains {content}")


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

    if not os.path.exists(directory):
        os.makedirs(directory)

    yield directory

    # This uses the status set in conftest.pytest_runtest_makereport to
    # determine whether we succeeded or failed. Outcome can be None if the
    # failure occurs during the setup phase, hence the use to getattr instead
    # of accessing it directly.
    rep_call = getattr(request.node, 'rep_call', None)
    outcome = 'passed' if rep_call is None else rep_call.outcome
    failed = not outcome or request.node.has_errors or outcome != 'passed'

    if not failed:
        try:
            shutil.rmtree(directory)
        except Exception:
            files = [os.path.join(dp, f) for dp, _, fn in os.walk(directory) for f in fn]
            print("Directory still contains files:", files)
            raise
    else:
        print(f"Test failed, leaving directory '{directory}' intact")


@pytest.fixture(autouse=True)
def setup_logging():
    """Enable logging before a test, and remove all handlers afterwards.

    This "fixes" the issue with pytest swapping out sys.stdout and sys.stderr
    in order to capture the output, but then doesn't wait for the handlers to
    terminate before closing the buffers. It just iterates through all
    loggers, and removes any handlers that might be pointing at sys.stdout or
    sys.stderr.

    """
    if TEST_DEBUG:
        logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

    yield

    loggers = [logging.getLogger()] + list(logging.Logger.manager.loggerDict.values())
    for logger in loggers:
        handlers = getattr(logger, 'handlers', [])
        for handler in handlers:
            logger.removeHandler(handler)


@pytest.fixture
def test_name(request):
    yield request.function.__name__


@pytest.fixture
def bitcoind(directory):
    bitcoind = BitcoinD(bitcoin_dir=directory)
    bitcoind.startup()

    bitcoind.rpc.createwallet(bitcoind.rpc.wallet_name, False, False, "", True)

    while bitcoind.rpc.getbalance() < 50:
        bitcoind.rpc.generatetoaddress(1, bitcoind.rpc.getnewaddress())

    while bitcoind.rpc.getblockcount() <= 1:
        time.sleep(0.1)

    yield bitcoind

    bitcoind.cleanup()


@pytest.fixture
def revaultd_stakeholder(bitcoind, directory):
    datadir = os.path.join(directory, "revaultd")
    os.makedirs(datadir, exist_ok=True)
    (stk_xpubs, cosig_keys, man_xpubs) = get_participants(2, 3)

    stk_config = {
        "xpub": stk_xpubs[0],
        "watchtowers": [
            {
                "host": "127.0.0.1:1",
                "noise_key": "03c3fee141e97ed33a50875a092179684c1145"
                             "5cc6f49a9bddaacf93cd77def697"
            }
        ]
    }
    csv = 35
    coordinator_noise_key = b"d91563973102454a7830137e92d0548bc83b4e" \
                            b"a2799f1df04622ca1307381402"
    revaultd = StakeholderRevaultd(
        datadir, stk_xpubs, cosig_keys, man_xpubs, csv, os.urandom(32),
        coordinator_noise_key, bitcoind, stk_config=stk_config
    )
    revaultd.start()

    yield revaultd

    revaultd.cleanup()


@pytest.fixture
def revaultd_manager(bitcoind, directory):
    datadir = os.path.join(directory, "revaultd")
    os.makedirs(datadir, exist_ok=True)
    (stk_xpubs, cosig_keys, man_xpubs) = get_participants(2, 3)

    man_config = {
        "xpub": man_xpubs[0],
        "cosigners": [
            {
                "host": "127.0.0.1:1",
                "noise_key": "03c3fee141e97ed33a50875a092179684c1145"
                             "5cc6f49a9bddaacf93cd77def697"
            }
        ]
    }
    csv = 35
    coordinator_noise_key = b"d91563973102454a7830137e92d0548bc83b4e" \
                            b"a2799f1df04622ca1307381402"
    revaultd = ManagerRevaultd(
        datadir, stk_xpubs, cosig_keys, man_xpubs, csv, os.urandom(32),
        coordinator_noise_key, bitcoind, man_config=man_config
    )
    revaultd.start()

    yield revaultd

    revaultd.cleanup()


@pytest.fixture
def revault_network(directory, bitcoind):
    if not POSTGRES_IS_SETUP:
        raise ValueError("Please set the POSTGRES_USER, POSTGRES_PASS and "
                         "POSTGRES_HOST environment variables.")

    factory = RevaultNetwork(directory, bitcoind, POSTGRES_USER, POSTGRES_PASS,
                             POSTGRES_HOST)

    yield factory

    factory.cleanup()
