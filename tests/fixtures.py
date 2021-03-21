"""
Most of the code here was initially stolen from C-lightning's test suite.
Credits to Rusty Russell and Christian Decker from Blockstream who wrote most
of the file i originally copied! (MIT licensed)
"""
from concurrent import futures
from ephemeral_port_reserve import reserve
from test_framework.utils import (
    BitcoinD,
    ManagerRevaultd,
    StakeholderRevaultd,
    get_participants,
    RevaultNetwork,
    POSTGRES_USER,
    POSTGRES_PASS,
    POSTGRES_HOST,
    POSTGRES_IS_SETUP,
    EXECUTOR_WORKERS,
)

import os
import pytest
import shutil
import tempfile
import time

__attempts = {}


@pytest.fixture(autouse=True)
def set_backtrace():
    prev = os.getenv("RUST_BACKTRACE", "0")
    os.environ["RUST_BACKTRACE"] = "1"

    yield

    os.environ["RUST_BACKTRACE"] = prev


@pytest.fixture(scope="session")
def test_base_dir():
    d = os.getenv("TEST_DIR", "/tmp")

    directory = tempfile.mkdtemp(prefix="revaultd-tests-", dir=d)
    print("Running tests in {}".format(directory))

    yield directory

    content = os.listdir(directory)
    if content == []:
        shutil.rmtree(directory)
    else:
        print(f"Leaving base dir '{directory}' as it still contains {content}")


# Taken from https://docs.pytest.org/en/latest/example/simple.html#making-test-result-information-available-in-fixtures
@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()

    # set a report attribute for each phase of a call, which can
    # be "setup", "call", "teardown"

    setattr(item, "rep_" + rep.when, rep)


@pytest.fixture
def directory(request, test_base_dir, test_name):
    """Return a per-test specific directory.

    This makes a unique test-directory even if a test is rerun multiple times.

    """
    global __attempts
    # Auto set value if it isn't in the dict yet
    __attempts[test_name] = __attempts.get(test_name, 0) + 1
    directory = os.path.join(
        test_base_dir, "{}_{}".format(test_name, __attempts[test_name])
    )

    if not os.path.exists(directory):
        os.makedirs(directory)

    yield directory

    # Taken from the doc, as is the hook above.
    # request.node is an "item" because we use the default
    # "function" scope
    failed = False
    # FIXME: somehow the doc example is invalid.
    # if request.node.rep_setup.failed:
    # failed = True
    # elif request.node.rep_call.failed:
    # failed = True

    if not failed:
        try:
            shutil.rmtree(directory)
        except Exception:
            files = [
                os.path.join(dp, f) for dp, _, fn in os.walk(directory) for f in fn
            ]
            print("Directory still contains files:", files)
            raise
    else:
        print(f"Test failed, leaving directory '{directory}' intact")


@pytest.fixture
def test_name(request):
    yield request.function.__name__


@pytest.fixture
def executor(test_name):
    ex = futures.ThreadPoolExecutor(
        max_workers=EXECUTOR_WORKERS, thread_name_prefix=test_name
    )
    yield ex
    ex.shutdown(wait=False)


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
    (stks, cosigs, mans) = get_participants(2, 3)

    stk_config = {
        "keychain": stks[0],
        "watchtowers": [
            {
                "host": "127.0.0.1:1",
                "noise_key": "03c3fee141e97ed33a50875a092179684c1145"
                "5cc6f49a9bddaacf93cd77def697",
            }
        ],
    }
    csv = 35
    coordinator_noise_key = (
        "d91563973102454a7830137e92d0548bc83b4e" "a2799f1df04622ca1307381402"
    )
    revaultd = StakeholderRevaultd(
        datadir,
        stks,
        cosigs,
        mans,
        csv,
        os.urandom(32),
        coordinator_noise_key,
        reserve(),
        bitcoind,
        stk_config=stk_config,
    )
    revaultd.start()

    yield revaultd

    revaultd.cleanup()


@pytest.fixture
def revaultd_manager(bitcoind, directory):
    datadir = os.path.join(directory, "revaultd")
    os.makedirs(datadir, exist_ok=True)
    (stks, cosigs, mans) = get_participants(2, 3)

    man_config = {
        "keychain": mans[0],
        "cosigners": [
            {
                "host": "127.0.0.1:1",
                "noise_key": "03c3fee141e97ed33a50875a092179684c1145"
                "5cc6f49a9bddaacf93cd77def697",
            }
        ],
    }
    csv = 35
    coordinator_noise_key = (
        "d91563973102454a7830137e92d0548bc83b4e" "a2799f1df04622ca1307381402"
    )
    revaultd = ManagerRevaultd(
        datadir,
        stks,
        cosigs,
        mans,
        csv,
        os.urandom(32),
        coordinator_noise_key,
        reserve(),
        bitcoind,
        man_config=man_config,
    )
    revaultd.start()

    yield revaultd

    revaultd.cleanup()


@pytest.fixture
def revault_network(directory, bitcoind):
    if not POSTGRES_IS_SETUP:
        raise ValueError(
            "Please set the POSTGRES_USER, POSTGRES_PASS and "
            "POSTGRES_HOST environment variables."
        )

    factory = RevaultNetwork(
        directory, bitcoind, POSTGRES_USER, POSTGRES_PASS, POSTGRES_HOST
    )

    yield factory

    factory.cleanup()
