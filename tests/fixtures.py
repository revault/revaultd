"""
Most of the code here was initially stolen from C-lightning's test suite.
Credits to Rusty Russell and Christian Decker from Blockstream who wrote most
of the file i originally copied! (MIT licensed)
"""
from concurrent import futures
from ephemeral_port_reserve import reserve
from test_framework.bitcoind import BitcoinD
from test_framework.revaultd import ManagerRevaultd, StakeholderRevaultd
from test_framework.revault_network import RevaultNetwork
from test_framework.utils import (
    get_descriptors,
    get_participants,
    POSTGRES_USER,
    POSTGRES_PASS,
    POSTGRES_HOST,
    POSTGRES_IS_SETUP,
    EXECUTOR_WORKERS,
)

import bip32
import os
import pytest
import shutil
import tempfile
import time


# A dict in which we count how often a particular test has run so far. Used to
# give each attempt its own numbered directory, and avoid clashes.
__attempts = {}


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

    # test_base_dir is at the session scope, so we can't use request.node as mentioned in
    # the doc linked in the hook above.
    if request.session.testsfailed == 0:
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

    bitcoind.rpc.createwallet(bitcoind.rpc.wallet_name, False, False, "", False, True)

    bitcoind.rpc.generatetoaddress(101, bitcoind.rpc.getnewaddress())
    while bitcoind.rpc.getbalance() < 50:
        time.sleep(0.01)

    yield bitcoind

    bitcoind.cleanup()


@pytest.fixture
def revaultd_stakeholder(bitcoind, directory):
    datadir = os.path.join(directory, "revaultd")
    os.makedirs(datadir, exist_ok=True)
    (stks, cosigs, mans, _, _, _) = get_participants(2, 3)
    cpfp_xprivs = [
        bytes.fromhex(
            "0435839400000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689004b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
        )
    ]
    cpfp_xpubs = [
        "tpubD6NzVbkrYhZ4XJDrzRvuxHEyQaPd1mwwdDofEJwekX18tAdsqeKfxss79AJzg1431FybXg5rfpTrJF4iAhyR7RubberdzEQXiRmXGADH2eA"
    ]
    stks_xpubs = [stk.get_xpub() for stk in stks]
    cosigs_keys = []
    mans_xpubs = [man.get_xpub() for man in mans]
    (dep_desc, unv_desc, cpfp_desc) = get_descriptors(
        stks_xpubs, cosigs_keys, mans_xpubs, len(mans_xpubs), cpfp_xpubs, 232
    )

    stk_config = {
        "keychain": stks[0],
        "watchtowers": [{"host": "127.0.0.1:1", "noise_key": os.urandom(32).hex()}],
        # We use a dummy one since we don't use it anyways
        "emergency_address": "bcrt1qewc2348370pgw8kjz8gy09z8xyh0d9fxde6nzamd3txc9gkmjqmq8m4cdq",
    }
    coordinator_noise_key = (
        "d91563973102454a7830137e92d0548bc83b4ea2799f1df04622ca1307381402"
    )
    bitcoind_cookie = os.path.join(bitcoind.bitcoin_dir, "regtest", ".cookie")
    revaultd = StakeholderRevaultd(
        datadir,
        dep_desc,
        unv_desc,
        cpfp_desc,
        os.urandom(32),
        coordinator_noise_key,
        reserve(),
        bitcoind.rpcport,
        bitcoind_cookie,
        stk_config=stk_config,
        wt_process=None,
    )

    try:
        revaultd.start()
        yield revaultd
    except Exception:
        revaultd.cleanup()
        raise

    revaultd.cleanup()


@pytest.fixture
def revaultd_manager(bitcoind, directory):
    datadir = os.path.join(directory, "revaultd")
    os.makedirs(datadir, exist_ok=True)
    (stks, cosigs, mans, _, _, _) = get_participants(2, 3)
    cpfp_seed = os.urandom(32)
    cpfp_xprivs = [bip32.BIP32.from_seed(cpfp_seed, network="test")]
    cpfp_xpubs = [cpfp_xprivs[0].get_xpub()]
    stks_xpubs = [stk.get_xpub() for stk in stks]
    cosigs_keys = []
    mans_xpubs = [man.get_xpub() for man in mans]
    (dep_desc, unv_desc, cpfp_desc) = get_descriptors(
        stks_xpubs, cosigs_keys, mans_xpubs, len(mans_xpubs), cpfp_xpubs, 232
    )

    man_config = {
        "keychain": mans[0],
        "cosigners": [{"host": "127.0.0.1:1", "noise_key": os.urandom(32)}],
        # We use a dummy one since we don't use it anyways
        "emergency_address": "bcrt1qewc2348370pgw8kjz8gy09z8xyh0d9fxde6nzamd3txc9gkmjqmq8m4cdq",
    }
    coordinator_noise_key = (
        "d91563973102454a7830137e92d0548bc83b4ea2799f1df04622ca1307381402"
    )
    bitcoind_cookie = os.path.join(bitcoind.bitcoin_dir, "regtest", ".cookie")
    revaultd = ManagerRevaultd(
        datadir,
        dep_desc,
        unv_desc,
        cpfp_desc,
        os.urandom(32),
        coordinator_noise_key,
        reserve(),
        bitcoind.rpcport,
        bitcoind_cookie,
        man_config=man_config,
        cpfp_seed=cpfp_seed,
    )

    try:
        revaultd.start()
        yield revaultd
    except Exception:
        revaultd.cleanup()
        raise

    revaultd.cleanup()


@pytest.fixture
def revault_network(directory, bitcoind, executor):
    if not POSTGRES_IS_SETUP:
        raise ValueError(
            "Please set the POSTGRES_USER, POSTGRES_PASS and "
            "POSTGRES_HOST environment variables."
        )

    factory = RevaultNetwork(
        directory, bitcoind, executor, POSTGRES_USER, POSTGRES_PASS, POSTGRES_HOST
    )

    try:
        yield factory
    except Exception:
        factory.cleanup()
        raise

    factory.cleanup()
