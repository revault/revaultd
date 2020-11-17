"""
Most of the code here is stolen from C-lightning's test suite. This is surely
Rusty Russell or Christian Decker who wrote most of this (I'd put some sats on
cdecker), so credits to them ! (MIT licensed)
"""
from bitcoin.core import COIN
from decimal import Decimal
from utils import BitcoinD, RevaultD, wait_for

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


MOCK_MANAGERS = [
    {
        "xpub": "xpub6AtVcKWPpZ9t3Aa3VvzWid1dzJFeXPfNntPbkGsYjNrp7uhXpzSL5QVMCmaHqUzbVUGENEwbBbzF9E8emTxQeP3AzbMjfzvwSDkwUrxg2G4",
    },
    {
        "xpub": "xpub6AMXQWzNN9GSrWk5SeKdEUK6Ntha87BBtprp95EGSsLiMkUedYcHh53P3J1frsnMqRSssARq6EdRnAJmizJMaBqxCrA3MVGjV7d9wNQAEtm",
    },
]

MOCK_STAKEHOLDERS = [
    {
        "xpub": "xpub6BHATNyFVsBD8MRygTsv2q9WFTJzEB3o6CgJK7sjopcB286bmWFkNYm6kK5fzVe2gk4mJrSK5isFSFommNDST3RYJWSzrAe9V4bEzboHqnA",
        "cosigner_key": "02644cf9e2b78feb0a751e50502f530a4cbd0bbda3020779605391e71654dd66c2",
    },
    {
        "xpub": "xpub6AP3nZhB34Zoan3KCL9bAdnwNHdzMbskLudpbchwTfkHwnNDXYf1769gzozjgzDNUF7iwa5nCdhE5byrcx5PDKFCUDByeuqiHa382EKhcay",
        "cosigner_key": "03ced55d1208bd8c6b42b11e29baa577711cae831b3a1296607c5e5d3ed365f49c",
    },
    {
        "xpub": "xpub6AUkrYoAoySUXnEbspdqL7dJ5qE4n5wTDAXb22tzNaU9cKqpeE6Tjvh5gkXECrX8bGM2Ndgk3HYYVmD7m3NyHxS74NRi1cuq9ddxmhG8RxP",
        "cosigner_key": "026237f655f3bf45fd6b7aa00e91c2603d6155f1cc001e40f5e47662d965c4c779",
    },
    {
        "xpub": "xpub6AL6oiHLkP5bDMry27vH7uethb1g8iTysk5MZJvNe1yBv5fedvqqgiaPS2riWCiu4o3H8xinEVdQ5zz8pZKH1RtjTbdQyxHsMMCBrp2PP8S",
        "cosigner_key": "030a3cbcfbfdf7122fe7fa830354c956ea6595f2dbde23286f03bc1ec0c1685ca3",
    },
]


@pytest.fixture
def revaultd_stakeholder(bitcoind, test_base_dir):
    datadir = os.path.join(test_base_dir, "revaultd")
    os.makedirs(datadir, exist_ok=True)
    ourselves = {
        "stakeholder_xpub": MOCK_STAKEHOLDERS[0]["xpub"],
    }
    csv = 35
    revaultd = RevaultD(datadir, ourselves, MOCK_STAKEHOLDERS, MOCK_MANAGERS,
                        csv, bitcoind)
    revaultd.start()

    yield revaultd

    revaultd.cleanup()


@pytest.fixture
def revaultd_manager(bitcoind, test_base_dir):
    datadir = os.path.join(test_base_dir, "revaultd")
    os.makedirs(datadir, exist_ok=True)
    ourselves = {
        "manager_xpub": MOCK_MANAGERS[0]["xpub"],
    }
    csv = 35
    revaultd = RevaultD(datadir, ourselves, MOCK_STAKEHOLDERS, MOCK_MANAGERS,
                        csv, bitcoind)
    revaultd.start()

    yield revaultd

    revaultd.cleanup()
