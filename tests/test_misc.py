from fixtures import (
    revaultd_stakeholder, revaultd_manager, bitcoind, directory, test_base_dir,
    test_name
)
from utils import TIMEOUT
import time
import json, socket


def test_revaultd_stakeholder_starts(revaultd_stakeholder):
    revaultd_stakeholder.rpc.call("stop")
    revaultd_stakeholder.wait_for_log("Stopping revaultd.")
    revaultd_stakeholder.wait_for_log("Bitcoind received shutdown.")
    revaultd_stakeholder.proc.wait(TIMEOUT)


def test_revaultd_manager_starts(revaultd_manager):
    revaultd_manager.rpc.call("stop")
    revaultd_manager.wait_for_log("Stopping revaultd.")
    revaultd_manager.wait_for_log("Bitcoind received shutdown.")
    revaultd_manager.proc.wait(TIMEOUT)


def test_getinfo(revaultd_manager, bitcoind):
    res = revaultd_manager.rpc.call("getinfo")
    assert res["network"] == "regtest"
    assert res["sync"] == 1.0
    assert res["version"] == "0.0.2"

    bitcoind.generate_block(1)
    revaultd_manager.wait_for_log("New tip")
    sec_res = revaultd_manager.rpc.call("getinfo")
    assert sec_res["blockheight"] == res["blockheight"] + 1


def test_listvaults(revaultd_manager):
    res = revaultd_manager.rpc.call("listvaults")
    assert res["vaults"] == []

    # TODO: add a getnewaddress method to test listvaults..
