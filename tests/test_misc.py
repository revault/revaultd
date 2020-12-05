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


def test_listvaults(revaultd_manager, bitcoind):
    res = revaultd_manager.rpc.call("listvaults")
    assert res["vaults"] == []

    # Send to a deposit address, we detect one unconfirmed vault
    amount_sent = 0.75
    addr = revaultd_manager.rpc.call("getdepositaddress")["address"]
    txid = bitcoind.rpc.sendtoaddress(addr, amount_sent)
    revaultd_manager.wait_for_log("Got a new unconfirmed deposit")
    vault_list = revaultd_manager.rpc.call("listvaults")["vaults"]
    assert len(vault_list) == 1
    assert vault_list[0]["status"] == "unconfirmed"
    assert vault_list[0]["txid"] == txid
    assert vault_list[0]["amount"] == amount_sent * 10**8

    # Generate 5 blocks, it is still unconfirmed
    bitcoind.generate_block(5)
    revaultd_manager.rpc.call("listvaults")["vaults"][0]["status"] == \
        "unconfirmed"

    # 1 more block will get it confirmed
    bitcoind.generate_block(1)
    revaultd_manager.rpc.call("listvaults")["vaults"][0]["status"] == \
        "funded"

    # Of course, it persists across restarts.
    revaultd_manager.rpc.call("stop")
    revaultd_manager.proc.wait(TIMEOUT)
    revaultd_manager.start()
    vault_list = revaultd_manager.rpc.call("listvaults")["vaults"]
    assert len(vault_list) == 1
    assert vault_list[0]["status"] == "unconfirmed"
    assert vault_list[0]["txid"] == txid
    assert vault_list[0]["amount"] == amount_sent * 10**8


def test_getdepositaddress(revaultd_manager, bitcoind):
    addr = revaultd_manager.rpc.call("getdepositaddress")["address"]

    # If we don't use it, we'll get the same
    assert addr == revaultd_manager.rpc.call("getdepositaddress")["address"]

    # But if we do, we'll get the next one!
    bitcoind.rpc.sendtoaddress(addr, 0.22222)
    revaultd_manager.wait_for_log("Got a new unconfirmed deposit")
    assert addr != revaultd_manager.rpc.call("getdepositaddress")["address"]
