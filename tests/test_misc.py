import pytest

from fixtures import (
    revaultd_stakeholder, revaultd_manager, bitcoind, directory, test_base_dir,
    test_name, revault_network
)
from utils import TIMEOUT, wait_for, RpcError, POSTGRES_IS_SETUP

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

    wait_for(lambda: revaultd_manager.rpc.call("getinfo")["blockheight"] > 0)
    height = revaultd_manager.rpc.call("getinfo")["blockheight"]
    bitcoind.generate_block(1)
    wait_for(lambda: revaultd_manager.rpc.call("getinfo")["blockheight"]
                      == height + 1)


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
    assert vault_list[0]["address"] == addr
    assert vault_list[0]["derivation_index"] == 0

    # Generate 5 blocks, it is still unconfirmed
    bitcoind.generate_block(5)
    assert revaultd_manager.rpc.call("listvaults")["vaults"][0]["status"] == \
        "unconfirmed"

    # 1 more block will get it confirmed
    bitcoind.generate_block(1)
    revaultd_manager.wait_for_log(f"Vault at .*{txid}.* is now confirmed")
    assert revaultd_manager.rpc.call("listvaults")["vaults"][0]["status"] == \
        "funded"

    # Of course, it persists across restarts.
    revaultd_manager.rpc.call("stop")
    revaultd_manager.proc.wait(TIMEOUT)
    revaultd_manager.start()
    vault_list = revaultd_manager.rpc.call("listvaults")["vaults"]
    assert len(vault_list) == 1
    assert vault_list[0]["status"] == "funded"
    assert vault_list[0]["txid"] == txid
    assert vault_list[0]["amount"] == amount_sent * 10**8
    assert vault_list[0]["address"] == addr
    assert vault_list[0]["derivation_index"] == 0

    # And we can filter the result by status
    vault_list = revaultd_manager.rpc.call("listvaults",
                                           [["unconfirmed"]])["vaults"]
    assert len(vault_list) == 0
    vault_list = revaultd_manager.rpc.call("listvaults",
                                           [["funded"]])["vaults"]
    assert len(vault_list) == 1
    assert vault_list[0]["status"] == "funded"
    assert vault_list[0]["txid"] == txid
    assert vault_list[0]["amount"] == amount_sent * 10**8
    assert vault_list[0]["address"] == addr
    assert vault_list[0]["derivation_index"] == 0

    # And we can filter the result by outpoints
    outpoint = f"{txid}:{vault_list[0]['vout']}"
    vault_list = revaultd_manager.rpc.call("listvaults",
                                           [[], [outpoint]])["vaults"]
    assert len(vault_list) == 1
    assert vault_list[0]["status"] == "funded"
    assert vault_list[0]["txid"] == txid
    assert vault_list[0]["amount"] == amount_sent * 10**8
    assert vault_list[0]["address"] == addr
    assert vault_list[0]["derivation_index"] == 0

    outpoint = f"{txid}:{100}"
    vault_list = revaultd_manager.rpc.call("listvaults",
                                           [[], [outpoint]])["vaults"]
    assert len(vault_list) == 0


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_getdepositaddress(revault_network, bitcoind):
    (stks, mans) = revault_network.deploy(4, 2)
    addr = stks[0].rpc.call("getdepositaddress")["address"]

    # If we don't use it, we'll get the same. From us and everyone else
    for n in stks + mans:
        assert addr == n.rpc.call("getdepositaddress")["address"]

    # But if we do, we'll get the next one (but the same from everyone)!
    bitcoind.rpc.sendtoaddress(addr, 0.22222)
    stks[0].wait_for_logs(["Got a new unconfirmed deposit",
                           "Incremented deposit derivation index"])
    addr2 = stks[0].rpc.call("getdepositaddress")["address"]
    assert addr2 != addr
    for n in stks[1:] + mans:
        n.wait_for_logs(["Got a new unconfirmed deposit",
                         "Incremented deposit derivation index"])
        assert addr2 == n.rpc.call("getdepositaddress")["address"]


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_getrevocationtxs(revault_network, bitcoind):
    (stks, mans) = revault_network.deploy(4, 2)
    addr = stks[0].rpc.call("getdepositaddress")["address"]

    # If the vault isn't known, it'll fail (note: it's racy for others but
    # behaviour is the same is the vault isn't known)
    txid = bitcoind.rpc.sendtoaddress(addr, 0.22222)
    stks[0].wait_for_logs(["Got a new unconfirmed deposit",
                           "Incremented deposit derivation index"])
    vault = stks[0].rpc.listvaults()["vaults"][0]
    for n in stks + mans:
        with pytest.raises(RpcError, match=".* does not refer to a known and "
                                           "confirmed vault"):
            n.rpc.getrevocationtxs(f"{vault['txid']}:{vault['vout']}")

    # Now, get it confirmed. They all derived the same transactions
    bitcoind.generate_block(6, txid)
    wait_for(lambda: stks[0].rpc.listvaults()["vaults"][0]["status"] == "funded")
    txs = stks[0].rpc.getrevocationtxs(f"{vault['txid']}:{vault['vout']}")
    for n in stks[1:] + mans:
        wait_for(lambda: n.rpc.listvaults()["vaults"][0]["status"] == "funded")
        assert txs == n.rpc.getrevocationtxs(f"{vault['txid']}:{vault['vout']}")


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_listtransactions(revault_network, bitcoind):
    (stks, mans) = revault_network.deploy(4, 2)

    addr = stks[0].rpc.call("getdepositaddress")["address"]
    txid = bitcoind.rpc.sendtoaddress(addr, 0.22222)
    wait_for(lambda: len(stks[0].rpc.call("listvaults")["vaults"]) > 0)
    vault = stks[0].rpc.call("listvaults")["vaults"][0]
    deposit = f"{vault['txid']}:{vault['vout']}"

    res = stks[0].rpc.listtransactions([deposit])["transactions"][0]
    # Sanity check the API
    assert ("deposit" in res and "unvault" in res and "cancel" in res
            and "emergency" in res and "unvault_emergency" in res)
    assert (stks[0].rpc.listtransactions([deposit]) ==
            stks[0].rpc.listtransactions())
    # The deposit is always fully signed..
    assert "hex" in res["deposit"]
    # .. And broadcast
    assert "received_at" in res["deposit"]
    # .. But right now it's not confirmed
    assert "blockheight" not in res["deposit"]

    # Get it confirmed
    bitcoind.generate_block(6, txid)
    wait_for(lambda: stks[0].rpc.listvaults()["vaults"][0]["status"] == "funded")
    res = stks[0].rpc.listtransactions([deposit])["transactions"][0]
    assert "blockheight" in res["deposit"]

    # Sanity check they all output the same transactions..
    # FIXME: this is flaky on the received_at value. Check out how it's set in
    # bitcoind that somehow it's different between the calls..
    # sorted_res = sorted(res.items())
    # for n in stks[1:] + mans:
        # res = n.rpc.listtransactions([deposit])["transactions"][0]
        # assert sorted(res.items()) == sorted_res
