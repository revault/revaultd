import copy
import logging
import pytest
import serializations

from fixtures import *
from utils import TIMEOUT, wait_for, RpcError, POSTGRES_IS_SETUP

def test_revaultd_stakeholder_starts(revaultd_stakeholder):
    revaultd_stakeholder.rpc.call("stop")
    revaultd_stakeholder.wait_for_logs([
        "Stopping revaultd.",
        "Bitcoind received shutdown.",
        "Signature fetcher thread received shutdown.",
    ])
    revaultd_stakeholder.proc.wait(TIMEOUT)


def test_revaultd_manager_starts(revaultd_manager):
    revaultd_manager.rpc.call("stop")
    revaultd_manager.wait_for_logs([
        "Stopping revaultd.",
        "Bitcoind received shutdown.",
        "Signature fetcher thread received shutdown.",
    ])
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

    # If we are not a stakeholder, it'll fail
    with pytest.raises(RpcError, match="This is a stakeholder command"):
         mans[0].rpc.getrevocationtxs("whatever_doesnt_matter")

    # If the vault isn't known, it'll fail (note: it's racy for others but
    # behaviour is the same is the vault isn't known)
    txid = bitcoind.rpc.sendtoaddress(addr, 0.22222)
    stks[0].wait_for_logs(["Got a new unconfirmed deposit",
                           "Incremented deposit derivation index"])
    vault = stks[0].rpc.listvaults()["vaults"][0]
    for n in stks:
        with pytest.raises(RpcError, match=".* does not refer to a known and "
                                           "confirmed vault"):
            n.rpc.getrevocationtxs(f"{vault['txid']}:{vault['vout']}")

    # Now, get it confirmed. They all derived the same transactions
    bitcoind.generate_block(6, txid)
    wait_for(lambda: stks[0].rpc.listvaults()["vaults"][0]["status"] == "funded")
    txs = stks[0].rpc.getrevocationtxs(f"{vault['txid']}:{vault['vout']}")
    assert len(txs.keys()) == 3
    for n in stks[1:]:
        wait_for(lambda: n.rpc.listvaults()["vaults"][0]["status"] == "funded")
        assert txs == n.rpc.getrevocationtxs(f"{vault['txid']}:{vault['vout']}")


def test_getunvaulttx(revault_network):
    revault_network.deploy(3, 1)
    mans = revault_network.man_wallets
    stks = revault_network.stk_wallets

    # If we are not a stakeholder, it'll fail
    with pytest.raises(RpcError, match="This is a stakeholder command"):
         mans[0].rpc.getunvaulttx("whatever_doesnt_matter")

    # We can't query for an unknow vault
    invalid_outpoint = f"{'0'*64}:1"
    with pytest.raises(RpcError, match="No vault at"):
         stks[0].rpc.getunvaulttx(invalid_outpoint)

    vault = revault_network.fund(18)
    outpoint = f"{vault['txid']}:{vault['vout']}"
    stks[0].wait_for_deposit(outpoint)
    tx = stks[0].rpc.getunvaulttx(outpoint)
    for stk in stks[1:]:
        stk.wait_for_deposit(outpoint)
        assert (tx["unvault_tx"] ==
                stk.rpc.getunvaulttx(outpoint)["unvault_tx"])


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


def psbt_add_input(psbt_str):
    psbt = serializations.PSBT()
    psbt.deserialize(psbt_str)
    assert len(psbt.inputs) == 1
    psbt.inputs.append(serializations.PartiallySignedInput())
    psbt.inputs[1].witness_utxo = copy.copy(psbt.inputs[0].witness_utxo)
    psbt.inputs[1].witness_utxo.nValue = 12398
    psbt.inputs[1].witness_script = psbt.inputs[0].witness_script
    psbt.tx.vin.append(serializations.CTxIn())
    return psbt.serialize()


def psbt_add_invalid_sig(psbt_str):
    psbt = serializations.PSBT()
    psbt.deserialize(psbt_str)
    assert len(psbt.inputs) == 1
    pk = bytes.fromhex("02c83dc7fb3ed0a5dd33cf35d891ba4fcbde"
                       "90ede809a0b247a46f4d989dd14411")
    sig = bytes.fromhex("3045022100894f5c61d1c297227a9a094ea471fd9d84b"
                        "61d4fc78eb71376621758df8c4946022073f5c11e62add56c4c9"
                        "10bc90d0eadb154919e0c6c67b909897bda13cae3620d")
    psbt.inputs[0].partial_sigs[pk] = sig
    return psbt.serialize()


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_revocationtxs_sanity_checks(revault_network):
    revault_network.deploy(6, 2)
    mans = revault_network.man_wallets
    stks = revault_network.stk_wallets

    # If we are not a stakeholder, it'll fail
    with pytest.raises(RpcError, match="This is a stakeholder command"):
         mans[0].rpc.revocationtxs("whatever_doesnt_matter", "a", "n", "dd")

    vault = revault_network.fund(10)
    deposit = f"{vault['txid']}:{vault['vout']}"
    child_index = vault["derivation_index"]
    stks[0].wait_for_deposit(deposit)
    psbts = stks[0].rpc.getrevocationtxs(deposit)

    # We must provide all revocation txs at once
    with pytest.raises(RpcError, match="Invalid params.*"):
         stks[0].rpc.revocationtxs(deposit, psbts["cancel_tx"],
                                   psbts["emergency_tx"])

    # We can't send it for an unknown vault
    with pytest.raises(RpcError, match="Outpoint does not correspond to an "
                                       "existing vault"):
        stks[0].rpc.revocationtxs(deposit[:-1] + "18", psbts["cancel_tx"],
                                   psbts["emergency_tx"],
                                   psbts["emergency_unvault_tx"])

    # We can't give it random PSBTs, it will fail at parsing time
    mal_cancel = psbt_add_input(psbts["cancel_tx"])
    with pytest.raises(RpcError, match="Invalid Revault transaction"):
        stks[0].rpc.revocationtxs(deposit, mal_cancel,
                                  psbts["emergency_tx"],
                                  psbts["emergency_unvault_tx"])
    mal_emer = psbt_add_input(psbts["emergency_tx"])
    with pytest.raises(RpcError, match="Invalid Revault transaction"):
        stks[0].rpc.revocationtxs(deposit, psbts["cancel_tx"],
                                  mal_emer,
                                  psbts["emergency_unvault_tx"])
    mal_unemer = psbt_add_input(psbts["emergency_unvault_tx"])
    with pytest.raises(RpcError, match="Invalid Revault transaction"):
        stks[0].rpc.revocationtxs(deposit, psbts["cancel_tx"],
                                  psbts["emergency_tx"], mal_unemer)

    # We can't mix up PSBTS (the Cancel can even be detected at parsing time)
    with pytest.raises(RpcError, match="Invalid Revault transaction"):
        stks[0].rpc.revocationtxs(deposit, psbts["emergency_tx"], # here
                                  psbts["emergency_tx"],
                                  psbts["emergency_unvault_tx"])
    with pytest.raises(RpcError, match="Invalid Emergency tx: db wtxid"):
        stks[0].rpc.revocationtxs(deposit, psbts["cancel_tx"],
                                  psbts["cancel_tx"], # here
                                  psbts["emergency_unvault_tx"])
    with pytest.raises(RpcError, match="Invalid Unvault Emergency tx: db wtxid"):
        stks[0].rpc.revocationtxs(deposit, psbts["cancel_tx"],
                                  psbts["emergency_tx"],
                                  psbts["emergency_tx"]) # here


    # We must provide a signature for ourselves
    with pytest.raises(RpcError, match="No signature for ourselves.*Cancel"):
        stks[0].rpc.revocationtxs(deposit, psbts["cancel_tx"],
                                  psbts["emergency_tx"],
                                  psbts["emergency_unvault_tx"])
    cancel_psbt = stks[0].stk_keychain.sign_revocation_psbt(psbts["cancel_tx"],
                                                            child_index)
    with pytest.raises(RpcError, match="No signature for ourselves.*Emergency"):
        stks[0].rpc.revocationtxs(deposit, cancel_psbt, psbts["emergency_tx"],
                                  psbts["emergency_unvault_tx"])
    emer_psbt = stks[0].stk_keychain.sign_revocation_psbt(psbts["emergency_tx"],
                                                          child_index)
    with pytest.raises(RpcError, match="No signature for ourselves.*UnvaultEmergency"):
        stks[0].rpc.revocationtxs(deposit, cancel_psbt, emer_psbt,
                                  psbts["emergency_unvault_tx"])
    unemer_psbt = stks[0].stk_keychain.sign_revocation_psbt(
        psbts["emergency_unvault_tx"], child_index
    )

    # We refuse any random invalid signature
    mal_cancel = psbt_add_invalid_sig(cancel_psbt)
    with pytest.raises(RpcError, match="Invalid signature in Cancel"):
        stks[0].rpc.revocationtxs(deposit, mal_cancel, emer_psbt, unemer_psbt)
    mal_emer = psbt_add_invalid_sig(emer_psbt)
    with pytest.raises(RpcError, match="Invalid signature in Emergency"):
        stks[0].rpc.revocationtxs(deposit, cancel_psbt, mal_emer, unemer_psbt)
    mal_unemer = psbt_add_invalid_sig(unemer_psbt)
    with pytest.raises(RpcError, match="Invalid signature in Unvault Emergency"):
        stks[0].rpc.revocationtxs(deposit, cancel_psbt, emer_psbt, mal_unemer)


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_sig_sharing(revault_network):
    revault_network.deploy(5, 3)
    stks = revault_network.stk_wallets
    mans = revault_network.man_wallets

    vault = revault_network.fund(10)
    deposit = f"{vault['txid']}:{vault['vout']}"
    child_index = vault["derivation_index"]

    # We can just get everyone to sign it out of band and a single one handing
    # it to the sync server.
    stks[0].wait_for_deposit(deposit)
    psbts = stks[0].rpc.getrevocationtxs(deposit)
    cancel_psbt = psbts["cancel_tx"]
    emer_psbt = psbts["emergency_tx"]
    unemer_psbt = psbts["emergency_unvault_tx"]
    for stk in stks:
        cancel_psbt = stk.stk_keychain.sign_revocation_psbt(cancel_psbt,
                                                            child_index)
        emer_psbt = stk.stk_keychain.sign_revocation_psbt(emer_psbt,
                                                          child_index)
        unemer_psbt = stk.stk_keychain.sign_revocation_psbt(unemer_psbt,
                                                            child_index)
    stks[0].rpc.revocationtxs(deposit, cancel_psbt, emer_psbt, unemer_psbt)
    assert stks[0].rpc.listvaults()["vaults"][0]["status"] == "secured"
    # Note that we can't pass it twice
    with pytest.raises(RpcError, match="Invalid vault status"):
        stks[0].rpc.revocationtxs(deposit, cancel_psbt, emer_psbt, unemer_psbt)
    # They must all have fetched the signatures, even the managers!
    for stk in stks + mans:
        wait_for(lambda: len(stk.rpc.listvaults(["secured"], [deposit])["vaults"]) > 0)


    vault = revault_network.fund(20)
    deposit = f"{vault['txid']}:{vault['vout']}"
    child_index = vault["derivation_index"]

    # Or everyone can sign on their end and push to the sync server
    for stk in stks:
        stk.wait_for_deposit(deposit)
        psbts = stk.rpc.getrevocationtxs(deposit)
        cancel_psbt = stk.stk_keychain.sign_revocation_psbt(psbts["cancel_tx"],
                                                            child_index)
        emer_psbt = stk.stk_keychain.sign_revocation_psbt(psbts["emergency_tx"],
                                                          child_index)
        unemer_psbt = stk.stk_keychain.sign_revocation_psbt(
            psbts["emergency_unvault_tx"], child_index
        )
        stk.rpc.revocationtxs(deposit, cancel_psbt, emer_psbt, unemer_psbt)
    for stk in stks + mans:
        wait_for(lambda: len(stk.rpc.listvaults(["secured"], [deposit])["vaults"]) > 0)
