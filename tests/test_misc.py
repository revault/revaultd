import copy
import logging
import pytest
import random

from bitcoin.core import COIN
from fixtures import *
from test_framework import serializations
from test_framework.utils import (
    POSTGRES_IS_SETUP,
    TIMEOUT,
    RpcError,
    wait_for,
)


def test_getinfo(revaultd_manager, bitcoind):
    res = revaultd_manager.rpc.call("getinfo")
    assert res["network"] == "regtest"
    assert res["sync"] == 1.0
    assert res["version"] == "0.0.2"
    assert res["vaults"] == 0

    wait_for(lambda: revaultd_manager.rpc.call("getinfo")["blockheight"] > 0)
    height = revaultd_manager.rpc.call("getinfo")["blockheight"]
    bitcoind.generate_block(1)
    wait_for(lambda: revaultd_manager.rpc.call("getinfo")["blockheight"] == height + 1)


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
    assert vault_list[0]["amount"] == amount_sent * 10 ** 8
    assert vault_list[0]["address"] == addr
    assert vault_list[0]["derivation_index"] == 0
    assert vault_list[0]["updated_at"] == vault_list[0]["received_at"]
    assert vault_list[0]["blockheight"] == 0
    assert revaultd_manager.rpc.call("getinfo")["vaults"] == 1

    # Generate 5 blocks, it is still unconfirmed
    bitcoind.generate_block(5)
    assert (
        revaultd_manager.rpc.call("listvaults")["vaults"][0]["status"] == "unconfirmed"
    )

    # 1 more block will get it confirmed
    bitcoind.generate_block(1)
    revaultd_manager.wait_for_log(f"Vault at .*{txid}.* is now confirmed")
    vault = revaultd_manager.rpc.call("listvaults")["vaults"][0]
    assert vault["status"] == "funded"
    assert vault["updated_at"] > vault["received_at"]
    assert vault["blockheight"] == bitcoind.rpc.getblockcount() - 5

    # Of course, it persists across restarts.
    revaultd_manager.rpc.call("stop")
    revaultd_manager.proc.wait(TIMEOUT)
    revaultd_manager.start()
    vault_list = revaultd_manager.rpc.call("listvaults")["vaults"]
    assert len(vault_list) == 1
    assert vault_list[0]["status"] == "funded"
    assert vault_list[0]["txid"] == txid
    assert vault_list[0]["amount"] == amount_sent * 10 ** 8
    assert vault_list[0]["address"] == addr
    assert vault_list[0]["derivation_index"] == 0

    # And we can filter the result by status
    vault_list = revaultd_manager.rpc.call("listvaults", [["unconfirmed"]])["vaults"]
    assert len(vault_list) == 0
    vault_list = revaultd_manager.rpc.call("listvaults", [["funded"]])["vaults"]
    assert len(vault_list) == 1
    assert vault_list[0]["status"] == "funded"
    assert vault_list[0]["txid"] == txid
    assert vault_list[0]["amount"] == amount_sent * 10 ** 8
    assert vault_list[0]["address"] == addr
    assert vault_list[0]["derivation_index"] == 0

    # And we can filter the result by outpoints
    outpoint = f"{txid}:{vault_list[0]['vout']}"
    vault_list = revaultd_manager.rpc.call("listvaults", [[], [outpoint]])["vaults"]
    assert len(vault_list) == 1
    assert vault_list[0]["status"] == "funded"
    assert vault_list[0]["txid"] == txid
    assert vault_list[0]["amount"] == amount_sent * 10 ** 8
    assert vault_list[0]["address"] == addr
    assert vault_list[0]["derivation_index"] == 0

    outpoint = f"{txid}:{100}"
    vault_list = revaultd_manager.rpc.call("listvaults", [[], [outpoint]])["vaults"]
    assert len(vault_list) == 0


def test_largewallets(revaultd_stakeholder, bitcoind):
    """Test a wallet with 1000 deposits and 10 dust deposits"""
    amount = 0.01
    dust_amount = 0.00012345
    bitcoind.generate_block(10)

    for i in range(10):
        txids = []
        for i in range(100):
            addr = revaultd_stakeholder.rpc.call("getdepositaddress")["address"]
            txids.append(bitcoind.rpc.sendtoaddress(addr, amount))

        addr = revaultd_stakeholder.rpc.call("getdepositaddress")["address"]
        txids.append(bitcoind.rpc.sendtoaddress(addr, dust_amount))

        bitcoind.generate_block(6, wait_for_mempool=txids)

    wait_for(lambda: revaultd_stakeholder.rpc.getinfo()["vaults"] == 10 * 100)
    assert len(revaultd_stakeholder.rpc.listvaults()["vaults"]) == 10 * 100
    # We previously experienced crashes when calling listpresignedtransactions
    # with a large number of vaults
    revaultd_stakeholder.rpc.listpresignedtransactions()


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_getdepositaddress(revault_network, bitcoind):
    (stks, mans) = revault_network.deploy(4, 2)
    addr = stks[0].rpc.call("getdepositaddress")["address"]

    # If we don't use it, we'll get the same. From us and everyone else
    for n in stks + mans:
        assert addr == n.rpc.call("getdepositaddress")["address"]

    # But if we do, we'll get the next one (but the same from everyone)!
    bitcoind.rpc.sendtoaddress(addr, 0.22222)
    stks[0].wait_for_logs(
        ["Got a new unconfirmed deposit", "Incremented deposit derivation index"]
    )
    addr2 = stks[0].rpc.call("getdepositaddress")["address"]
    assert addr2 != addr
    for n in stks[1:] + mans:
        n.wait_for_logs(
            ["Got a new unconfirmed deposit", "Incremented deposit derivation index"]
        )
        assert addr2 == n.rpc.call("getdepositaddress")["address"]


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_huge_deposit(revault_network, bitcoind):
    revault_network.deploy(2, 1)
    stk = revault_network.stk_wallets[0]
    amount = 13_000
    bitcoind.get_coins(amount)
    vault = revault_network.fund(amount)
    deposit = f"{vault['txid']}:{vault['vout']}"
    stk.wait_for_deposits([deposit])
    assert stk.rpc.listvaults([], [deposit])["vaults"][0]["amount"] == amount * COIN


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_getrevocationtxs(revault_network, bitcoind):
    (stks, mans) = revault_network.deploy(4, 2)
    addr = stks[0].rpc.call("getdepositaddress")["address"]
    txid = bitcoind.rpc.sendtoaddress(addr, 0.22222)
    stks[0].wait_for_logs(
        ["Got a new unconfirmed deposit", "Incremented deposit derivation index"]
    )
    vault = stks[0].rpc.listvaults()["vaults"][0]
    deposit = f"{vault['txid']}:{vault['vout']}"

    # If we are not a stakeholder, it'll fail
    with pytest.raises(RpcError, match="This is a stakeholder command"):
        mans[0].rpc.getrevocationtxs(deposit)

    # If the vault isn't confirmed, it'll fail (note: it's racy for others but
    # behaviour is the same is the vault isn't known)
    for n in stks:
        with pytest.raises(
            RpcError, match=".* does not refer to a known and confirmed vault"
        ):
            n.rpc.getrevocationtxs(deposit)

    # Now, get it confirmed. They all derived the same transactions
    bitcoind.generate_block(6, txid)
    wait_for(lambda: stks[0].rpc.listvaults()["vaults"][0]["status"] == "funded")
    txs = stks[0].rpc.getrevocationtxs(deposit)
    assert len(txs.keys()) == 3
    for n in stks[1:]:
        wait_for(lambda: n.rpc.listvaults()["vaults"][0]["status"] == "funded")
        assert txs == n.rpc.getrevocationtxs(deposit)


def test_getunvaulttx(revault_network):
    revault_network.deploy(3, 1)
    mans = revault_network.man_wallets
    stks = revault_network.stk_wallets
    vault = revault_network.fund(18)
    outpoint = f"{vault['txid']}:{vault['vout']}"
    stks[0].wait_for_deposits([outpoint])

    # If we are not a stakeholder, it'll fail
    with pytest.raises(RpcError, match="This is a stakeholder command"):
        mans[0].rpc.getunvaulttx(outpoint)

    # We can't query for an unknow vault
    invalid_outpoint = f"{'0'*64}:1"
    with pytest.raises(RpcError, match="No vault at"):
        stks[0].rpc.getunvaulttx(invalid_outpoint)

    tx = stks[0].rpc.getunvaulttx(outpoint)
    for stk in stks[1:]:
        stk.wait_for_deposits([outpoint])
        assert tx["unvault_tx"] == stk.rpc.getunvaulttx(outpoint)["unvault_tx"]


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_listpresignedtransactions(revault_network):
    revault_network.deploy(2, 1)
    vaultA = revault_network.fund(0.2222221)
    vaultB = revault_network.fund(122.88881)
    depositA = f"{vaultA['txid']}:{vaultA['vout']}"
    depositB = f"{vaultB['txid']}:{vaultB['vout']}"
    stks = revault_network.stk_wallets
    mans = revault_network.man_wallets

    # Sanity check the API
    stks[0].wait_for_deposits([depositA, depositB])
    stk_res = stks[0].rpc.listpresignedtransactions([depositA])[
        "presigned_transactions"
    ][0]
    assert stk_res["unvault"] is not None
    assert stk_res["cancel"] is not None
    assert stk_res["emergency"] is not None
    assert stk_res["unvault_emergency"] is not None
    mans[0].wait_for_deposits([depositA, depositB])
    man_res = mans[0].rpc.listpresignedtransactions([depositB])[
        "presigned_transactions"
    ][0]
    assert man_res["unvault"] is not None
    assert man_res["cancel"] is not None
    assert man_res["emergency"] is None
    assert man_res["unvault_emergency"] is None

    # Sanity check they all generated the same unsigned PSBTs
    for w in stks[1:] + mans:
        w.wait_for_deposits([depositA])
        res = w.rpc.listpresignedtransactions([depositA])["presigned_transactions"][0]
        assert res["unvault"] == stk_res["unvault"]
        assert res["cancel"] == stk_res["cancel"]
        if res["emergency"] is not None:
            assert res["emergency"] == stk_res["emergency"]
        if res["unvault_emergency"] is not None:
            assert res["unvault_emergency"] == stk_res["unvault_emergency"]

    # If the vault gets secured the extracted revocation transactions will be
    # available
    revault_network.secure_vault(vaultA)
    stk_res = stks[0].rpc.listpresignedtransactions([depositA])[
        "presigned_transactions"
    ][0]
    assert stk_res["unvault"]["hex"] is None, "not active yet"
    assert stk_res["cancel"]["hex"] is not None
    assert stk_res["emergency"]["hex"] is not None
    assert stk_res["unvault_emergency"]["hex"] is not None

    # If the vault gets activated the unvault transaction will then be available
    revault_network.activate_vault(vaultA)
    man_res = mans[0].rpc.listpresignedtransactions([depositA])[
        "presigned_transactions"
    ][0]
    assert man_res["unvault"]["hex"] is not None


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_listonchaintransactions(revault_network):
    """Just a small sanity check of the API"""
    revault_network.deploy(2, 1)
    vaultA = revault_network.fund(0.2222221)
    vaultB = revault_network.fund(122.88881)
    depositA = f"{vaultA['txid']}:{vaultA['vout']}"
    depositB = f"{vaultB['txid']}:{vaultB['vout']}"
    stks = revault_network.stk_wallets
    mans = revault_network.man_wallets

    # Sanity check the API
    for w in stks + mans:
        w.wait_for_deposits([depositA, depositB])
        res = w.rpc.listonchaintransactions([depositA, depositB])[
            "onchain_transactions"
        ][0]
        # Deposit is always there
        assert res["deposit"]["blockheight"] is not None
        assert res["deposit"]["received_at"] is not None
        assert res["deposit"]["hex"] is not None
        assert res["unvault"] is None
        assert res["cancel"] is None
        assert res["emergency"] is None
        assert res["unvault_emergency"] is None


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
    pk = bytes.fromhex(
        "02c83dc7fb3ed0a5dd33cf35d891ba4fcbde" "90ede809a0b247a46f4d989dd14411"
    )
    sig = bytes.fromhex(
        "3045022100894f5c61d1c297227a9a094ea471fd9d84b"
        "61d4fc78eb71376621758df8c4946022073f5c11e62add56c4c9"
        "10bc90d0eadb154919e0c6c67b909897bda13cae3620d"
    )
    psbt.inputs[0].partial_sigs[pk] = sig
    return psbt.serialize()


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_revocationtxs(revault_network):
    """Sanity checks for the revocationtxs command"""
    revault_network.deploy(6, 2)
    mans = revault_network.man_wallets
    stks = revault_network.stk_wallets

    vault = revault_network.fund(10)
    deposit = f"{vault['txid']}:{vault['vout']}"
    child_index = vault["derivation_index"]
    stks[0].wait_for_deposits([deposit])
    psbts = stks[0].rpc.getrevocationtxs(deposit)

    # If we are not a stakeholder, it'll fail
    with pytest.raises(RpcError, match="This is a stakeholder command"):
        mans[0].rpc.revocationtxs(
            deposit,
            psbts["cancel_tx"],
            psbts["emergency_tx"],
            psbts["emergency_unvault_tx"],
        )

    # We must provide all revocation txs at once
    with pytest.raises(RpcError, match="Invalid params.*"):
        stks[0].rpc.revocationtxs(deposit, psbts["cancel_tx"], psbts["emergency_tx"])

    # We can't send it for an unknown vault
    with pytest.raises(
        RpcError, match="Outpoint does not correspond to an " "existing vault"
    ):
        stks[0].rpc.revocationtxs(
            deposit[:-1] + "18",
            psbts["cancel_tx"],
            psbts["emergency_tx"],
            psbts["emergency_unvault_tx"],
        )

    # We can't give it random PSBTs, it will fail at parsing time
    mal_cancel = psbt_add_input(psbts["cancel_tx"])
    with pytest.raises(RpcError, match="Invalid Revault transaction"):
        stks[0].rpc.revocationtxs(
            deposit, mal_cancel, psbts["emergency_tx"], psbts["emergency_unvault_tx"]
        )
    mal_emer = psbt_add_input(psbts["emergency_tx"])
    with pytest.raises(RpcError, match="Invalid Revault transaction"):
        stks[0].rpc.revocationtxs(
            deposit, psbts["cancel_tx"], mal_emer, psbts["emergency_unvault_tx"]
        )
    mal_unemer = psbt_add_input(psbts["emergency_unvault_tx"])
    with pytest.raises(RpcError, match="Invalid Revault transaction"):
        stks[0].rpc.revocationtxs(
            deposit, psbts["cancel_tx"], psbts["emergency_tx"], mal_unemer
        )

    # We can't mix up PSBTS (the Cancel can even be detected at parsing time)
    with pytest.raises(RpcError, match="Invalid Revault transaction"):
        stks[0].rpc.revocationtxs(
            deposit,
            psbts["emergency_tx"],  # here
            psbts["emergency_tx"],
            psbts["emergency_unvault_tx"],
        )
    with pytest.raises(RpcError, match="Invalid Emergency tx: db wtxid"):
        stks[0].rpc.revocationtxs(
            deposit,
            psbts["cancel_tx"],
            psbts["cancel_tx"],  # here
            psbts["emergency_unvault_tx"],
        )
    with pytest.raises(RpcError, match="Invalid Unvault Emergency tx: db wtxid"):
        stks[0].rpc.revocationtxs(
            deposit, psbts["cancel_tx"], psbts["emergency_tx"], psbts["emergency_tx"]
        )  # here

    # We must provide a signature for ourselves
    with pytest.raises(RpcError, match="No signature for ourselves.*Cancel"):
        stks[0].rpc.revocationtxs(
            deposit,
            psbts["cancel_tx"],
            psbts["emergency_tx"],
            psbts["emergency_unvault_tx"],
        )
    cancel_psbt = stks[0].stk_keychain.sign_revocation_psbt(
        psbts["cancel_tx"], child_index
    )
    with pytest.raises(RpcError, match="No signature for ourselves.*Emergency"):
        stks[0].rpc.revocationtxs(
            deposit, cancel_psbt, psbts["emergency_tx"], psbts["emergency_unvault_tx"]
        )
    emer_psbt = stks[0].stk_keychain.sign_revocation_psbt(
        psbts["emergency_tx"], child_index
    )
    with pytest.raises(RpcError, match="No signature for ourselves.*UnvaultEmergency"):
        stks[0].rpc.revocationtxs(
            deposit, cancel_psbt, emer_psbt, psbts["emergency_unvault_tx"]
        )
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

    # If we input valid presigned transactions, it will acknowledge that *we* already
    # signed and that we are waiting for others' signatures now.
    stks[0].rpc.revocationtxs(
        deposit,
        cancel_psbt,
        emer_psbt,
        unemer_psbt,
    )
    assert len(stks[0].rpc.listvaults(["securing"], [deposit])["vaults"]) == 1


def test_unvaulttx(revault_network):
    """Sanity checks for the unvaulttx command"""
    revault_network.deploy(3, 1)
    mans = revault_network.man_wallets
    stks = revault_network.stk_wallets
    vault = revault_network.fund(10)
    deposit = f"{vault['txid']}:{vault['vout']}"
    child_index = vault["derivation_index"]
    stks[0].wait_for_deposits([deposit])

    def sign_revocation_txs(stks, deposit):
        """
        Get all stakeholders to sign revocation transactions (speedrun mode)
        """
        stks[0].wait_for_deposits([deposit])
        psbts = stks[0].rpc.getrevocationtxs(deposit)
        cancel_psbt = psbts["cancel_tx"]
        emer_psbt = psbts["emergency_tx"]
        unemer_psbt = psbts["emergency_unvault_tx"]
        for stk in stks:
            cancel_psbt = stk.stk_keychain.sign_revocation_psbt(
                cancel_psbt, child_index
            )
            emer_psbt = stk.stk_keychain.sign_revocation_psbt(emer_psbt, child_index)
            unemer_psbt = stk.stk_keychain.sign_revocation_psbt(
                unemer_psbt, child_index
            )
        stks[0].rpc.revocationtxs(deposit, cancel_psbt, emer_psbt, unemer_psbt)
        assert stks[0].rpc.listvaults([], [deposit])["vaults"][0]["status"] == "secured"

    unvault_psbt = stks[0].rpc.getunvaulttx(deposit)["unvault_tx"]

    # If we are not a stakeholder, it'll fail
    with pytest.raises(RpcError, match="This is a stakeholder command"):
        mans[0].rpc.unvaulttx(deposit, unvault_psbt)

    # We can't send it for an unknown vault
    invalid_outpoint = f"{'00'*32}:1"
    with pytest.raises(RpcError, match="No vault at"):
        stks[0].rpc.unvaulttx(invalid_outpoint, unvault_psbt)

    # We can't give it a random PSBT, it will fail at parsing time
    mal_psbt = psbt_add_input(unvault_psbt)
    with pytest.raises(RpcError, match="Invalid Revault transaction"):
        stks[0].rpc.unvaulttx(deposit, mal_psbt)

    # We can't send it until all the revocation txs sigs have been stored
    assert stks[0].rpc.listvaults([], [deposit])["vaults"][0]["status"] == "funded"
    with pytest.raises(RpcError, match="Invalid vault status"):
        stks[0].rpc.unvaulttx(deposit, unvault_psbt)

    sign_revocation_txs(stks, deposit)

    # We must provide a signature for ourselves
    with pytest.raises(RpcError, match="No signature for ourselves"):
        stks[0].rpc.unvaulttx(deposit, unvault_psbt)
    unvault_psbt = stks[0].stk_keychain.sign_unvault_psbt(unvault_psbt, child_index)

    # We refuse any random invalid signature
    mal_unvault = psbt_add_invalid_sig(unvault_psbt)
    unvault_psbt = stks[0].stk_keychain.sign_unvault_psbt(unvault_psbt, child_index)
    with pytest.raises(RpcError, match="Invalid signature"):
        stks[0].rpc.unvaulttx(deposit, mal_unvault)

    # Get all stakeholders to share their sig, this makes the vault active
    for stk in stks:
        wait_for(
            lambda: stk.rpc.listvaults([], [deposit])["vaults"][0]["status"]
            == "secured"
        )
        unvault_psbt = stk.rpc.getunvaulttx(deposit)["unvault_tx"]
        unvault_psbt = stk.stk_keychain.sign_unvault_psbt(unvault_psbt, child_index)
        stk.rpc.unvaulttx(deposit, unvault_psbt)
        assert (
            len(stk.rpc.listvaults(["activating", "active"], [deposit])["vaults"]) == 1
        )
    for stk in stks:
        wait_for(
            lambda: stk.rpc.listvaults([], [deposit])["vaults"][0]["status"] == "active"
        )

    # We can't do it again
    with pytest.raises(RpcError, match="Invalid vault status"):
        stks[0].rpc.unvaulttx(deposit, unvault_psbt)

    # We can share all the signatures at once
    vault = revault_network.fund(20)
    deposit = f"{vault['txid']}:{vault['vout']}"
    child_index = vault["derivation_index"]
    stks[0].wait_for_deposits([deposit])
    sign_revocation_txs(stks, deposit)
    unvault_psbt = stks[0].rpc.getunvaulttx(deposit)["unvault_tx"]
    for stk in stks:
        wait_for(
            lambda: stk.rpc.listvaults([], [deposit])["vaults"][0]["status"]
            == "secured"
        )
        unvault_psbt = stk.stk_keychain.sign_unvault_psbt(unvault_psbt, child_index)
    stks[0].rpc.unvaulttx(deposit, unvault_psbt)
    for stk in stks:
        wait_for(
            lambda: stk.rpc.listvaults([], [deposit])["vaults"][0]["status"] == "active"
        )


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_revocation_sig_sharing(revault_network):
    revault_network.deploy(5, 3)
    stks = revault_network.stk_wallets
    mans = revault_network.man_wallets

    vault = revault_network.fund(10)
    deposit = f"{vault['txid']}:{vault['vout']}"
    child_index = vault["derivation_index"]

    # We can just get everyone to sign it out of band and a single one handing
    # it to the sync server.
    stks[0].wait_for_deposits([deposit])
    psbts = stks[0].rpc.getrevocationtxs(deposit)
    cancel_psbt = psbts["cancel_tx"]
    emer_psbt = psbts["emergency_tx"]
    unemer_psbt = psbts["emergency_unvault_tx"]
    for stk in stks:
        cancel_psbt = stk.stk_keychain.sign_revocation_psbt(cancel_psbt, child_index)
        emer_psbt = stk.stk_keychain.sign_revocation_psbt(emer_psbt, child_index)
        unemer_psbt = stk.stk_keychain.sign_revocation_psbt(unemer_psbt, child_index)
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
        stk.wait_for_deposits([deposit])
        psbts = stk.rpc.getrevocationtxs(deposit)
        cancel_psbt = stk.stk_keychain.sign_revocation_psbt(
            psbts["cancel_tx"], child_index
        )
        emer_psbt = stk.stk_keychain.sign_revocation_psbt(
            psbts["emergency_tx"], child_index
        )
        unemer_psbt = stk.stk_keychain.sign_revocation_psbt(
            psbts["emergency_unvault_tx"], child_index
        )
        stk.rpc.revocationtxs(deposit, cancel_psbt, emer_psbt, unemer_psbt)
    for stk in stks + mans:
        wait_for(lambda: len(stk.rpc.listvaults(["secured"], [deposit])["vaults"]) > 0)


def test_raw_broadcast_cancel(revault_network, bitcoind):
    """
    Test broadcasting a dozen of pair of Unvault and Cancel for vaults with
    different derivation indexes.
    """
    revault_network.deploy(3, 2)
    stks = revault_network.stk_wallets
    mans = revault_network.man_wallets

    for i in range(10):
        logging.debug(f"\n\nRound {i}\n\n")
        vault = revault_network.fund(10)
        assert (
            vault["derivation_index"] == i
        ), "Derivation index isn't increasing one by one?"

        deposit = f"{vault['txid']}:{vault['vout']}"
        revault_network.secure_vault(vault)
        revault_network.activate_vault(vault)

        unvault_tx = stks[0].rpc.listpresignedtransactions([deposit])[
            "presigned_transactions"
        ][0]["unvault"]["hex"]
        txid = bitcoind.rpc.sendrawtransaction(unvault_tx)
        bitcoind.generate_block(1, wait_for_mempool=txid)

        for w in stks + mans:
            wait_for(lambda: len(w.rpc.listvaults(["unvaulted"], [deposit])) == 1)

        cancel_tx = stks[0].rpc.listpresignedtransactions([deposit])[
            "presigned_transactions"
        ][0]["cancel"]["hex"]
        logging.debug(f"{cancel_tx}")
        txid = bitcoind.rpc.sendrawtransaction(cancel_tx)
        bitcoind.generate_block(1, wait_for_mempool=txid)

        for w in stks + mans:
            wait_for(lambda: len(w.rpc.listvaults(["canceled"], [deposit])) == 1)


def test_reorged_deposit(revaultd_stakeholder, bitcoind):
    stk = revaultd_stakeholder

    # Create a new deposit
    amount_sent = 42
    addr = stk.rpc.getdepositaddress()["address"]
    bitcoind.rpc.sendtoaddress(addr, amount_sent)
    wait_for(lambda: len(stk.rpc.listvaults()["vaults"]) > 0)

    # Get it confirmed
    vault = stk.rpc.listvaults()["vaults"][0]
    deposit = f"{vault['txid']}:{vault['vout']}"
    bitcoind.generate_block(6, wait_for_mempool=vault["txid"])
    stk.wait_for_deposits([deposit])
    vault = stk.rpc.listvaults()["vaults"][0]

    # Now reorg the last block. This should not affect us, but we should detect
    # it.
    bitcoind.simple_reorg(bitcoind.rpc.getblockcount() - 1)
    stk.wait_for_logs(
        [
            "Detected reorg",
            # 7 because simple_reorg() adds a block
            f"Vault deposit '{deposit}' still has '7' confirmations",
        ]
    )
    stk.wait_for_deposits([deposit])

    # Now actually reorg the deposit. This should not affect us
    bitcoind.simple_reorg(vault["blockheight"])
    stk.wait_for_logs(
        [
            "Detected reorg",
            # 8 because simple_reorg() adds a block
            f"Vault deposit '{deposit}' still has '8' confirmations",
        ]
    )
    stk.wait_for_deposits([deposit])

    # Now reorg the deposit and shift the transaction up 3 blocks, since we are
    # adding an extra one during the reorg we should still have 6 confs and be
    # fine
    bitcoind.simple_reorg(vault["blockheight"], shift=3)
    stk.wait_for_logs(
        [
            "Detected reorg",
            f"Vault deposit '{deposit}' still has '6' confirmations",
        ]
    )
    stk.wait_for_deposits([deposit])

    # Now reorg the deposit and shift the transaction up 2 blocks, since we are
    # adding an extra one during the reorg we should end up with 5 confs, and
    # mark the vault as unconfirmed
    bitcoind.simple_reorg(vault["blockheight"] + 3, shift=2)
    stk.wait_for_logs(
        [
            "Detected reorg",
            f"Vault deposit '{deposit}' ended up with '5' confirmations",
            "Rescan of all vaults in db done.",
        ]
    )
    assert stk.rpc.listvaults()["vaults"][0]["status"] == "unconfirmed"

    # Reorg it again, it's already unconfirmed so nothing to do, but since we
    # mined a new block it's now confirmed!
    bitcoind.simple_reorg(vault["blockheight"] + 3 + 2)
    stk.wait_for_logs(
        [
            "Detected reorg",
            f"Vault deposit '{deposit}' is already unconfirmed",
            "Rescan of all vaults in db done.",
            f"Vault at {deposit} is now confirmed",
        ]
    )
    assert stk.rpc.listvaults()["vaults"][0]["status"] == "funded"

    # Now try to completely evict it from the chain with a 6-blocks reorg. We
    # should mark it as unconfirmed (but it's not the same codepath).
    bitcoind.simple_reorg(vault["blockheight"] + 3 + 2, shift=-1)
    stk.wait_for_logs(
        [
            "Detected reorg",
            f"Vault deposit '{deposit}' ended up without confirmation",
            "Rescan of all vaults in db done.",
        ]
    )
    assert stk.rpc.listvaults()["vaults"][0]["status"] == "unconfirmed"


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_reorged_deposit_status(revault_network, bitcoind):
    # A csv of 2 because bitcoind would discard updating the mempool if the reorg is >10
    # blocks long.
    revault_network.deploy(4, 2, csv=2)
    vault = revault_network.fund(0.14)
    revault_network.secure_vault(vault)
    deposit = f"{vault['txid']}:{vault['vout']}"

    # Reorg the deposit. This should not affect us as the transaction did not
    # shift
    bitcoind.simple_reorg(vault["blockheight"])
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        w.wait_for_logs(
            [
                "Detected reorg",
                # 7 because simple_reorg() adds a block
                f"Vault deposit '{deposit}' still has '7' confirmations",
            ]
        )

    # Now actually shift it (7 + 1 - 3 == 5)
    bitcoind.simple_reorg(vault["blockheight"], shift=3)
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault deposit '{deposit}' ended up with '5' confirmations",
                "Rescan of all vaults in db done.",
            ]
        )
        wait_for(lambda: len(w.rpc.listvaults(["unconfirmed"], [deposit])) == 1)

    # All presigned transactions must have been removed from the db,
    # if we get it confirmed again, it will re-create the pre-signed
    # transactions. But they are the very same than previously to the
    # signatures on the coordinator are still valid therefore the signature
    # fetcher thread will add them all and the vault will be back to 'secured'
    # again
    bitcoind.generate_block(1)
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        w.wait_for_secured_vaults([deposit])

    # TODO: eventually try with tx malleation

    # Now do the same dance with the 'active' status
    revault_network.activate_vault(vault)
    bitcoind.simple_reorg(vault["blockheight"] + 3)
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        w.wait_for_logs(
            [
                "Detected reorg",
                # 7 because simple_reorg() adds a block
                f"Vault deposit '{deposit}' still has '7' confirmations",
            ]
        )
    bitcoind.simple_reorg(vault["blockheight"] + 3, shift=3)
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault deposit '{deposit}' ended up with '5' confirmations",
                "Rescan of all vaults in db done.",
            ]
        )
        wait_for(lambda: len(w.rpc.listvaults(["unconfirmed"], [deposit])) > 0)
    bitcoind.generate_block(1)
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        w.wait_for_active_vaults([deposit])

    # If we are stopped during the reorg, we recover in the same way at startup
    revault_network.stop_wallets()
    bitcoind.simple_reorg(vault["blockheight"] + 3 + 3)
    revault_network.start_wallets()
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        w.wait_for_logs(
            [
                "Detected reorg",
                # 7 because simple_reorg() adds a block
                f"Vault deposit '{deposit}' still has '7' confirmations",
            ]
        )

    revault_network.stop_wallets()
    bitcoind.simple_reorg(vault["blockheight"] + 3 + 3, shift=3)
    revault_network.start_wallets()
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault deposit '{deposit}' ended up with '5' confirmations",
                "Rescan of all vaults in db done.",
            ]
        )
        wait_for(lambda: len(w.rpc.listvaults(["unconfirmed"], [deposit])) > 0)
    revault_network.stop_wallets()
    bitcoind.generate_block(1)
    revault_network.start_wallets()
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        w.wait_for_active_vaults([deposit])

    # Now do the same dance with a spent vault

    # Keep track of the deposit transaction for later use as we'll reorg deeply enough that
    # bitcoind won't add the transactions back to mempool.
    deposit_tx = revault_network.stk_wallets[0].rpc.listonchaintransactions([deposit])[
        "onchain_transactions"
    ][0]["deposit"]["hex"]

    # If the deposit is not unconfirmed, it's fine
    revault_network.spend_vaults_anyhow([vault])
    for w in revault_network.man_wallets:
        assert len(w.rpc.listspendtxs()["spend_txs"]) == 1
    bitcoind.simple_reorg(vault["blockheight"] + 3 + 3 + 3)
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault deposit '{deposit}' still has .* confirmations",
                "Rescan of all vaults in db done.",
            ]
        )

    # If it is then we'll mark it back as unvaulting
    bitcoind.simple_reorg(vault["blockheight"] + 3 + 3 + 3, shift=-1)
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault deposit '{deposit}' ended up without confirmation",
                "Rescan of all vaults in db done.",
            ]
        )
        wait_for(lambda: len(w.rpc.listvaults(["unvaulting"])["vaults"]) == 1)

    # Now the same dance with a canceled vault

    # Re-confirm the vault, get it active, then unvault and cancel it.
    bitcoind.rpc.sendrawtransaction(deposit_tx)
    bitcoind.generate_block(1, wait_for_mempool=2)
    vault = revault_network.stk_wallets[0].rpc.listvaults(
        # NB: 'unvaulting' because we reuse a vault that was previously spent! (ie
        # the Spend transaction is in the walelt and therefore we don't keep track
        # of the Unvault confirmation)
        ["unvaulting"]
    )["vaults"][0]
    revault_network.cancel_vault(vault)

    # If the deposit is not unconfirmed, nothing changes
    bitcoind.simple_reorg(vault["blockheight"], shift=2)
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault deposit '{deposit}' still has .* confirmations",
                "Rescan of all vaults in db done.",
            ]
        )

    # If it is then it'll be marked as 'canceling'
    bitcoind.simple_reorg(vault["blockheight"] + 2, shift=-1)
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault deposit '{deposit}' ended up without confirmation",
                "Rescan of all vaults in db done.",
            ]
        )
        wait_for(lambda: len(w.rpc.listvaults(["canceling"])["vaults"]) == 1)


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_reorged_unvault(revault_network, bitcoind):
    revault_network.deploy(4, 2, csv=12)
    man = revault_network.man_wallets[0]
    vaults = revault_network.fundmany([32, 3])
    deposits = []
    amounts = []
    for v in vaults:
        revault_network.secure_vault(v)
        revault_network.activate_vault(v)
        deposits.append(f"{v['txid']}:{v['vout']}")
        amounts.append(v["amount"])

    addr = bitcoind.rpc.getnewaddress()
    amount = sum(amounts)
    feerate = 1
    fee = revault_network.compute_spendtx_fees(feerate, len(vaults), 1)
    destinations = {addr: amount - fee}
    revault_network.unvault_vaults(vaults, destinations, feerate)

    unvault_tx_a = man.rpc.listonchaintransactions([deposits[0]])[
        "onchain_transactions"
    ][0]["unvault"]
    unvault_tx_b = man.rpc.listonchaintransactions([deposits[1]])[
        "onchain_transactions"
    ][0]["unvault"]

    # If the Unvault moves but it still confirmed, everything is fine :tm:
    assert unvault_tx_a["blockheight"] == unvault_tx_b["blockheight"]
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        assert len(w.rpc.listvaults(["unvaulted"], deposits)["vaults"]) == len(deposits)
    bitcoind.simple_reorg(unvault_tx_a["blockheight"], shift=1)
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault {deposits[0]}'s Unvault transaction is still confirmed",
                f"Vault {deposits[1]}'s Unvault transaction is still confirmed",
                "Rescan of all vaults in db done.",
            ]
        )
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        assert len(w.rpc.listvaults(["unvaulted"], deposits)["vaults"]) == len(deposits)

    # If it's not confirmed anymore, we'll detect it and mark the vault as unvaulting
    bitcoind.simple_reorg(unvault_tx_a["blockheight"] + 1, shift=-1)
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault {deposits[0]}'s Unvault transaction .* got unconfirmed",
                f"Vault {deposits[1]}'s Unvault transaction .* got unconfirmed",
                "Rescan of all vaults in db done.",
            ]
        )
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        assert len(w.rpc.listvaults(["unvaulting"], deposits)["vaults"]) == len(
            deposits
        )

    # Now if we are spending
    # unvault_vault() above actually registered the Spend transaction, so we can activate
    # it by generating enough block for it to be mature.
    bitcoind.generate_block(1, wait_for_mempool=len(vaults))
    bitcoind.generate_block(revault_network.csv - 1)
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        wait_for(
            lambda: len(w.rpc.listvaults(["spending"], deposits)["vaults"])
            == len(deposits)
        )

    # If we are 'spending' and the Unvault gets unconfirmed, it'll get marked for
    # re-broadcast
    bitcoind.simple_reorg(unvault_tx_a["blockheight"] + 1, shift=-1)
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault {deposits[0]}'s Unvault transaction .* got unconfirmed",
                f"Vault {deposits[1]}'s Unvault transaction .* got unconfirmed",
                "Rescan of all vaults in db done.",
            ]
        )
    # NOTE: it will stay in the 'unvaulting' state until it can finally gets marked as
    # 'spending' (ie once the Spend transaction is valid and can be in mempool). That's
    # because bitcoind's wallet will consider the Unvault at spent even if it's actually
    # 'spent' by a yet-invalid transaction, and this prevents us to track confirmation.
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulting"], deposits)["vaults"])
            == len(deposits)
        )
    bitcoind.generate_block(1, wait_for_mempool=len(vaults))
    bitcoind.generate_block(revault_network.csv - 1)
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        wait_for(
            lambda: len(w.rpc.listvaults(["spending"], deposits)["vaults"])
            == len(deposits)
        )
    bitcoind.generate_block(1, wait_for_mempool=1)
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        wait_for(
            lambda: len(w.rpc.listvaults(["spent"], deposits)["vaults"])
            == len(deposits)
        )

    # If we are 'spent' and the Unvault gets unconfirmed, it'll get marked for
    # re-broadcast
    blockheight = bitcoind.rpc.getblockcount()
    bitcoind.simple_reorg(blockheight, shift=-1)
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault {deposits[0]}'s Spend transaction .* got unconfirmed",
                f"Vault {deposits[1]}'s Spend transaction .* got unconfirmed",
                "Rescan of all vaults in db done.",
            ]
        )
    bitcoind.generate_block(1, wait_for_mempool=1)
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        wait_for(
            lambda: len(w.rpc.listvaults(["spent"], deposits)["vaults"])
            == len(deposits)
        )


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_reorged_cancel(revault_network, bitcoind):
    revault_network.deploy(4, 2, csv=12)
    stks = revault_network.stk_wallets
    mans = revault_network.man_wallets
    vault = revault_network.fund(32)
    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)
    deposit = f"{vault['txid']}:{vault['vout']}"
    amount = vault["amount"]

    addr = bitcoind.rpc.getnewaddress()
    feerate = 1
    fee = revault_network.compute_spendtx_fees(feerate, 1, 1)
    destinations = {addr: amount - fee}
    revault_network.unvault_vaults([vault], destinations, feerate)
    unvault_tx = mans[0].rpc.listonchaintransactions([deposit])["onchain_transactions"][
        0
    ]["unvault"]

    # Now let's cancel the spending
    revault_network.cancel_vault(vault)
    cancel_tx = mans[0].rpc.listonchaintransactions([deposit])["onchain_transactions"][
        0
    ]["cancel"]

    # Reorging, but not unconfirming the cancel
    bitcoind.simple_reorg(cancel_tx["blockheight"])
    for w in stks + mans:
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault {deposit}'s Cancel transaction is still confirmed",
                "Rescan of all vaults in db done.",
            ]
        )

    # Let's unconfirm the cancel and check that the vault is now in 'canceling' state
    bitcoind.simple_reorg(cancel_tx["blockheight"], shift=-1)
    for w in stks + mans:
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault {deposit}'s Cancel transaction .* got unconfirmed",
                "Rescan of all vaults in db done.",
            ]
        )
    for w in stks + mans:
        wait_for(
            lambda: w.rpc.listvaults([], [deposit])["vaults"][0]["status"]
            == "canceling"
        )

    # Confirming the cancel again
    bitcoind.generate_block(1, wait_for_mempool=1)
    for w in stks + mans:
        w.wait_for_log("Cancel tx .* was confirmed at height .*")
        wait_for(
            lambda: w.rpc.listvaults([], [deposit])["vaults"][0]["status"] == "canceled"
        )

    # Let's unconfirm the unvault
    bitcoind.simple_reorg(unvault_tx["blockheight"], shift=-1)
    for w in stks + mans:
        w.wait_for_log(f"Vault {deposit}'s Unvault transaction .* got unconfirmed")

    # Here we go canceling everything again
    bitcoind.generate_block(1, wait_for_mempool=2)
    for w in stks + mans:
        w.wait_for_logs(
            [
                "Unvault transaction at .* is now being canceled",
                "Cancel tx .* was confirmed",
            ]
        )
        wait_for(
            lambda: w.rpc.listvaults([], [deposit])["vaults"][0]["status"] == "canceled"
        )


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_getspendtx(revault_network, bitcoind):
    revault_network.deploy(2, 1)
    man = revault_network.man_wallets[0]
    amount = 32.67890
    vault = revault_network.fund(amount)
    deposit = f"{vault['txid']}:{vault['vout']}"

    addr = bitcoind.rpc.getnewaddress()
    spent_vaults = [deposit]
    feerate = 2
    fees = revault_network.compute_spendtx_fees(feerate, len(spent_vaults), 1)
    destination = {addr: vault["amount"] - fees}

    revault_network.secure_vault(vault)

    # If the vault isn't active, it'll fail
    with pytest.raises(RpcError, match="Invalid vault status"):
        man.rpc.getspendtx(spent_vaults, destination, feerate)

    revault_network.activate_vault(vault)

    # If we are not a manager, it'll fail
    with pytest.raises(RpcError, match="This is a manager command"):
        revault_network.stk_wallets[0].rpc.getspendtx(
            spent_vaults, destination, feerate
        )

    # The amount was not enough to afford a change output, everything went to
    # fees.
    psbt = serializations.PSBT()
    psbt.deserialize(man.rpc.getspendtx(spent_vaults, destination, feerate)["spend_tx"])
    assert len(psbt.inputs) == 1 and len(psbt.outputs) == 2

    # But if we decrease it enough, it'll create a change output
    destinations = {addr: vault["amount"] - fees - 1_000_000}
    psbt = serializations.PSBT()
    psbt.deserialize(
        man.rpc.getspendtx(spent_vaults, destinations, feerate)["spend_tx"]
    )
    assert len(psbt.inputs) == 1 and len(psbt.outputs) == 3

    # Asking for an impossible feerate will error
    with pytest.raises(
        RpcError,
        match="Required feerate .* is significantly higher than actual feerate",
    ):
        man.rpc.getspendtx(spent_vaults, destinations, 100_000)

    # We'll stubbornly refuse they shoot themselves in the foot
    with pytest.raises(
        RpcError,
        match="Fees larger than 20000000 sats",
    ):
        destinations = {addr: vault["amount"] // 10}
        man.rpc.getspendtx(spent_vaults, destinations, 100_000)

    # We can spend many vaults
    deposits = [deposit]
    amounts = [vault["amount"]]
    for _ in range(10):
        amount = round(random.random() * 10 ** 8 % 50, 7)
        vault = revault_network.fund(amount)
        revault_network.secure_vault(vault)
        revault_network.activate_vault(vault)

        deposit = f"{vault['txid']}:{vault['vout']}"
        amount_sat = vault["amount"]
        deposits.append(deposit)
        amounts.append(amount_sat)

        # Note that it passes even with 100k/vb if you disable insane fees
        # sanity checks :)
        feerate = random.randint(1, 10_000)
        sent_amount = sum(amounts) - revault_network.compute_spendtx_fees(
            feerate, len(deposits), 1
        )
        destinations = {addr: sent_amount}
        psbt = serializations.PSBT()
        psbt.deserialize(
            man.rpc.getspendtx(deposits, destinations, feerate)["spend_tx"]
        )
        assert (
            len(psbt.inputs) == len(deposits) and len(psbt.outputs) == 2
        ), "unexpected change output"

    # And we can spend to many destinations
    deposits = [deposit]
    destinations = {}
    for _ in range(10):
        feerate = random.randint(1, 1_000)
        destinations[bitcoind.rpc.getnewaddress()] = vault["amount"] // 20
        psbt = serializations.PSBT()
        psbt.deserialize(
            man.rpc.getspendtx(deposits, destinations, feerate)["spend_tx"]
        )
        assert (
            len(psbt.inputs) == len(deposits)
            # destinations + CPFP + change
            and len(psbt.outputs) == len(destinations.keys()) + 1 + 1
        ), "expected a change output"

    # And we can do both
    deposits = []
    destinations = {}
    for vault in man.rpc.listvaults(["active"])["vaults"]:
        deposits.append(f"{vault['txid']}:{vault['vout']}")
        destinations[bitcoind.rpc.getnewaddress()] = vault["amount"] // 2
    psbt = serializations.PSBT()
    psbt.deserialize(man.rpc.getspendtx(deposits, destinations, feerate)["spend_tx"])
    assert (
        len(psbt.inputs) == len(deposits)
        # destinations + CPFP + change
        and len(psbt.outputs) == len(destinations.keys()) + 1 + 1
    ), "expected a change output"

    # We can't create an insanely large transaction
    destinations = {bitcoind.rpc.getnewaddress(): 200_001 for _ in range(10_000)}
    with pytest.raises(
        RpcError,
        match="Transaction too large: satisfied it could be >400k weight units",
    ):
        man.rpc.getspendtx(deposits, destinations, feerate)


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_spendtx_management(revault_network, bitcoind):
    CSV = 12
    revault_network.deploy(2, 1, csv=CSV)
    man = revault_network.man_wallets[0]
    amount = 0.24
    vault = revault_network.fund(amount)
    deposit = f"{vault['txid']}:{vault['vout']}"

    addr = bitcoind.rpc.getnewaddress()
    spent_vaults = [deposit]
    feerate = 2
    fees = revault_network.compute_spendtx_fees(feerate, len(spent_vaults), 1)
    destination = {addr: vault["amount"] - fees}

    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)

    spend_tx = man.rpc.getspendtx(spent_vaults, destination, feerate)["spend_tx"]

    # If we are not a manager, it'll fail
    with pytest.raises(RpcError, match="This is a manager command"):
        revault_network.stk_wallets[0].rpc.updatespendtx(spend_tx)

    # It will not accept a spend_tx which spends an unknown Unvault
    psbt = serializations.PSBT()
    psbt.deserialize(spend_tx)
    psbt.tx.vin[0].prevout.hash = 0
    insane_spend_tx = psbt.serialize()
    with pytest.raises(RpcError, match="Spend transaction refers an unknown Unvault"):
        man.rpc.updatespendtx(insane_spend_tx)

    # First time, it'll be stored
    man.rpc.updatespendtx(spend_tx)
    man.wait_for_log("Storing new Spend transaction")
    # We can actually update it no matter if it's the same
    man.rpc.updatespendtx(spend_tx)
    man.wait_for_log("Updating Spend transaction")

    assert len(man.rpc.listspendtxs()["spend_txs"]) == 1

    # If we delete it..
    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx)
    spend_psbt.tx.calc_sha256()
    man.rpc.delspendtx(spend_psbt.tx.hash)
    assert len(man.rpc.listspendtxs()["spend_txs"]) == 0
    # When we update it it'll be treated as a new transaction
    man.rpc.updatespendtx(spend_tx)
    man.wait_for_log("Storing new Spend transaction")
    assert len(man.rpc.listspendtxs()["spend_txs"]) == 1

    # Create another Spend transaction spending two vaults
    vault_b = revault_network.fund(amount)
    deposit_b = f"{vault_b['txid']}:{vault_b['vout']}"
    addr_b = bitcoind.rpc.getnewaddress()
    spent_vaults = [deposit, deposit_b]
    feerate = 50
    fees = revault_network.compute_spendtx_fees(feerate, len(spent_vaults), 2)
    destination = {
        addr: (vault_b["amount"] - fees) // 2,
        addr_b: (vault_b["amount"] - fees) // 2,
    }
    revault_network.secure_vault(vault_b)
    revault_network.activate_vault(vault_b)
    spend_tx_b = man.rpc.getspendtx(spent_vaults, destination, feerate)["spend_tx"]
    man.rpc.updatespendtx(spend_tx_b)
    man.wait_for_log("Storing new Spend transaction")
    assert len(man.rpc.listspendtxs()["spend_txs"]) == 2
    assert {
        "deposit_outpoints": [deposit],
        "psbt": spend_tx,
    } in man.rpc.listspendtxs()["spend_txs"]
    assert {
        "deposit_outpoints": [deposit, deposit_b],
        "psbt": spend_tx_b,
    } in man.rpc.listspendtxs()["spend_txs"]

    # Now we could try to broadcast it..
    # But we couldn't broadcast a random txid
    with pytest.raises(RpcError, match="Unknown Spend transaction"):
        man.rpc.setspendtx(
            "d5eb741a31ebf4d2f5d6ae223900f1bd996e209150d3604fca7d9fa5d6136337"
        )

    # ..And even with an existing one we would have to sign it beforehand!
    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx_b)
    spend_psbt.tx.calc_sha256()
    with pytest.raises(
        RpcError, match="Error checking Spend transaction signature: 'Missing signature"
    ):
        man.rpc.setspendtx(spend_psbt.tx.hash)

    deriv_indexes = [vault["derivation_index"], vault_b["derivation_index"]]
    for man in revault_network.man_wallets:
        spend_tx_b = man.man_keychain.sign_spend_psbt(spend_tx_b, deriv_indexes)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx_b)
    spend_psbt.tx.calc_sha256()
    spend_tx_b = spend_psbt.serialize()
    man.rpc.updatespendtx(spend_tx_b)
    man.rpc.setspendtx(spend_psbt.tx.hash)

    # Of course, Cosigning Servers will cringe if we poll them twice.
    with pytest.raises(
        RpcError,
        match="One of the Cosigning Server already signed a Spend transaction spending one of these vaults",
    ):
        man.rpc.setspendtx(spend_psbt.tx.hash)

    # It gets marked as in the process of being unvaulted immediately (next bitcoind
    # poll), and will get marked as succesfully unvaulted after a single confirmation.
    wait_for(
        lambda: all(
            v["status"] == "unvaulting"
            for v in man.rpc.listvaults([], spent_vaults)["vaults"]
        )
    )
    man.wait_for_logs(
        [
            f"The deposit utxo created via '{deposit}' was unvaulted"
            for deposit in spent_vaults
        ]
    )
    bitcoind.generate_block(1, wait_for_mempool=len(spent_vaults))
    wait_for(
        lambda: all(
            v["status"] == "unvaulted"
            for v in man.rpc.listvaults([], spent_vaults)["vaults"]
        )
    )

    # We'll broadcast the Spend transaction as soon as it's valid
    bitcoind.generate_block(CSV - 1)
    man.wait_for_log(f"Succesfully broadcasted Spend tx '{spend_psbt.tx.hash}'")
    wait_for(
        lambda: all(
            v["status"] == "spending"
            for v in man.rpc.listvaults([], spent_vaults)["vaults"]
        )
    )


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_spends_concurrent(revault_network, bitcoind):
    """
    Here we test the creation and succesful broadcast of both Spend transaction
    concurrently handled but non conflicting.
    """
    CSV = 1024
    revault_network.deploy(3, 2, csv=CSV)
    man = revault_network.man_wallets[1]
    # FIXME: there is something up with higher number and the test framework fee
    # computation
    amounts = [0.22, 16, 3, 21]
    vaults = revault_network.fundmany(amounts)
    # Edge case: bitcoind can actually mess up with the amounts
    amounts = []
    deposits = []
    deriv_indexes = []
    for v in vaults:
        revault_network.secure_vault(v)
        revault_network.activate_vault(v)
        deposits.append(f"{v['txid']}:{v['vout']}")
        deriv_indexes.append(v["derivation_index"])
        amounts.append(v["amount"])

    (deposits_a, deposits_b) = (deposits[:2], deposits[2:])
    (amounts_a, amounts_b) = (amounts[:2], amounts[2:])
    (indexes_a, indexes_b) = (deriv_indexes[:2], deriv_indexes[2:])

    # Spending to a P2WSH (effectively a change but hey), with a change output
    destinations = {man.rpc.getdepositaddress()["address"]: sum(amounts_a) // 2}
    spend_tx_a = man.rpc.getspendtx(deposits_a, destinations, 1)["spend_tx"]
    for man in revault_network.man_wallets:
        spend_tx_a = man.man_keychain.sign_spend_psbt(spend_tx_a, indexes_a)
    man.rpc.updatespendtx(spend_tx_a)

    # Spending to a P2WPKH, with a change output
    destinations = {bitcoind.rpc.getnewaddress(): sum(amounts_b) // 2}
    spend_tx_b = man.rpc.getspendtx(deposits_b, destinations, 1)["spend_tx"]
    for man in revault_network.man_wallets:
        spend_tx_b = man.man_keychain.sign_spend_psbt(spend_tx_b, indexes_b)
    man.rpc.updatespendtx(spend_tx_b)

    # Of course, we can just stop and still broadcast the Spend
    man.stop()
    man.proc.wait(10)
    man.start()

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx_a)
    spend_psbt.tx.calc_sha256()
    spend_txid_a = spend_psbt.tx.hash
    man.rpc.setspendtx(spend_txid_a)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx_b)
    spend_psbt.tx.calc_sha256()
    spend_txid_b = spend_psbt.tx.hash
    man.rpc.setspendtx(spend_txid_b)

    for w in revault_network.stk_wallets + revault_network.man_wallets:
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulting"], deposits)["vaults"])
            == len(deposits)
        )
        w.wait_for_logs(
            [
                f"The deposit utxo created via '{deposit}' was unvaulted"
                for deposit in deposits
            ]
        )
    # We need a single confirmation to consider the Unvault transaction confirmed
    bitcoind.generate_block(1, wait_for_mempool=len(deposits))
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulted"], deposits)["vaults"])
            == len(deposits)
        )

    # We'll broadcast the Spend transaction as soon as it's valid
    bitcoind.generate_block(CSV - 1)
    man.wait_for_logs(
        [
            f"Succesfully broadcasted Spend tx '{spend_txid_a}'",
            f"Succesfully broadcasted Spend tx '{spend_txid_b}'",
        ]
    )
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        wait_for(
            lambda: len(w.rpc.listvaults(["spending"], deposits)["vaults"])
            == len(deposits)
        )

    # And will mark it as spent after a single confirmation of the Spend tx
    bitcoind.generate_block(1, wait_for_mempool=[spend_txid_a, spend_txid_b])
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        wait_for(
            lambda: len(w.rpc.listvaults(["spent"], deposits)["vaults"])
            == len(deposits)
        )


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_spends_conflicting(revault_network, bitcoind):
    """
    Here we test two spends which spends 2 vaults each, with one shared and all vaults
    being created from the same Deposit transaction.
    """
    # Get some more coins
    bitcoind.generate_block(12)

    CSV = 112
    revault_network.deploy(5, 3, csv=CSV)
    man = revault_network.man_wallets[0]
    amounts = [0.1, 64, 410]
    vaults = revault_network.fundmany(amounts)
    assert len(vaults) == len(amounts)
    # Edge case: bitcoind can actually mess up with the amounts
    amounts = []
    deposits = []
    deriv_indexes = []
    for v in vaults:
        revault_network.secure_vault(v)
        revault_network.activate_vault(v)
        deposits.append(f"{v['txid']}:{v['vout']}")
        deriv_indexes.append(v["derivation_index"])
        amounts.append(v["amount"])

    (deposits_a, deposits_b) = (deposits[:2], deposits[1:])
    (amounts_a, amounts_b) = (amounts[:2], amounts[1:])
    (indexes_a, indexes_b) = (deriv_indexes[:2], deriv_indexes[1:])

    feerate = 5_000
    fees = revault_network.compute_spendtx_fees(feerate, len(deposits_a), 1)
    destinations = {bitcoind.rpc.getnewaddress(): sum(amounts_a) - fees}
    spend_tx_a = man.rpc.getspendtx(deposits_a, destinations, 1)["spend_tx"]
    for man in revault_network.man_wallets:
        spend_tx_a = man.man_keychain.sign_spend_psbt(spend_tx_a, indexes_a)
    man.rpc.updatespendtx(spend_tx_a)

    feerate = 10_000
    fees = revault_network.compute_spendtx_fees(feerate, len(deposits_b), 1, True)
    destinations = {bitcoind.rpc.getnewaddress(): (sum(amounts_b) - fees) // 2}
    spend_tx_b = man.rpc.getspendtx(deposits_b, destinations, 1)["spend_tx"]
    for man in revault_network.man_wallets:
        spend_tx_b = man.man_keychain.sign_spend_psbt(spend_tx_b, indexes_b)
    man.rpc.updatespendtx(spend_tx_b)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx_a)
    spend_psbt.tx.calc_sha256()
    spend_txid_a = spend_psbt.tx.hash
    man.rpc.setspendtx(spend_txid_a)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx_b)
    spend_psbt.tx.calc_sha256()
    with pytest.raises(
        RpcError,
        match="One of the Cosigning Server already signed a Spend transaction spending one of these vaults",
    ):
        man.rpc.setspendtx(spend_psbt.tx.hash)

    wait_for(
        lambda: len(man.rpc.listvaults(["unvaulting"], deposits_a)["vaults"])
        == len(deposits_a)
    )
    man.wait_for_logs(
        [
            f"The deposit utxo created via '{deposit}' was unvaulted"
            for deposit in deposits_a
        ]
    )
    # We need a single confirmation to consider the Unvault transaction confirmed
    bitcoind.generate_block(1, wait_for_mempool=len(deposits_a))
    wait_for(
        lambda: len(man.rpc.listvaults(["unvaulted"], deposits_a)["vaults"])
        == len(deposits_a)
    )

    # We'll broadcast the Spend transaction as soon as it's valid
    bitcoind.generate_block(CSV - 1)
    man.wait_for_log(
        f"Succesfully broadcasted Spend tx '{spend_txid_a}'",
    )
    wait_for(
        lambda: len(man.rpc.listvaults(["spending"], deposits_a)["vaults"])
        == len(deposits_a)
    )

    # And will mark it as spent after a single confirmation of the Spend tx
    bitcoind.generate_block(1, wait_for_mempool=[spend_txid_a])
    wait_for(
        lambda: len(man.rpc.listvaults(["spent"], deposits)["vaults"])
        == len(deposits_a)
    )


# FIXME: exchange of signatures with the cosigning server gets too large too quickly
# See https://github.com/revault/practical-revault/issues/81
@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_large_spends(revault_network, bitcoind, executor):
    CSV = 2016  # 2 weeks :tm:
    revault_network.deploy(9, 4, csv=CSV)
    man = revault_network.man_wallets[0]

    deposits = []
    deriv_indexes = []
    total_amount = 0
    for _ in range(15):
        amount = random.randint(5, 5000) / 100
        vault = revault_network.fund(amount)
        revault_network.secure_vault(vault)
        revault_network.activate_vault(vault)
        deposits.append(f"{vault['txid']}:{vault['vout']}")
        deriv_indexes.append(vault["derivation_index"])
        total_amount += vault["amount"]

    feerate = 1
    n_outputs = random.randint(1, 5)
    fees = revault_network.compute_spendtx_fees(feerate, len(deposits), n_outputs)
    destinations = {
        bitcoind.rpc.getnewaddress(): (total_amount - fees) // n_outputs
        for _ in range(n_outputs)
    }
    spend_tx = man.rpc.getspendtx(deposits, destinations, feerate)["spend_tx"]

    for man in revault_network.man_wallets:
        spend_tx = man.man_keychain.sign_spend_psbt(spend_tx, deriv_indexes)
    man.rpc.updatespendtx(spend_tx)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx)
    spend_psbt.tx.calc_sha256()
    man.rpc.setspendtx(spend_psbt.tx.hash)

    wait_for(
        lambda: len(man.rpc.listvaults(["unvaulting"], deposits)["vaults"])
        == len(deposits)
    )
    man.wait_for_logs(
        [
            f"The deposit utxo created via '{deposit}' was unvaulted"
            for deposit in deposits
        ]
    )
    # We need a single confirmation to consider the Unvault transaction confirmed
    bitcoind.generate_block(1, wait_for_mempool=len(deposits))
    wait_for(
        lambda: len(man.rpc.listvaults(["unvaulted"], deposits)["vaults"])
        == len(deposits)
    )

    # We'll broadcast the Spend transaction as soon as it's valid
    bitcoind.generate_block(CSV - 1)
    man.wait_for_log(
        f"Succesfully broadcasted Spend tx '{spend_psbt.tx.hash}'",
    )
    wait_for(
        lambda: len(man.rpc.listvaults(["spending"], deposits)["vaults"])
        == len(deposits)
    )

    # And will mark it as spent after a single confirmation of the Spend tx
    bitcoind.generate_block(1, wait_for_mempool=[spend_psbt.tx.hash])
    wait_for(
        lambda: len(man.rpc.listvaults(["spent"], deposits)["vaults"]) == len(deposits)
    )


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_revault_command(revault_network, bitcoind, executor):
    """
    Here we manually broadcast the unvualt_tx, followed by the cancel_tx
    """
    revault_network.deploy(3, 1)
    man = revault_network.man_wallets[0]
    stks = revault_network.stk_wallets
    vault = revault_network.fund(18)
    deposit = f"{vault['txid']}:{vault['vout']}"

    # Can't cancel an unconfirmed deposit
    with pytest.raises(
        RpcError, match="Invalid vault status: 'funded'. Need 'unvaulting'"
    ):
        stks[0].rpc.revault(deposit)

    # A manager gets the same error: both parties can revault
    with pytest.raises(
        RpcError, match="Invalid vault status: 'funded'. Need 'unvaulting'"
    ):
        man.rpc.revault(deposit)
    revault_network.secure_vault(vault)

    # Secured is not good enough though
    with pytest.raises(
        RpcError, match="Invalid vault status: 'secured'. Need 'unvaulting'"
    ):
        stks[0].rpc.revault(deposit)
    revault_network.activate_vault(vault)

    # Active? Not enough!
    with pytest.raises(
        RpcError, match="Invalid vault status: 'active'. Need 'unvaulting'"
    ):
        stks[0].rpc.revault(deposit)

    # Now we want to broadcast the unvault tx without having an associated spend tx
    # First of all, we need the unvault psbt finalized
    unvault_psbt = stks[0].rpc.listpresignedtransactions([deposit])[
        "presigned_transactions"
    ][0]["unvault"]["psbt"]
    unvault_tx = bitcoind.rpc.finalizepsbt(unvault_psbt)["hex"]
    bitcoind.rpc.sendrawtransaction(unvault_tx)

    # Unvaulting! And there's no associated spend tx! Is revault broken?
    for w in stks + [man]:
        wait_for(
            lambda: w.rpc.listvaults([], [deposit])["vaults"][0]["status"]
            == "unvaulting"
        )

    # Nah it's not, just broadcast the cancel
    man.rpc.revault(deposit)

    # Not confirmed yet...
    for w in stks + [man]:
        w.wait_for_log("Unvault transaction at .* is now being canceled")
        wait_for(
            lambda: w.rpc.listvaults([], [deposit])["vaults"][0]["status"]
            == "canceling"
        )
    bitcoind.generate_block(1, wait_for_mempool=1)

    # Funds are safe, we happy
    for w in stks + [man]:
        wait_for(lambda: w.rpc.call("getinfo")["blockheight"] == 108)
        w.wait_for_log("Cancel tx .* was confirmed at height '108'")
        wait_for(
            lambda: w.rpc.listvaults([], [deposit])["vaults"][0]["status"] == "canceled"
        )

    # Now, do the same process with two new vaults (thus with different derivation indexes)
    # at the same time, and with the Unvault not being mined yet
    vault_a = revault_network.fund(12)
    vault_b = revault_network.fund(0.4)

    revault_network.secure_vault(vault_a)
    revault_network.secure_vault(vault_b)

    revault_network.activate_vault(vault_a)
    revault_network.activate_vault(vault_b)

    for v in [vault_a, vault_b]:
        deposit = f"{v['txid']}:{v['vout']}"
        unvault_tx = man.rpc.listpresignedtransactions([deposit])[
            "presigned_transactions"
        ][0]["unvault"]["hex"]
        bitcoind.rpc.sendrawtransaction(unvault_tx)

        # On purpose, only wait for the one we want to revault with, to trigger some race conditions
        wait_for(
            lambda: len(stks[0].rpc.listvaults(["unvaulting"], [deposit])["vaults"])
            == 1
        )
        stks[0].rpc.revault(deposit)

    for w in stks + [man]:
        wait_for(lambda: len(stks[0].rpc.listvaults(["canceling"])["vaults"]) == 2)
    bitcoind.generate_block(1, wait_for_mempool=4)
    for w in stks + [man]:
        # 3 cause the first part of the test already had one canceled.
        wait_for(lambda: len(stks[0].rpc.listvaults(["canceled"])["vaults"]) == 3)

    # We have as many new deposits as canceled vaults
    bitcoind.generate_block(6)
    wait_for(
        lambda: len(stks[0].rpc.listvaults(["canceled"])["vaults"])
        == len(stks[0].rpc.listvaults(["funded"])["vaults"])
    )

    # And the deposit txid is the Cancel txid
    for v in stks[0].rpc.listvaults(["canceled"])["vaults"]:
        deposit = f"{v['txid']}:{v['vout']}"
        cancel_psbt = serializations.PSBT()
        cancel_b64 = stks[0].rpc.listpresignedtransactions([deposit])[
            "presigned_transactions"
        ][0]["cancel"]["psbt"]
        cancel_psbt.deserialize(cancel_b64)

        cancel_psbt.tx.calc_sha256()
        cancel_txid = cancel_psbt.tx.hash
        new_deposits = stks[0].rpc.listvaults(["funded"])["vaults"]
        assert cancel_txid in [v["txid"] for v in new_deposits]


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_revaulted_spend(revault_network, bitcoind, executor):
    """
    Revault an ongoing Spend transaction carried out by the managers, under misc
    circumstances.
    """
    CSV = 12
    revault_network.deploy(2, 2, csv=CSV)
    mans = revault_network.man_wallets
    stks = revault_network.stk_wallets

    # Simple case. Managers Spend a single vault.
    vault = revault_network.fund(0.05)
    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)

    revault_network.spend_vaults_anyhow_unconfirmed([vault])
    revault_network.cancel_vault(vault)

    # Managers spend two vaults, both are canceled.
    vaults = [revault_network.fund(0.05), revault_network.fund(0.1)]
    for v in vaults:
        revault_network.secure_vault(v)
        revault_network.activate_vault(v)

    revault_network.unvault_vaults_anyhow(vaults)
    for vault in vaults:
        revault_network.cancel_vault(vault)

    # Managers spend three vaults, only a single one is canceled. And both of them were
    # created in the same deposit transaction.
    vaults = revault_network.fundmany([0.2, 0.08])
    vaults.append(revault_network.fund(0.03))
    for v in vaults:
        revault_network.secure_vault(v)
        revault_network.activate_vault(v)
    revault_network.unvault_vaults_anyhow(vaults)
    revault_network.cancel_vault(vaults[0])

    # vaults[0] is canceled, therefore the Spend transaction is now invalid. The vaults
    # should be marked as unvaulted since they are not being spent anymore.
    deposits = [f"{v['txid']}:{v['vout']}" for v in vaults[1:]]
    for w in mans + stks:
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulted"], deposits)["vaults"])
            == len(deposits)
        )


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_retrieve_vault_status(revault_network, bitcoind):
    """Test we keep track of coins that moved without us actively noticing it."""
    CSV = 3
    revault_network.deploy(2, 2, csv=CSV)
    mans = revault_network.man_wallets

    # Create a new deposit, makes everyone aware of it. Then stop one of the
    # wallets for it to not notice anything from now on.
    vault = revault_network.fund(0.05)
    man = mans.pop(0)
    man.stop()

    # Now activate and Spend the vault, the manager does not acknowledge it (yet)
    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)
    deposits = [f"{vault['txid']}:{vault['vout']}"]
    destinations = {bitcoind.rpc.getnewaddress(): vault["amount"] // 2}
    spend_tx = mans[0].rpc.getspendtx(deposits, destinations, 1)["spend_tx"]
    for m in [man] + mans:
        spend_tx = m.man_keychain.sign_spend_psbt(spend_tx, [vault["derivation_index"]])
        mans[0].rpc.updatespendtx(spend_tx)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx)
    spend_psbt.tx.calc_sha256()
    mans[0].rpc.setspendtx(spend_psbt.tx.hash)

    bitcoind.generate_block(1, wait_for_mempool=len(deposits))
    bitcoind.generate_block(CSV)
    mans[0].wait_for_log(
        f"Succesfully broadcasted Spend tx '{spend_psbt.tx.hash}'",
    )
    wait_for(lambda: len(mans[0].rpc.listvaults(["spending"], deposits)["vaults"]) == 1)

    # The manager should restart, and acknowledge the vault as being "spending"
    mans.insert(0, man)
    mans[0].start()
    deposit = f"{vault['txid']}:{vault['vout']}"
    wait_for(
        lambda: len(mans[0].rpc.listvaults(["spending"], deposits)["vaults"])
        == len(deposits)
    )

    # And if we mine it now everyone will see it as "spent"
    bitcoind.generate_block(1, wait_for_mempool=spend_psbt.tx.hash)
    for w in mans + revault_network.stk_wallets:
        wait_for(
            lambda: len(w.rpc.listvaults(["spent"], deposits)["vaults"])
            == len(deposits)
        )

    # Now do the same dance with a "spent" vault
    vault = revault_network.fund(0.14)
    man = mans.pop(0)
    man.stop()

    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)
    deposits = [f"{vault['txid']}:{vault['vout']}"]
    destinations = {bitcoind.rpc.getnewaddress(): vault["amount"] // 2}
    spend_tx = mans[0].rpc.getspendtx(deposits, destinations, 1)["spend_tx"]
    for m in [man] + mans:
        spend_tx = m.man_keychain.sign_spend_psbt(spend_tx, [vault["derivation_index"]])
        mans[0].rpc.updatespendtx(spend_tx)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx)
    spend_psbt.tx.calc_sha256()
    mans[0].rpc.setspendtx(spend_psbt.tx.hash)

    bitcoind.generate_block(1, wait_for_mempool=len(deposits))
    bitcoind.generate_block(CSV)
    mans[0].wait_for_log(
        f"Succesfully broadcasted Spend tx '{spend_psbt.tx.hash}'",
    )
    bitcoind.generate_block(1, wait_for_mempool=spend_psbt.tx.hash)
    for w in mans + revault_network.stk_wallets:
        wait_for(
            lambda: len(w.rpc.listvaults(["spent"], deposits)["vaults"])
            == len(deposits)
        )

    # The manager should restart, and acknowledge the vault as being "spent"
    mans.insert(0, man)
    mans[0].start()
    deposit = f"{vault['txid']}:{vault['vout']}"
    wait_for(
        lambda: len(mans[0].rpc.listvaults(["spent"], [deposit])["vaults"])
        == len(deposits)
    )

    # Now do the same dance with a "canceling" vault
    vault = revault_network.fund(8)
    man = mans.pop(0)
    man.stop()

    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)
    deposits = [f"{vault['txid']}:{vault['vout']}"]
    destinations = {bitcoind.rpc.getnewaddress(): vault["amount"] // 2}
    spend_tx = mans[0].rpc.getspendtx(deposits, destinations, 1)["spend_tx"]
    for m in [man] + mans:
        spend_tx = m.man_keychain.sign_spend_psbt(spend_tx, [vault["derivation_index"]])
        mans[0].rpc.updatespendtx(spend_tx)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx)
    spend_psbt.tx.calc_sha256()
    mans[0].rpc.setspendtx(spend_psbt.tx.hash)
    bitcoind.generate_block(1, wait_for_mempool=len(deposits))

    # Cancel it
    for w in mans + revault_network.stk_wallets:
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulted"], deposits)["vaults"])
            == len(deposits)
        )
    mans[0].rpc.revault(deposits[0])
    for w in mans + revault_network.stk_wallets:
        wait_for(
            lambda: len(w.rpc.listvaults(["canceling"], deposits)["vaults"])
            == len(deposits)
        )
    # The manager should restart, and acknowledge the vault as being "canceling"
    mans.insert(0, man)
    mans[0].start()
    deposit = f"{vault['txid']}:{vault['vout']}"
    wait_for(
        lambda: len(mans[0].rpc.listvaults(["canceling"], [deposit])["vaults"])
        == len(deposits)
    )

    # Now do the same dance with a "canceled" vault
    vault = revault_network.fund(19)
    man = mans.pop(0)
    man.stop()

    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)
    deposits = [f"{vault['txid']}:{vault['vout']}"]
    destinations = {bitcoind.rpc.getnewaddress(): vault["amount"] // 2}
    spend_tx = mans[0].rpc.getspendtx(deposits, destinations, 1)["spend_tx"]
    for m in [man] + mans:
        spend_tx = m.man_keychain.sign_spend_psbt(spend_tx, [vault["derivation_index"]])
        mans[0].rpc.updatespendtx(spend_tx)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx)
    spend_psbt.tx.calc_sha256()
    mans[0].rpc.setspendtx(spend_psbt.tx.hash)
    bitcoind.generate_block(1, wait_for_mempool=len(deposits))

    # Cancel it
    for w in mans + revault_network.stk_wallets:
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulted"], deposits)["vaults"])
            == len(deposits)
        )
    mans[0].rpc.revault(deposits[0])
    bitcoind.generate_block(1, wait_for_mempool=1)
    for w in mans + revault_network.stk_wallets:
        wait_for(
            lambda: len(w.rpc.listvaults(["canceled"], deposits)["vaults"])
            == len(deposits)
        )
    # The manager should restart, and acknowledge the vault as being "canceled"
    mans.insert(0, man)
    mans[0].start()
    deposit = f"{vault['txid']}:{vault['vout']}"
    wait_for(
        lambda: len(mans[0].rpc.listvaults(["canceled"], [deposit])["vaults"])
        == len(deposits)
    )

    # Now do the same dance with a "unvaulting" vault
    vault = revault_network.fund(41)
    man = mans.pop(0)
    man.stop()

    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)
    deposits = [f"{vault['txid']}:{vault['vout']}"]
    destinations = {bitcoind.rpc.getnewaddress(): vault["amount"] // 2}
    spend_tx = mans[0].rpc.getspendtx(deposits, destinations, 1)["spend_tx"]
    for m in [man] + mans:
        spend_tx = m.man_keychain.sign_spend_psbt(spend_tx, [vault["derivation_index"]])
        mans[0].rpc.updatespendtx(spend_tx)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx)
    spend_psbt.tx.calc_sha256()
    mans[0].rpc.setspendtx(spend_psbt.tx.hash)

    for w in mans + revault_network.stk_wallets:
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulting"], deposits)["vaults"])
            == len(deposits)
        )

    # The manager should restart, and acknowledge the vault as being "unvaulting"
    mans.insert(0, man)
    mans[0].start()
    deposit = f"{vault['txid']}:{vault['vout']}"
    wait_for(
        lambda: len(mans[0].rpc.listvaults(["unvaulting"], [deposit])["vaults"])
        == len(deposits)
    )

    # Now do the same dance with a "unvaulted" vault
    vault = revault_network.fund(99)
    man = mans.pop(0)
    man.stop()

    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)
    deposits = [f"{vault['txid']}:{vault['vout']}"]
    destinations = {bitcoind.rpc.getnewaddress(): vault["amount"] // 2}
    spend_tx = mans[0].rpc.getspendtx(deposits, destinations, 1)["spend_tx"]
    for m in [man] + mans:
        spend_tx = m.man_keychain.sign_spend_psbt(spend_tx, [vault["derivation_index"]])
        mans[0].rpc.updatespendtx(spend_tx)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx)
    spend_psbt.tx.calc_sha256()
    mans[0].rpc.setspendtx(spend_psbt.tx.hash)

    bitcoind.generate_block(1, wait_for_mempool=len(deposits))
    for w in mans + revault_network.stk_wallets:
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulted"], deposits)["vaults"])
            == len(deposits)
        )

    # The manager should restart, and acknowledge the vault as being "unvaulted"
    mans.insert(0, man)
    mans[0].start()
    deposit = f"{vault['txid']}:{vault['vout']}"
    wait_for(
        lambda: len(mans[0].rpc.listvaults(["unvaulted"], [deposit])["vaults"])
        == len(deposits)
    )

    # Now do the same dance with an "active" vault
    vault = revault_network.fund(0.0556789)
    man = mans.pop(0)
    man.stop()

    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)

    # The manager should restart, and acknowledge the vault as being "active"
    mans.insert(0, man)
    mans[0].start()
    deposit = f"{vault['txid']}:{vault['vout']}"
    mans[0].wait_for_active_vaults([deposit])

    # Now do the same dance with a "secured" vault
    vault = revault_network.fund(0.123456)
    man = mans.pop(0)
    man.stop()

    revault_network.secure_vault(vault)

    # The manager should restart, and acknowledge the vault as being "secured"
    mans.insert(0, man)
    mans[0].start()
    deposit = f"{vault['txid']}:{vault['vout']}"
    mans[0].wait_for_secured_vaults([deposit])

    # TODO: same dance with all emergency statuses
