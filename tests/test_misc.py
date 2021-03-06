import copy
import logging
import pytest
import random
import serializations

from bitcoin.core import COIN
from fixtures import *
from utils import POSTGRES_IS_SETUP, TIMEOUT, RpcError, wait_for


def test_getinfo(revaultd_manager, bitcoind):
    res = revaultd_manager.rpc.call("getinfo")
    assert res["network"] == "regtest"
    assert res["sync"] == 1.0
    assert res["version"] == "0.0.2"

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

    # Generate 5 blocks, it is still unconfirmed
    bitcoind.generate_block(5)
    assert (
        revaultd_manager.rpc.call("listvaults")["vaults"][0]["status"] == "unconfirmed"
    )

    # 1 more block will get it confirmed
    bitcoind.generate_block(1)
    revaultd_manager.wait_for_log(f"Vault at .*{txid}.* is now confirmed")
    assert revaultd_manager.rpc.call("listvaults")["vaults"][0]["status"] == "funded"

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
    """Test a wallet with 1000 deposits"""
    amount = 0.01
    bitcoind.generate_block(10)

    for i in range(10):
        txids = []
        for i in range(100):
            addr = revaultd_stakeholder.rpc.call("getdepositaddress")["address"]
            txids.append(bitcoind.rpc.sendtoaddress(addr, amount))
        bitcoind.generate_block(6, txids)

    revaultd_stakeholder.rpc.getinfo()
    revaultd_stakeholder.rpc.listvaults()


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


def test_reorged_deposit(revaultd_stakeholder, bitcoind):
    # TODO: start / stop, partial reorgs
    stk = revaultd_stakeholder

    # Create a new deposit
    amount_sent = 42
    addr = stk.rpc.getdepositaddress()["address"]
    bitcoind.rpc.sendtoaddress(addr, amount_sent)
    wait_for(lambda: len(stk.rpc.listvaults()["vaults"]) > 0)

    # Get it confirmed
    vault = stk.rpc.listvaults()["vaults"][0]
    deposit = f"{vault['txid']}:{vault['vout']}"
    bitcoind.generate_block(6)

    stk.wait_for_deposits([deposit])
    # FIXME: remove this ugly workaround once the blockheight is in `listvaults`
    blockheight = stk.rpc.listonchaintransactions([deposit])["onchain_transactions"][0][
        "deposit"
    ]["blockheight"]

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
    bitcoind.simple_reorg(blockheight)
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
    bitcoind.simple_reorg(blockheight, shift=3)
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
    bitcoind.simple_reorg(blockheight + 3, shift=2)
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
    bitcoind.simple_reorg(blockheight + 3 + 2)
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
    bitcoind.simple_reorg(blockheight + 3 + 2, shift=-1)
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
    revault_network.deploy(4, 2)
    vault = revault_network.fund(0.14)
    revault_network.secure_vault(vault)

    deposit = f"{vault['txid']}:{vault['vout']}"
    # FIXME: remove this ugly workaround once the blockheight is in `listvaults`
    blockheight = revault_network.stk_wallets[0].rpc.listonchaintransactions([deposit])[
        "onchain_transactions"
    ][0]["deposit"]["blockheight"]

    # Reorg the deposit. This should not affect us as the transaction did not
    # shift
    bitcoind.simple_reorg(blockheight)
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        w.wait_for_logs(
            [
                "Detected reorg",
                # 7 because simple_reorg() adds a block
                f"Vault deposit '{deposit}' still has '7' confirmations",
            ]
        )

    # Now actually shift it (7 + 1 - 3 == 5)
    bitcoind.simple_reorg(blockheight, shift=3)
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault deposit '{deposit}' ended up with '5' confirmations",
                "Rescan of all vaults in db done.",
            ]
        )
        wait_for(lambda: len(w.rpc.listvaults(["unconfirmed"], [deposit])) > 0)

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
    bitcoind.simple_reorg(blockheight + 3)
    for w in revault_network.stk_wallets + revault_network.man_wallets:
        w.wait_for_logs(
            [
                "Detected reorg",
                # 7 because simple_reorg() adds a block
                f"Vault deposit '{deposit}' still has '7' confirmations",
            ]
        )
    bitcoind.simple_reorg(blockheight + 3, shift=3)
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
    bitcoind.simple_reorg(blockheight + 3 + 3)
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
    bitcoind.simple_reorg(blockheight + 3 + 3, shift=3)
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


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_getspendtx(revault_network, bitcoind):
    revault_network.deploy(2, 1)
    man = revault_network.man_wallets[0]
    amount = 32.67890
    vault = revault_network.fund(amount)
    deposit = f"{vault['txid']}:{vault['vout']}"

    addr = bitcoind.rpc.getnewaddress()
    spent_vaults = [deposit]
    # 10k fees, 50k CPFP, 50k unvault CPFP + fees
    destination = {addr: vault["amount"] - 10_000 - 50_000 - 50_000}
    feerate = 2

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
    destinations = {addr: vault["amount"] - 10_000 - 50_000 - 50_000 - 1_000_000}
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
        # Overhead, P2WPKH, P2WSH, inputs, witnesses
        tx_vbytes = 11 + 31 + 43 + (32 + 4 + 4 + 1) * len(deposits) + 99 * len(deposits)
        sent_amount = (
            sum(amounts)
            - tx_vbytes * feerate  # fees
            - 2 * 32 * tx_vbytes  # CPFP
            - 30_000 * len(deposits)  # Unvault CPFP
            # Overhead, P2WSH * 2, inputs + witnesses
            - (11 + 43 * 2 + 91) * len(deposits) * 24  # Unvault fees (6sat/WU feerate)
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
