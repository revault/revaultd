"""Sanity checks of the JSONRPC API.

These tests should ideally be focused on only sanity checking the command API. More
complete test scenarii using these commands belong to another group.
"""

import copy
import pytest
import random
import time

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
    assert res["version"] == "0.3.1"
    assert res["vaults"] == 0
    # revaultd_manager always deploys with N = 2, M = 3, threshold = M
    assert res["managers_threshold"] == 3
    assert res["participant_type"] == "manager"
    # test descriptors: RPC call & which Revaultd's were configured
    assert res["descriptors"]["cpfp"] == str(revaultd_manager.cpfp_desc)
    assert res["descriptors"]["deposit"] == str(revaultd_manager.deposit_desc)
    assert res["descriptors"]["unvault"] == str(revaultd_manager.unvault_desc)

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
    assert vault_list[0]["amount"] == amount_sent * 10**8
    assert vault_list[0]["address"] == addr
    assert vault_list[0]["derivation_index"] == 0
    assert vault_list[0]["blockheight"] is None
    assert vault_list[0]["funded_at"] is None
    assert vault_list[0]["secured_at"] is None
    assert vault_list[0]["delegated_at"] is None
    assert vault_list[0]["moved_at"] is None
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
    assert vault["funded_at"] is not None
    assert vault["secured_at"] is None
    assert vault["delegated_at"] is None
    assert vault["moved_at"] is None
    assert vault["blockheight"] == bitcoind.rpc.getblockcount() - 5

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
    assert vault["funded_at"] is not None
    assert vault["secured_at"] is None
    assert vault["delegated_at"] is None
    assert vault["moved_at"] is None
    assert vault_list[0]["derivation_index"] == 0

    # And we can filter the result by status
    vault_list = revaultd_manager.rpc.call("listvaults", [["unconfirmed"]])["vaults"]
    assert len(vault_list) == 0
    vault_list = revaultd_manager.rpc.call("listvaults", [["funded"]])["vaults"]
    assert len(vault_list) == 1
    assert vault_list[0]["status"] == "funded"
    assert vault_list[0]["txid"] == txid
    assert vault_list[0]["amount"] == amount_sent * 10**8
    assert vault_list[0]["address"] == addr
    assert vault_list[0]["derivation_index"] == 0

    # And we can filter the result by outpoints
    outpoint = f"{txid}:{vault_list[0]['vout']}"
    vault_list = revaultd_manager.rpc.call("listvaults", [[], [outpoint]])["vaults"]
    assert len(vault_list) == 1
    assert vault_list[0]["status"] == "funded"
    assert vault_list[0]["txid"] == txid
    assert vault_list[0]["amount"] == amount_sent * 10**8
    assert vault_list[0]["address"] == addr
    assert vault_list[0]["derivation_index"] == 0

    outpoint = f"{txid}:{100}"
    vault_list = revaultd_manager.rpc.call("listvaults", [[], [outpoint]])["vaults"]
    assert len(vault_list) == 0


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_getdepositaddress(revault_network, bitcoind):
    rn = revault_network
    rn.deploy(4, 2)
    stk = rn.stk(0)
    addr = stk.rpc.call("getdepositaddress")["address"]

    # If we don't use it, we'll get the same. From us and everyone else
    for n in rn.participants():
        assert addr == n.rpc.call("getdepositaddress")["address"]

    # But if we do, we'll get the next one (but the same from everyone)!
    bitcoind.rpc.sendtoaddress(addr, 0.22222)
    stk.wait_for_logs(
        ["Got a new unconfirmed deposit", "Incremented deposit derivation index"]
    )
    addr2 = stk.rpc.call("getdepositaddress")["address"]
    assert addr2 != addr
    remaining_participants = rn.participants()[1:]
    for w in remaining_participants:
        w.wait_for_logs(
            ["Got a new unconfirmed deposit", "Incremented deposit derivation index"]
        )
        assert addr2 == w.rpc.call("getdepositaddress")["address"]


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_getrevocationtxs(revault_network, bitcoind):
    rn = revault_network
    rn.deploy(4, 2)
    stks = rn.stks()
    stk = stks[0]
    addr = stk.rpc.call("getdepositaddress")["address"]
    txid = bitcoind.rpc.sendtoaddress(addr, 0.22222)
    stk.wait_for_logs(
        ["Got a new unconfirmed deposit", "Incremented deposit derivation index"]
    )
    vault = stk.rpc.listvaults()["vaults"][0]
    deposit = f"{vault['txid']}:{vault['vout']}"

    # If we are not a stakeholder, it'll fail
    with pytest.raises(RpcError, match="This is a stakeholder command"):
        rn.man(0).rpc.getrevocationtxs(deposit)

    # If the vault isn't confirmed, it'll fail
    for n in stks:
        wait_for(lambda: len(n.rpc.listvaults([], [deposit])["vaults"]) == 1)
        with pytest.raises(RpcError, match="Invalid vault status"):
            n.rpc.getrevocationtxs(deposit)

    # Now, get it confirmed. They all derived the same transactions
    bitcoind.generate_block(6, txid)
    wait_for(lambda: stk.rpc.listvaults()["vaults"][0]["status"] == "funded")
    txs = stk.rpc.getrevocationtxs(deposit)
    assert len(txs.keys()) == 3
    remaining_stks = stks[1:]
    for n in remaining_stks:
        wait_for(lambda: n.rpc.listvaults()["vaults"][0]["status"] == "funded")
        assert txs == n.rpc.getrevocationtxs(deposit)


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_getunvaulttx(revault_network):
    revault_network.deploy(3, 1)
    mans = revault_network.mans()
    stks = revault_network.stks()
    vault = revault_network.fund(18)
    outpoint = f"{vault['txid']}:{vault['vout']}"
    stks[0].wait_for_deposits([outpoint])

    # If we are not a stakeholder, it'll fail
    with pytest.raises(RpcError, match="This is a stakeholder command"):
        mans[0].rpc.getunvaulttx(outpoint)

    # We can't query for an unknow vault
    invalid_outpoint = f"{'0'*64}:1"
    with pytest.raises(RpcError, match=f"No vault at '{invalid_outpoint}'"):
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
    stks = revault_network.stks()
    mans = revault_network.mans()

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
def test_listspendtxs(revault_network, bitcoind):
    rn = revault_network
    rn.deploy(n_stakeholders=2, n_managers=2, n_stkmanagers=0, csv=5)
    man = rn.man(0)

    vaults = rn.fundmany([1, 2, 3, 1])
    for v in vaults:
        rn.secure_vault(v)
        rn.activate_vault(v)

    # _any_spend_data never creates change
    destinations, feerate = rn._any_spend_data(vaults)
    deposits = []
    deriv_indexes = []
    for v in vaults:
        deposits.append(f"{v['txid']}:{v['vout']}")
        deriv_indexes.append(v["derivation_index"])
    man.wait_for_active_vaults(deposits)
    spend_tx = man.rpc.getspendtx(deposits, destinations, feerate)["spend_tx"]["psbt"]

    for man in rn.mans():
        spend_tx = man.man_keychain.sign_spend_psbt(spend_tx, deriv_indexes)
        man.rpc.updatespendtx(spend_tx)
        spend_txs = man.rpc.listspendtxs(["non_final"])["spend_txs"]
        assert len(spend_txs) == 1
        assert spend_txs[0]["change_index"] is None
        assert spend_txs[0]["cpfp_index"] is not None

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx)
    spend_psbt.tx.calc_sha256()
    man.rpc.setspendtx(spend_psbt.tx.hash)

    # The initiator will see the spend as pending
    for w in rn.participants():
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulting"], deposits)["vaults"])
            == len(deposits)
        )
    spend_txs = man.rpc.listspendtxs(["pending"])["spend_txs"]
    assert len(spend_txs) == 1
    assert spend_txs[0]["change_index"] is None
    assert spend_txs[0]["cpfp_index"] is not None

    rn.bitcoind.generate_block(rn.csv - 1, wait_for_mempool=len(deposits))

    # Still pending...
    for w in rn.participants():
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulted"], deposits)["vaults"])
            == len(deposits)
        )
    spend_txs = man.rpc.listspendtxs(["pending"])["spend_txs"]
    assert len(spend_txs) == 1
    assert spend_txs[0]["change_index"] is None
    assert spend_txs[0]["cpfp_index"] is not None

    rn.bitcoind.generate_block(1)

    # Broadcasted!
    for w in rn.participants():
        wait_for(
            lambda: len(w.rpc.listvaults(["spending"], deposits)["vaults"])
            == len(deposits)
        )
    spend_txs = man.rpc.listspendtxs(["broadcasted"])["spend_txs"]
    assert len(spend_txs) == 1
    assert spend_txs[0]["change_index"] is None
    assert spend_txs[0]["cpfp_index"] is not None

    rn.bitcoind.generate_block(1, wait_for_mempool=[spend_psbt.tx.hash])

    # Transaction is spent, the status is "confirmed"
    for w in rn.participants():
        wait_for(
            lambda: len(w.rpc.listvaults(["spent"], deposits)["vaults"])
            == len(deposits)
        )
    spend_txs = man.rpc.listspendtxs(["confirmed"])["spend_txs"]
    assert len(spend_txs) == 1
    assert spend_txs[0]["change_index"] is None
    assert spend_txs[0]["cpfp_index"] is not None

    vaults = rn.fundmany([3, 4, 5])
    for v in vaults:
        rn.secure_vault(v)
        rn.activate_vault(v)
    rn.unvault_vaults_anyhow(vaults)
    rn.cancel_vault(vaults[0])
    # Transaction is canceled, the status is still "pending" as
    # the vaults can not be spent anymore
    # (Keep in mind that in the utilities under tests/revault_network.py
    # we usually use the last manager for broadcasting the transactions)
    deprecated_txs = rn.man(1).rpc.listspendtxs(["deprecated"])["spend_txs"]
    assert len(deprecated_txs) == 1
    assert deprecated_txs[0]["status"] == "deprecated"

    v = rn.fund(6)
    rn.secure_vault(v)
    rn.activate_vault(v)
    rn.spend_vaults_anyhow_unconfirmed([v])
    assert len(rn.man(1).rpc.listspendtxs(["broadcasted"])["spend_txs"]) == 1
    rn.cancel_vault(v)
    # Status of the spend is deprecated because one of its vault is canceled
    deprecated_txs = rn.man(1).rpc.listspendtxs(["deprecated"])["spend_txs"]
    assert len(deprecated_txs) == 2
    assert deprecated_txs[0]["status"] == "deprecated"
    assert deprecated_txs[1]["status"] == "deprecated"


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_listspendtxs_check_indexes(revault_network, bitcoind):
    # Spending with the change output
    rn = revault_network
    rn.deploy(n_stakeholders=2, n_managers=1, n_stkmanagers=0, csv=5)
    v = rn.fund(6)
    rn.secure_vault(v)
    rn.activate_vault(v)
    address = rn.bitcoind.rpc.getnewaddress()
    rn.spend_vaults([v], {address: 500000000}, 1)
    spend_txs = rn.man(0).rpc.listspendtxs()["spend_txs"]
    assert len(spend_txs) == 1
    assert spend_txs[0]["change_index"] is not None
    assert spend_txs[0]["cpfp_index"] is not None


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_listonchaintransactions(revault_network):
    """Just a small sanity check of the API"""
    rn = revault_network
    rn.deploy(2, 1, csv=5)
    vaultA = rn.fund(0.2222221)
    vaultB = rn.fund(122.88881)
    depositA = f"{vaultA['txid']}:{vaultA['vout']}"
    depositB = f"{vaultB['txid']}:{vaultB['vout']}"

    # Sanity check the API
    for w in rn.participants():
        w.wait_for_deposits([depositA, depositB])
        res = w.rpc.listonchaintransactions([depositA, depositB])[
            "onchain_transactions"
        ][0]
        # Deposit is always there
        assert res["deposit"]["blockheight"] is not None
        assert res["deposit"]["blocktime"] is not None
        assert res["deposit"]["received_at"] is not None
        assert res["deposit"]["hex"] is not None
        assert res["unvault"] is None
        assert res["cancel"] is None
        assert res["emergency"] is None
        assert res["unvault_emergency"] is None
        assert res["spend"] is None

    for v in [vaultA, vaultB]:
        rn.secure_vault(v)
        rn.activate_vault(v)
    rn.spend_vaults_anyhow([vaultA, vaultB])

    for w in rn.participants():
        res = w.rpc.listonchaintransactions([depositA, depositB])[
            "onchain_transactions"
        ][0]
        assert res["deposit"]["blockheight"] is not None
        assert res["deposit"]["blocktime"] is not None
        assert res["deposit"]["received_at"] is not None
        assert res["deposit"]["hex"] is not None
        assert res["unvault"]["blockheight"] is not None
        assert res["unvault"]["received_at"] is not None
        assert res["unvault"]["hex"] is not None
        assert res["cancel"] is None
        assert res["emergency"] is None
        assert res["unvault_emergency"] is None
        assert res["spend"]["blockheight"] is not None
        assert res["spend"]["blocktime"] is not None
        assert res["spend"]["received_at"] is not None
        assert res["spend"]["hex"] is not None

    vaultC = rn.fund(23)
    depositC = f"{vaultC['txid']}:{vaultC['vout']}"
    rn.secure_vault(vaultC)
    rn.activate_vault(vaultC)
    rn.unvault_vaults_anyhow([vaultC])
    rn.cancel_vault(vaultC)

    for w in rn.participants():
        res = w.rpc.listonchaintransactions([depositC])["onchain_transactions"][0]
        assert res["deposit"]["blockheight"] is not None
        assert res["deposit"]["received_at"] is not None
        assert res["deposit"]["hex"] is not None
        assert res["unvault"]["blockheight"] is not None
        assert res["unvault"]["received_at"] is not None
        assert res["unvault"]["hex"] is not None
        assert res["cancel"]["blockheight"] is not None
        assert res["cancel"]["received_at"] is not None
        assert res["cancel"]["hex"] is not None
        assert res["emergency"] is None
        assert res["unvault_emergency"] is None
        assert res["spend"] is None


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
    mans = revault_network.mans()
    stks = revault_network.stks()

    vault = revault_network.fund(10)
    deposit = f"{vault['txid']}:{vault['vout']}"
    child_index = vault["derivation_index"]
    stks[0].wait_for_deposits([deposit])
    psbts = stks[0].rpc.getrevocationtxs(deposit)

    # If we are not a stakeholder, it'll fail
    with pytest.raises(RpcError, match="This is a stakeholder command"):
        mans[0].rpc.revocationtxs(
            deposit,
            psbts["cancel_txs"],
            psbts["emergency_tx"],
            psbts["emergency_unvault_tx"],
        )

    # We must provide all revocation txs at once
    with pytest.raises(RpcError, match="Invalid params.*"):
        stks[0].rpc.revocationtxs(deposit, psbts["cancel_txs"], psbts["emergency_tx"])

    # We must provide all cancel txs at once
    with pytest.raises(RpcError, match="Invalid params.*"):
        stks[0].rpc.revocationtxs(
            deposit, psbts["cancel_txs"][:2], psbts["emergency_tx"]
        )

    # We can't send it for an unknown vault
    with pytest.raises(RpcError, match="No vault at"):
        stks[0].rpc.revocationtxs(
            deposit[:-1] + "18",
            psbts["cancel_txs"],
            psbts["emergency_tx"],
            psbts["emergency_unvault_tx"],
        )

    # We can't give it random PSBTs, it will fail at parsing time
    mal_cancels = [psbt_add_input(c) for c in psbts["cancel_txs"]]
    with pytest.raises(RpcError, match="Invalid Revault transaction"):
        stks[0].rpc.revocationtxs(
            deposit, mal_cancels, psbts["emergency_tx"], psbts["emergency_unvault_tx"]
        )
    mal_emer = psbt_add_input(psbts["emergency_tx"])
    with pytest.raises(RpcError, match="Invalid Revault transaction"):
        stks[0].rpc.revocationtxs(
            deposit, psbts["cancel_txs"], mal_emer, psbts["emergency_unvault_tx"]
        )
    mal_unemer = psbt_add_input(psbts["emergency_unvault_tx"])
    with pytest.raises(RpcError, match="Invalid Revault transaction"):
        stks[0].rpc.revocationtxs(
            deposit, psbts["cancel_txs"], psbts["emergency_tx"], mal_unemer
        )

    # We can't mix up emergency PSBTS
    with pytest.raises(RpcError, match="Invalid Emergency tx: db wtxid"):
        stks[0].rpc.revocationtxs(
            deposit,
            psbts["cancel_txs"],
            psbts["emergency_unvault_tx"],
            psbts["emergency_unvault_tx"],
        )
    with pytest.raises(RpcError, match="Invalid Unvault Emergency tx: db wtxid"):
        stks[0].rpc.revocationtxs(
            deposit, psbts["cancel_txs"], psbts["emergency_tx"], psbts["emergency_tx"]
        )

    # We must provide a signature for ourselves
    with pytest.raises(RpcError, match="No signature for ourselves.*Cancel"):
        stks[0].rpc.revocationtxs(
            deposit,
            psbts["cancel_txs"],
            psbts["emergency_tx"],
            psbts["emergency_unvault_tx"],
        )
    cancel_psbts = [
        stks[0].stk_keychain.sign_revocation_psbt(c, child_index)
        for c in psbts["cancel_txs"]
    ]
    with pytest.raises(RpcError, match="No signature for ourselves.*Emergency"):
        stks[0].rpc.revocationtxs(
            deposit, cancel_psbts, psbts["emergency_tx"], psbts["emergency_unvault_tx"]
        )
    emer_psbt = stks[0].stk_keychain.sign_revocation_psbt(
        psbts["emergency_tx"], child_index
    )
    with pytest.raises(RpcError, match="No signature for ourselves.*UnvaultEmergency"):
        stks[0].rpc.revocationtxs(
            deposit, cancel_psbts, emer_psbt, psbts["emergency_unvault_tx"]
        )
    unemer_psbt = stks[0].stk_keychain.sign_revocation_psbt(
        psbts["emergency_unvault_tx"], child_index
    )

    # We can't provide ANYONECANPAY signatures
    cancel_psbts_acp = [
        stks[0].stk_keychain.sign_revocation_psbt(c, child_index, acp=True)
        for c in psbts["cancel_txs"]
    ]
    with pytest.raises(RpcError, match="Invalid signature .* in Cancel PSBT"):
        stks[0].rpc.revocationtxs(
            deposit,
            cancel_psbts_acp,
            emer_psbt,
            unemer_psbt,
        )

    # We refuse any random garbage signature
    mal_cancels = [psbt_add_invalid_sig(c) for c in cancel_psbts]
    with pytest.raises(RpcError, match="Unknown key in Cancel"):
        stks[0].rpc.revocationtxs(deposit, mal_cancels, emer_psbt, unemer_psbt)
    mal_emer = psbt_add_invalid_sig(emer_psbt)
    with pytest.raises(RpcError, match="Unknown key in Emergency"):
        stks[0].rpc.revocationtxs(deposit, cancel_psbts, mal_emer, unemer_psbt)
    mal_unemer = psbt_add_invalid_sig(unemer_psbt)
    with pytest.raises(RpcError, match="Unknown key in UnvaultEmergency"):
        stks[0].rpc.revocationtxs(deposit, cancel_psbts, emer_psbt, mal_unemer)

    # If we input valid presigned transactions, it will acknowledge that *we* already
    # signed and that we are waiting for others' signatures now.
    stks[0].rpc.revocationtxs(
        deposit,
        cancel_psbts,
        emer_psbt,
        unemer_psbt,
    )
    assert len(stks[0].rpc.listvaults(["securing"], [deposit])["vaults"]) == 1


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_unvaulttx(revault_network):
    """Sanity checks for the unvaulttx command"""
    revault_network.deploy(3, 1)
    mans = revault_network.mans()
    stks = revault_network.stks()
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
        cancel_psbts = psbts["cancel_txs"]
        emer_psbt = psbts["emergency_tx"]
        unemer_psbt = psbts["emergency_unvault_tx"]
        for stk in stks:
            cancel_psbts = [
                stk.stk_keychain.sign_revocation_psbt(c, child_index)
                for c in cancel_psbts
            ]
            emer_psbt = stk.stk_keychain.sign_revocation_psbt(emer_psbt, child_index)
            unemer_psbt = stk.stk_keychain.sign_revocation_psbt(
                unemer_psbt, child_index
            )
        stks[0].rpc.revocationtxs(deposit, cancel_psbts, emer_psbt, unemer_psbt)
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

    # We refuse any random garbage signature
    mal_unvault = psbt_add_invalid_sig(unvault_psbt)
    unvault_psbt = stks[0].stk_keychain.sign_unvault_psbt(unvault_psbt, child_index)
    with pytest.raises(RpcError, match="Unknown key"):
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
def test_emergency(revault_network, bitcoind):
    """This tests the 'emergency' RPC command"""
    rn = revault_network
    rn.deploy(1, 1, n_stkmanagers=1, csv=3)

    with pytest.raises(RpcError, match="This is a stakeholder command"):
        rn.man(1).rpc.emergency()

    # Calling it without any vault won't do anything
    rn.stk(1).rpc.emergency()

    # Emergencying with a single, not unvaulted vault
    vault = rn.fund(8)
    deposit = f"{vault['txid']}:{vault['vout']}"
    rn.secure_vault(vault)
    rn.stk(0).rpc.emergency()
    for stk in rn.stks():
        wait_for(
            lambda: len(stk.rpc.listvaults(["emergencyvaulting"], [deposit])["vaults"])
            == 1
        )
    bitcoind.generate_block(1, wait_for_mempool=1)
    for stk in rn.stks():
        wait_for(
            lambda: len(stk.rpc.listvaults(["emergencyvaulted"], [deposit])["vaults"])
            == 1
        )
    assert len(bitcoind.rpc.listunspent(1, 1, [rn.emergency_address])) == 1

    # Emergencying with a single unvaulted vault
    vault = rn.fund(42)
    deposit = f"{vault['txid']}:{vault['vout']}"
    rn.secure_vault(vault)
    rn.activate_vault(vault)
    rn.unvault_vaults_anyhow([vault])
    rn.stk(1).rpc.emergency()
    for stk in rn.stks():
        wait_for(
            lambda: len(
                stk.rpc.listvaults(["unvaultemergencyvaulting"], [deposit])["vaults"]
            )
            == 1
        )
    bitcoind.generate_block(1, wait_for_mempool=1)
    for stk in rn.stks():
        wait_for(
            lambda: len(
                stk.rpc.listvaults(["unvaultemergencyvaulted"], [deposit])["vaults"]
            )
            == 1
        )
    assert len(bitcoind.rpc.listunspent(1, 1, [rn.emergency_address])) == 1

    # Emergencying with several, not unvaulted vaults
    vaults = rn.fundmany([1.2, 3.4])
    deposits = [f"{v['txid']}:{v['vout']}" for v in vaults]
    rn.secure_vaults(vaults)
    rn.stk(0).rpc.emergency()
    for stk in rn.stks():
        wait_for(
            lambda: len(stk.rpc.listvaults(["emergencyvaulting"], deposits)["vaults"])
            == len(deposits)
        )
    bitcoind.generate_block(1, wait_for_mempool=2)
    for stk in rn.stks():
        wait_for(
            lambda: len(stk.rpc.listvaults(["emergencyvaulted"], deposits)["vaults"])
            == len(deposits)
        )
    assert len(bitcoind.rpc.listunspent(1, 1, [rn.emergency_address])) == 2

    # Emergencying with several unvaulted vaults
    vaults = [rn.fund(18), rn.fund(12)]
    deposits = [f"{v['txid']}:{v['vout']}" for v in vaults]
    rn.activate_fresh_vaults(vaults)
    rn.unvault_vaults_anyhow(vaults)
    rn.stk(0).rpc.emergency()
    for stk in rn.stks():
        wait_for(
            lambda: len(
                stk.rpc.listvaults(["unvaultemergencyvaulting"], deposits)["vaults"]
            )
            == len(deposits)
        )
    bitcoind.generate_block(1, wait_for_mempool=2)
    for stk in rn.stks():
        wait_for(
            lambda: len(
                stk.rpc.listvaults(["unvaultemergencyvaulted"], deposits)["vaults"]
            )
            == len(deposits)
        )
    assert len(bitcoind.rpc.listunspent(1, 1, [rn.emergency_address])) == 2

    # Emergencying with some unvaulted vaults and many non-unvaulted ones
    vaults = rn.fundmany([random.randint(5, 5000) / 100 for _ in range(30)])
    unvaulted_vaults, vaults = (vaults[:3], vaults[3:])
    deposits = [f"{v['txid']}:{v['vout']}" for v in vaults]
    unvaulted_deposits = [f"{v['txid']}:{v['vout']}" for v in unvaulted_vaults]
    rn.secure_vaults(vaults)
    rn.activate_fresh_vaults(unvaulted_vaults)
    rn.unvault_vaults_anyhow(unvaulted_vaults)
    rn.stk(1).rpc.emergency()
    for stk in rn.stks():
        wait_for(
            lambda: len(stk.rpc.listvaults(["emergencyvaulting"], deposits)["vaults"])
            == len(deposits)
        )
        wait_for(
            lambda: len(
                stk.rpc.listvaults(["unvaultemergencyvaulting"], unvaulted_deposits)[
                    "vaults"
                ]
            )
            == len(unvaulted_deposits)
        )
    bitcoind.generate_block(1, wait_for_mempool=len(vaults) + len(unvaulted_vaults))
    for stk in rn.stks():
        wait_for(
            lambda: len(stk.rpc.listvaults(["emergencyvaulted"], deposits)["vaults"])
            == len(deposits)
        )
        wait_for(
            lambda: len(
                stk.rpc.listvaults(["unvaultemergencyvaulted"], unvaulted_deposits)[
                    "vaults"
                ]
            )
            == len(unvaulted_deposits)
        )
    assert len(bitcoind.rpc.listunspent(1, 1, [rn.emergency_address])) == len(
        vaults
    ) + len(unvaulted_vaults)


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_getspendtx(revault_network, bitcoind):
    revault_network.deploy(2, 1)
    man = revault_network.man(0)
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
        revault_network.stk(0).rpc.getspendtx(spent_vaults, destination, feerate)

    # The amount was not enough to afford a change output, everything went to
    # fees.
    spend_tx = man.rpc.getspendtx(spent_vaults, destination, feerate)["spend_tx"]
    assert spend_tx["deposit_outpoints"] == [deposit]
    assert spend_tx["deposit_amount"] == amount * 100_000_000
    assert spend_tx["cpfp_amount"] == 44336
    assert spend_tx["change_index"] is None
    assert spend_tx["cpfp_index"] == 0
    assert spend_tx["status"] == "non_final"
    psbt = serializations.PSBT()
    psbt.deserialize(spend_tx["psbt"])
    assert len(psbt.inputs) == 1 and len(psbt.outputs) == 2

    # But if we decrease it enough, it'll create a change output
    destinations = {addr: vault["amount"] - fees - 1_000_000}
    spend_tx = man.rpc.getspendtx(spent_vaults, destinations, feerate)["spend_tx"]
    assert spend_tx["deposit_outpoints"] == [deposit]
    assert spend_tx["deposit_amount"] == amount * 100_000_000
    assert spend_tx["cpfp_amount"] == 47088
    assert spend_tx["change_index"] is not None
    assert spend_tx["status"] == "non_final"
    psbt = serializations.PSBT()
    psbt.deserialize(spend_tx["psbt"])
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
        amount = round(random.random() * 10**8 % 50, 7)
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
            man.rpc.getspendtx(deposits, destinations, feerate)["spend_tx"]["psbt"]
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
            man.rpc.getspendtx(deposits, destinations, feerate)["spend_tx"]["psbt"]
        )
        assert (
            len(psbt.inputs) == len(deposits)
            # destinations + CPFP + change
            and len(psbt.outputs) == len(destinations.keys()) + 1 + 1
        ), "expected a change output"

    # And we can do both
    deposits = []
    destinations = {}
    total_amount = 0
    for vault in man.rpc.listvaults(["active"])["vaults"]:
        total_amount += vault["amount"]
        deposits.append(f"{vault['txid']}:{vault['vout']}")
        destinations[bitcoind.rpc.getnewaddress()] = vault["amount"] // 2

    spend_tx = man.rpc.getspendtx(deposits, destinations, feerate)["spend_tx"]
    assert spend_tx["deposit_outpoints"] == deposits
    assert spend_tx["deposit_amount"] == total_amount
    assert spend_tx["change_index"] is not None
    assert spend_tx["status"] == "non_final"
    psbt = serializations.PSBT()
    psbt.deserialize(spend_tx["psbt"])
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
def test_revault_command(revault_network, bitcoind, executor):
    """
    Here we manually broadcast the unvualt_tx, followed by a cancel_tx
    """
    revault_network.deploy(3, 1)
    man = revault_network.man(0)
    stks = revault_network.stks()
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
    ][0]["unvault"]
    unvault_tx = bitcoind.rpc.finalizepsbt(unvault_psbt)["hex"]
    bitcoind.rpc.sendrawtransaction(unvault_tx)

    # Unvaulting! And there's no associated spend tx! Is revault broken?
    for w in stks + [man]:
        wait_for(
            lambda: w.rpc.listvaults([], [deposit])["vaults"][0]["status"]
            == "unvaulting"
        )

    # Nah it's not, just broadcast a cancel
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
        w.rpc.listvaults([], [deposit])["vaults"][0]["moved_at"] is not None

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
        unvault_psbt = man.rpc.listpresignedtransactions([deposit])[
            "presigned_transactions"
        ][0]["unvault"]
        unvault_tx = bitcoind.rpc.finalizepsbt(unvault_psbt)["hex"]
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

    # And the deposit txid is the lowest-feerate Cancel's txid
    for v in stks[0].rpc.listvaults(["canceled"])["vaults"]:
        deposit = f"{v['txid']}:{v['vout']}"
        cancel_psbt = serializations.PSBT()
        cancel_b64 = stks[0].rpc.listpresignedtransactions([deposit])[
            "presigned_transactions"
        ][0]["cancel"][0]
        cancel_psbt.deserialize(cancel_b64)

        cancel_psbt.tx.calc_sha256()
        cancel_txid = cancel_psbt.tx.hash
        new_deposits = stks[0].rpc.listvaults(["funded"])["vaults"]
        assert cancel_txid in [v["txid"] for v in new_deposits]


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_getserverstatus(revault_network, bitcoind):
    rn = revault_network
    rn.deploy(n_stakeholders=2, n_managers=1)

    # The coordinator is alive
    for w in rn.participants():
        res = w.rpc.call("getserverstatus")
        assert res["coordinator"]["reachable"]
        assert res["coordinator"]["host"] == f"127.0.0.1:{rn.coordinator_port}"

    # The cosigners are alive, but only the managers see them
    for w in rn.mans():
        res = w.rpc.call("getserverstatus")
        for cosigner in res["cosigners"]:
            assert cosigner["reachable"]
            # Sadly we don't persist the cosigner ports
            assert cosigner["host"].startswith("127.0.0.1:")

    # Stakeholders don't have cosigners info
    for w in rn.stks():
        res = w.rpc.call("getserverstatus")
        assert res["cosigners"] == []

    # Only stakeholders have info about the watchtowers, they must be reachable
    for w in rn.stks():
        res = w.rpc.call("getserverstatus")
        for watchtower in res["watchtowers"]:
            assert watchtower["reachable"]

    # Managers don't have watchtowers info
    for w in rn.mans():
        res = w.rpc.call("getserverstatus")
        assert res["watchtowers"] == []

    # Alright, let's kill all the servers
    for d in rn.daemons:
        if d not in rn.participants():
            d.stop()

    # The coordinator is dead
    for w in rn.participants():
        res = w.rpc.call("getserverstatus")
        assert not res["coordinator"]["reachable"]
        assert res["coordinator"]["host"] == f"127.0.0.1:{rn.coordinator_port}"

    # The cosigners are dead as well
    for w in rn.mans():
        res = w.rpc.call("getserverstatus")
        for cosigner in res["cosigners"]:
            assert not cosigner["reachable"]
            # Sadly we don't persist the cosigner ports
            assert cosigner["host"].startswith("127.0.0.1:")

    # So are the watchtowers
    for w in rn.stks():
        res = w.rpc.call("getserverstatus")
        for watchtower in res["watchtowers"]:
            assert not watchtower["reachable"]


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_setspendtx_cpfp_not_enabled(revault_network, bitcoind):
    CSV = 12
    revault_network.deploy(2, 1, n_stkmanagers=1, csv=CSV, with_cpfp=False)
    man = revault_network.mans()[1]
    stks = revault_network.stks()
    amount = 0.24
    vault = revault_network.fund(amount)
    deposit = f"{vault['txid']}:{vault['vout']}"

    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)
    with pytest.raises(
        RpcError,
        match="Can't read the cpfp key",
    ):
        revault_network.broadcast_unvaults_anyhow([vault], priority=True)


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_gethistory(revault_network, bitcoind, executor):
    """
    Retrieve the event History and check the presence of some triggered events.
    """

    CSV = 12
    revault_network.deploy(2, 2, n_stkmanagers=1, csv=CSV)
    mans = revault_network.mans()
    stks = revault_network.stks()

    t1 = int(time.time())

    # Create one canceled vault.
    canceled_vault = revault_network.fund(0.05)
    revault_network.secure_vault(canceled_vault)
    revault_network.activate_vault(canceled_vault)
    revault_network.spend_vaults_anyhow_unconfirmed([canceled_vault])
    revault_network.cancel_vault(canceled_vault)
    canceled_outpoint = f"{canceled_vault['txid']}:{canceled_vault['vout']}"

    vaults = mans[0].rpc.listvaults(["canceled"])["vaults"]
    assert len(vaults) == 1
    t2 = vaults[0]["moved_at"] + 1

    events = mans[0].rpc.gethistory(["spend", "deposit", "cancel"], t1, t2, 20)[
        "events"
    ]
    assert len(events) == 2
    assert events[0]["kind"] == "cancel"
    assert len(events[0]["vaults"]) == 1
    assert events[0]["vaults"][0] == canceled_outpoint
    assert events[1]["kind"] == "deposit"
    assert len(events[1]["vaults"]) == 1
    assert events[1]["vaults"][0] == canceled_outpoint

    # We can filter the results
    events = mans[0].rpc.gethistory(["deposit", "cancel"], t1, t2, 20)["events"]
    assert len(events) == 2
    assert events[0]["kind"] == "cancel"
    assert len(events[0]["vaults"]) == 1
    assert events[0]["vaults"][0] == canceled_outpoint
    assert events[1]["kind"] == "deposit"
    assert len(events[1]["vaults"]) == 1
    assert events[1]["vaults"][0] == canceled_outpoint

    events = mans[0].rpc.gethistory(["cancel"], t1, t2, 20)["events"]
    assert len(events) == 1
    assert events[0]["kind"] == "cancel"
    assert len(events[0]["vaults"]) == 1
    assert events[0]["vaults"][0] == canceled_outpoint

    events = mans[0].rpc.gethistory(["deposit"], t1, t2, 20)["events"]
    assert len(events) == 1
    assert events[0]["kind"] == "deposit"
    assert len(events[0]["vaults"]) == 1
    assert events[0]["vaults"][0] == canceled_outpoint

    events = mans[0].rpc.gethistory(["spend"], t1, t2, 20)["events"]
    assert len(events) == 0

    # More block to have a clean separation in terms of blocktime
    bitcoind.generate_block(12)

    spent_vault_1 = revault_network.fund(0.05)
    revault_network.secure_vault(spent_vault_1)
    revault_network.activate_vault(spent_vault_1)
    spent_vault_1_outpoint = f"{spent_vault_1['txid']}:{spent_vault_1['vout']}"

    spent_vault_2 = revault_network.fund(0.05)
    revault_network.secure_vault(spent_vault_2)
    revault_network.activate_vault(spent_vault_2)
    spent_vault_2_outpoint = f"{spent_vault_2['txid']}:{spent_vault_2['vout']}"

    address = revault_network.bitcoind.rpc.getnewaddress()
    revault_network.spend_vaults([spent_vault_1, spent_vault_2], {address: 4000000}, 1)
    spend_txs = revault_network.man(0).rpc.listspendtxs()["spend_txs"]
    assert len(spend_txs) == 2

    vaults = mans[0].rpc.listvaults(["spent"])["vaults"]
    assert len(vaults) == 2
    t3 = vaults[0]["moved_at"] + 1

    events = mans[0].rpc.gethistory(["spend", "deposit", "cancel"], t1, t2, 20)[
        "events"
    ]
    assert len(events) == 2
    assert events[0]["kind"] == "cancel"
    assert len(events[0]["vaults"]) == 1
    assert events[0]["vaults"][0] == canceled_outpoint
    assert events[1]["kind"] == "deposit"
    assert len(events[1]["vaults"]) == 1
    assert events[1]["vaults"][0] == canceled_outpoint

    events = mans[0].rpc.gethistory(["spend", "deposit", "cancel"], t2, t3, 20)[
        "events"
    ]
    assert len(events) == 3
    assert events[0]["kind"] == "spend"
    assert len(events[0]["vaults"]) == 2
    assert spent_vault_1_outpoint in events[0]["vaults"]
    assert spent_vault_2_outpoint in events[0]["vaults"]
    assert events[1]["kind"] == "deposit"
    assert len(events[1]["vaults"]) == 1
    assert events[1]["vaults"][0] == spent_vault_2_outpoint
    assert events[2]["kind"] == "deposit"
    assert len(events[2]["vaults"]) == 1
    assert events[2]["vaults"][0] == spent_vault_1_outpoint

    events = mans[0].rpc.gethistory(["spend", "deposit", "cancel"], t1, t3, 20)[
        "events"
    ]
    assert len(events) == 5
    assert events[0]["kind"] == "spend"
    assert len(events[0]["vaults"]) == 2
    assert spent_vault_1_outpoint in events[0]["vaults"]
    assert spent_vault_2_outpoint in events[0]["vaults"]
    assert events[1]["kind"] == "deposit"
    assert len(events[1]["vaults"]) == 1
    assert events[1]["vaults"][0] == spent_vault_2_outpoint
    assert events[2]["kind"] == "deposit"
    assert len(events[2]["vaults"]) == 1
    assert events[2]["vaults"][0] == spent_vault_1_outpoint
    assert events[3]["kind"] == "cancel"
    assert len(events[3]["vaults"]) == 1
    assert events[3]["vaults"][0] == canceled_outpoint
    assert events[4]["kind"] == "deposit"
    assert len(events[4]["vaults"]) == 1
    assert events[4]["vaults"][0] == canceled_outpoint

    events = mans[0].rpc.gethistory(["spend", "deposit", "cancel"], t1, t3, 2)["events"]
    assert len(events) == 2
    assert events[0]["kind"] == "spend"
    assert len(events[0]["vaults"]) == 2
    assert spent_vault_1_outpoint in events[0]["vaults"]
    assert spent_vault_2_outpoint in events[0]["vaults"]
    assert events[1]["kind"] == "deposit"
    assert len(events[1]["vaults"]) == 1
    assert events[1]["vaults"][0] == spent_vault_2_outpoint

    for w in mans + stks:
        wait_for(
            lambda: len(
                w.rpc.gethistory(["spend", "deposit", "cancel"], t1, t3, 20)["events"]
            )
            == 5
        )
