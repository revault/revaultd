import logging
import pytest
import os

from fixtures import *
from test_framework.utils import (
    TailableProc,
    POSTGRES_IS_SETUP,
    RpcError,
    wait_for,
    COIN,
)


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
def test_huge_deposit(revault_network, bitcoind):
    revault_network.deploy(2, 1)
    stk = revault_network.stk(0)
    amount = 13_000
    bitcoind.get_coins(amount)
    vault = revault_network.fund(amount)
    deposit = f"{vault['txid']}:{vault['vout']}"
    stk.wait_for_deposits([deposit])
    assert stk.rpc.listvaults([], [deposit])["vaults"][0]["amount"] == amount * COIN


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_revocation_sig_sharing(revault_network):
    revault_network.deploy(4, 2, n_stkmanagers=1)
    stks = revault_network.stks()
    mans = revault_network.mans()

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


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_raw_broadcast_cancel(revault_network, bitcoind):
    """
    Test broadcasting a dozen of pair of Unvault and Cancel for vaults with
    different derivation indexes.
    """
    revault_network.deploy(3, 2, n_stkmanagers=2)
    stks = revault_network.stks()
    mans = revault_network.mans()

    for i in range(10):
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


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_sigfetcher(revault_network, bitcoind, executor):
    rn = revault_network
    rn.deploy(7, 3, n_stkmanagers=2)
    # First of all, activate a vault
    vault = revault_network.fund(0.05)
    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)

    # Stopping revaultd, deleting the database
    for w in rn.participants():
        w.stop()
        datadir_db = os.path.join(w.datadir_with_network, "revaultd.sqlite3")
        os.remove(datadir_db)

    # Starting revaultd again
    for w in rn.participants():
        # Manually starting it so that we can check that
        # the db is being created again
        TailableProc.start(w)
        w.wait_for_logs(
            [
                "No database at .*, creating a new one",
                "revaultd started on network regtest",
                "bitcoind now synced",
                "JSONRPC server started",
                "Signature fetcher thread started",
            ]
        )

    # They should all get back to the 'active' state, pulling sigs from the coordinator
    for w in rn.participants():
        w.wait_for_log("Got a new unconfirmed deposit")
        wait_for(lambda: len(w.rpc.listvaults(["funded"], [])) == 1)
    for w in rn.stks():
        w.wait_for_logs(
            [
                "Fetching Unvault Emergency signature",
                "Fetching Emergency signature",
                "Fetching Cancel signature",
                "Fetching Unvault signature",
            ]
        )
    for w in rn.man_wallets:
        w.wait_for_logs(
            [
                "Fetching Cancel signature",
                "Fetching Unvault signature",
            ]
        )


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_stkman_only(revault_network, bitcoind):
    """Test a setup with only stakehodlers-managers"""
    rn = revault_network
    rn.deploy(n_stakeholders=0, n_managers=0, n_stkmanagers=3, csv=5)

    # They can spend
    vaults = rn.fundmany([1, 2])
    for v in vaults:
        rn.secure_vault(v)
        rn.activate_vault(v)
    rn.spend_vaults_anyhow(vaults)

    # They can revault
    vaults = rn.fundmany([3, 4, 5])
    for v in vaults:
        rn.secure_vault(v)
        rn.activate_vault(v)
    rn.unvault_vaults_anyhow(vaults)
    rn.cancel_vault(vaults[0])


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_no_cosig_server(revault_network):
    """Test a setup with no cosig"""
    rn = revault_network
    rn.deploy(n_stakeholders=2, n_managers=1, n_stkmanagers=1, with_cosigs=False, csv=2)

    # Sanity check they can spend and cancel
    vaults = rn.fundmany([4, 8, 16])
    rn.activate_fresh_vaults(vaults)
    rn.spend_vaults_anyhow(vaults[:2])
    rn.unvault_vaults_anyhow([vaults[-1]])
    rn.cancel_vault(vaults[-1])
