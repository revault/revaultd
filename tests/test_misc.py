import pytest
import os

from fixtures import *
from test_framework import serializations
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


def test_huge_deposit(revault_network, bitcoind):
    revault_network.deploy(2, 1)
    stk = revault_network.stk(0)
    amount = 13_000
    bitcoind.get_coins(amount)
    vault = revault_network.fund(amount)
    deposit = f"{vault['txid']}:{vault['vout']}"
    stk.wait_for_deposits([deposit])
    assert stk.rpc.listvaults([], [deposit])["vaults"][0]["amount"] == amount * COIN


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
    cancel_psbts = psbts["cancel_txs"]
    emer_psbt = psbts["emergency_tx"]
    unemer_psbt = psbts["emergency_unvault_tx"]
    for stk in stks:
        cancel_psbts = [
            stk.stk_keychain.sign_revocation_psbt(psbt, child_index)
            for psbt in cancel_psbts
        ]
        emer_psbt = stk.stk_keychain.sign_revocation_psbt(emer_psbt, child_index)
        unemer_psbt = stk.stk_keychain.sign_revocation_psbt(unemer_psbt, child_index)
    stks[0].rpc.revocationtxs(deposit, cancel_psbts, emer_psbt, unemer_psbt)
    assert stks[0].rpc.listvaults()["vaults"][0]["status"] == "secured"
    # Note that we can't pass it twice
    with pytest.raises(RpcError, match="Invalid vault status"):
        stks[0].rpc.revocationtxs(deposit, cancel_psbts, emer_psbt, unemer_psbt)
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
        cancel_psbts = [
            stk.stk_keychain.sign_revocation_psbt(psbt, child_index)
            for psbt in psbts["cancel_txs"]
        ]
        emer_psbt = stk.stk_keychain.sign_revocation_psbt(
            psbts["emergency_tx"], child_index
        )
        unemer_psbt = stk.stk_keychain.sign_revocation_psbt(
            psbts["emergency_unvault_tx"], child_index
        )
        stk.rpc.revocationtxs(deposit, cancel_psbts, emer_psbt, unemer_psbt)
    for stk in stks + mans:
        wait_for(lambda: len(stk.rpc.listvaults(["secured"], [deposit])["vaults"]) > 0)


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

        unvault_tx = revault_network.signed_unvault_psbt(
            deposit, vault["derivation_index"]
        )
        txid = bitcoind.rpc.sendrawtransaction(unvault_tx)
        bitcoind.generate_block(1, wait_for_mempool=txid)

        for w in stks + mans:
            wait_for(lambda: len(w.rpc.listvaults(["unvaulted"], [deposit])) == 1)

        cancel_tx = revault_network.signed_cancel_psbt(
            deposit, vault["derivation_index"]
        )
        txid = bitcoind.rpc.sendrawtransaction(cancel_tx)
        bitcoind.generate_block(1, wait_for_mempool=txid)

        for w in stks + mans:
            wait_for(lambda: len(w.rpc.listvaults(["canceled"], [deposit])) == 1)


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
                "Syncing Unvault Emergency signature",
                "Syncing Emergency signature",
                "Syncing Cancel signature",
                "Syncing Unvault signature",
            ]
        )
    for w in rn.man_wallets:
        w.wait_for_logs(
            [
                "Syncing Cancel signature",
                "Syncing Unvault signature",
            ]
        )


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_sigfetcher_coordinator_dead(revault_network, bitcoind):
    rn = revault_network
    rn.deploy(
        2,
        1,
        csv=1,
        with_cosigs=False,
        with_watchtowers=False,
    )
    vault = revault_network.fund(1)

    # We kill the coordinator
    for d in rn.daemons:
        if d not in rn.participants():
            d.stop()

    # Now we secure the vault
    deposit = f"{vault['txid']}:{vault['vout']}"
    for stk in rn.stks():
        stk.wait_for_deposits([deposit])
        psbts = stk.rpc.getrevocationtxs(deposit)
        cancel_psbts = [
            stk.stk_keychain.sign_revocation_psbt(psbt, vault["derivation_index"])
            for psbt in psbts["cancel_txs"]
        ]
        emer_psbt = stk.stk_keychain.sign_revocation_psbt(
            psbts["emergency_tx"], vault["derivation_index"]
        )
        unemer_psbt = stk.stk_keychain.sign_revocation_psbt(
            psbts["emergency_unvault_tx"], vault["derivation_index"]
        )

        # Revaultd complains because the coordinator is dead
        with pytest.raises(RpcError, match="Connection refused"):
            stk.rpc.revocationtxs(deposit, cancel_psbts, emer_psbt, unemer_psbt)

        # The sigfetcher tries to fetch the signatures, but fails
        stk.wait_for_log("Error while fetching signatures")
        wait_for(lambda: len(stk.rpc.listvaults(["securing"])["vaults"]) == 1)

    # Now we start the coordinator again, and the vault will be secured :)
    for d in rn.daemons:
        if d not in rn.participants():
            d.start()

    for stk in rn.stks():
        stk.wait_for_logs(
            [
                "Syncing Cancel signature",
                "Syncing Emergency signature",
                "Syncing Unvault Emergency signature",
            ]
        )
        stk.wait_for_secured_vaults([deposit])


def test_sigfetcher_secured_vaults(revault_network, bitcoind):
    """
    Test that unvault sigs are retrieved and stored for secured vault even if the
    daemon user did not start activating it or is not a stakeholder.
    """
    rn = revault_network
    rn.deploy(
        3,
        1,
        csv=1,
        with_cosigs=False,
        with_watchtowers=False,
    )
    vault = rn.fund(1)
    rn.secure_vault(vault)
    stks = rn.stks()

    outpoint = f"{vault['txid']}:{vault['vout']}"
    unvault_psbt = stks[0].rpc.getunvaulttx(outpoint)["unvault_tx"]
    unvault_psbt = stks[0].stk_keychain.sign_unvault_psbt(
        unvault_psbt, vault["derivation_index"]
    )
    stks[0].rpc.unvaulttx(outpoint, unvault_psbt)

    for stk in rn.participants():
        stk.wait_for_logs(
            [
                "Syncing Unvault signature",
            ]
        )
        wait_for(
            lambda: stk.rpc.listpresignedtransactions([outpoint])[
                "presigned_transactions"
            ][0]["unvault"]
            == unvault_psbt
        )


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


def get_unvault_txids(wallet, vaults):
    unvault_txids = []
    for vault in vaults:
        deposit = f"{vault['txid']}:{vault['vout']}"
        unvault_psbt = serializations.PSBT()
        unvault_b64 = wallet.rpc.listpresignedtransactions([deposit])[
            "presigned_transactions"
        ][0]["unvault"]
        unvault_psbt.deserialize(unvault_b64)
        unvault_psbt.tx.calc_sha256()
        unvault_txids.append(unvault_psbt.tx.hash)
    return unvault_txids


def test_cpfp_transaction(revault_network, bitcoind):
    CSV = 12
    revault_network.deploy(
        2,
        1,
        csv=CSV,
        bitcoind_rpc_mocks={"estimatesmartfee": {"feerate": 0.0005}},  # 50 sats/vbyte
    )
    man = revault_network.mans()[0]
    vaults = revault_network.fundmany([1, 2, 3])

    # Broadcast the unvaults and get their txids
    for vault in vaults:
        revault_network.secure_vault(vault)
        revault_network.activate_vault(vault)
    spend_psbt = revault_network.broadcast_unvaults_anyhow(vaults, priority=True)
    unvault_txids = get_unvault_txids(man, vaults)
    spend_txid = spend_psbt.tx.hash
    for w in revault_network.participants():
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulting"])["vaults"]) == len(vaults),
        )

    # If the feerate isn't significantly lower than the estimate, we won't feebump.
    # Note the Unvault txs have a fixed 24sat/vb feerate.
    entry = bitcoind.rpc.getmempoolentry(unvault_txids[0])
    assert int(entry["fees"]["base"] * COIN / entry["vsize"]) == 24
    revault_network.bitcoind_proxy.mocks["estimatesmartfee"] = {
        "feerate": 26 * 1_000 / COIN
    }
    bitcoind.generate_blocks_censor(1, unvault_txids)
    man.wait_for_logs(["Checking if transactions need CPFP...", "Nothing to CPFP"])

    # Now if we set a high-enough target feerate, this'll trigger the CPFP.
    revault_network.bitcoind_proxy.mocks["estimatesmartfee"] = {
        "feerate": 50 * 1_000 / COIN
    }
    bitcoind.generate_blocks_censor(1, unvault_txids)
    man.wait_for_log("CPFPed transactions")
    wait_for(lambda: len(bitcoind.rpc.getrawmempool()) == len(unvault_txids) + 1)
    for unvault_txid in unvault_txids:
        entry = bitcoind.rpc.getmempoolentry(unvault_txid)
        assert entry["descendantcount"] == 2
        package_feerate = entry["fees"]["descendant"] * COIN / entry["descendantsize"]
        assert package_feerate >= 50

    # Alright, now let's do everything again for the spend :tada:

    # Confirming the unvaults
    bitcoind.generate_block(1, wait_for_mempool=unvault_txids)
    for w in revault_network.participants():
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulted"])["vaults"]) == len(vaults),
        )

    bitcoind.generate_block(CSV - 1)
    man.wait_for_log(f"Succesfully broadcasted Spend tx '{spend_txid}'")

    for w in revault_network.participants():
        wait_for(
            lambda: len(w.rpc.listvaults(["spending"])["vaults"]) == len(vaults),
        )

    # Uh oh! The feerate is too low, miners aren't including our transaction...
    bitcoind.generate_blocks_censor(1, [spend_txid])
    man.wait_for_log(
        f"CPFPed transactions with ids '{{{spend_txid}}}'",
    )
    wait_for(lambda: len(bitcoind.rpc.getrawmempool()) == 2)
    entry = bitcoind.rpc.getmempoolentry(spend_txid)
    assert entry["descendantcount"] == 2
    package_feerate = entry["fees"]["descendant"] * COIN / entry["descendantsize"]
    assert package_feerate >= 50

    # Let's test that non-prioritized txs don't get cpfped
    amount = 0.24
    vault = revault_network.fund(amount)
    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)
    spend_psbt = revault_network.unvault_vaults_anyhow([vault], priority=False)
    spend_txid = spend_psbt.tx.hash
    bitcoind.generate_block(CSV - 1)
    man.wait_for_log(
        f"Succesfully broadcasted Spend tx '{spend_txid}'",
    )
    bitcoind.generate_blocks_censor(1, [spend_txid])
    man.wait_for_logs(["Checking if transactions need CPFP...", "Nothing to CPFP"])


def test_batched_cpfp_transaction(revault_network, bitcoind):
    rn = revault_network
    CSV = 6
    rn.deploy(
        2,
        1,
        csv=CSV,
        bitcoind_rpc_mocks={"estimatesmartfee": {"feerate": 1 * 1_000 / COIN}},
    )
    man = rn.mans()[0]

    bitcoind.generate_block(10)
    vaults = rn.fundmany(list(range(1, 11)))
    rn.activate_fresh_vaults(vaults)

    # Separate the vaults into 3 spends
    first_batch, sec_batch, thi_batch = vaults[:3], vaults[3:5], vaults[5:]
    first_unvaults = get_unvault_txids(man, first_batch)
    second_unvaults = get_unvault_txids(man, sec_batch)
    third_unvaults = get_unvault_txids(man, thi_batch)

    # Broadcast the first batch of unvaults, feerate starts rising but not yet enough
    # to make us feebump.
    first_spend_psbt = revault_network.broadcast_unvaults_anyhow(
        first_batch, priority=True
    )
    first_spend = first_spend_psbt.tx.hash
    revault_network.bitcoind_proxy.mocks["estimatesmartfee"] = {
        "feerate": 10 * 1_000 / COIN
    }
    bitcoind.generate_blocks_censor(1, first_unvaults)
    man.wait_for_logs(["Checking if transactions need CPFP...", "Nothing to CPFP"])

    # Another block comes in, and we proceed with another Spend.
    bitcoind.generate_blocks_censor(1, first_unvaults)
    man.wait_for_logs(["Checking if transactions need CPFP...", "Nothing to CPFP"])
    second_spend_psbt = revault_network.broadcast_unvaults_anyhow(
        sec_batch, priority=True
    )
    second_spend = second_spend_psbt.tx.hash

    # At this point, one of the first unvaults gets mined, but not the other. Feerate
    # spikes and makes us feebump: we'll create a CPFP tx spending the remaining unconfirmed
    # Unvault from the first batch, and the 2 unvaults of the second spend.
    revault_network.bitcoind_proxy.mocks["estimatesmartfee"] = {
        "feerate": 30 * 1_000 / COIN  # 30 is 6sats/vb above, should trigger CPFP
    }
    unvaults = first_unvaults[1:] + second_unvaults
    bitcoind.generate_blocks_censor(1, unvaults)
    man.wait_for_log(
        f"CPFPed transactions with ids '{{.*{unvaults[0]}.*}}'",
    )
    wait_for(lambda: len(bitcoind.rpc.getrawmempool()) == len(unvaults) + 1)
    cpfp_txid = next(
        txid for txid in bitcoind.rpc.getrawmempool() if txid not in unvaults
    )
    cpfp_entry = bitcoind.rpc.getmempoolentry(cpfp_txid)
    assert cpfp_entry["fees"]["ancestor"] * COIN / cpfp_entry["ancestorsize"] >= 30
    assert len(cpfp_entry["depends"]) == len(unvaults)
    for txid in unvaults:
        assert txid in cpfp_entry["depends"]

    # Now get to be able to broadcast the second Spend. Note that both Spend transactions
    # are only broadcastable at the last block, but revaultd might be lagging behind: it
    # is possible it polls the tip at block CSV-1 and actually manage to broadcast a Spend
    # since bitcoind is already at block CSV. It would then trigger CPFP for the Spend(s)
    # alone when mining the last block, and fail the test later on when we assert that we
    # CPFP the two spends and the unvaults at once.
    # Therefore we make sure revaultd is sync'ed before we mine the last block.
    height = man.rpc.getinfo()["blockheight"]
    bitcoind.generate_block(CSV - 1, wait_for_mempool=unvaults + [cpfp_txid])
    wait_for(lambda: man.rpc.getinfo()["blockheight"] == height + CSV - 1)
    bitcoind.generate_block(1)
    man.wait_for_logs(
        [
            f"broadcasted Spend tx '{first_spend}'",
            f"broadcasted Spend tx '{second_spend}'",
        ]
    )
    wait_for(lambda: len(bitcoind.rpc.getrawmempool()) == 2)

    # In the meantime, we attempt a third Spend.
    third_spend_psbt = revault_network.broadcast_unvaults_anyhow(
        thi_batch, priority=True
    )
    third_spend = third_spend_psbt.tx.hash

    # If they don't get mined we'll CPFP all at once.
    to_be_cpfped = [first_spend, second_spend] + third_unvaults
    bitcoind.generate_blocks_censor(1, to_be_cpfped)
    man.wait_for_log(
        f"CPFPed transactions with ids '{{.*{to_be_cpfped[0]}.*}}'",
    )
    wait_for(lambda: len(bitcoind.rpc.getrawmempool()) == len(to_be_cpfped) + 1)
    cpfp_txid = next(
        txid for txid in bitcoind.rpc.getrawmempool() if txid not in to_be_cpfped
    )
    cpfp_entry = bitcoind.rpc.getmempoolentry(cpfp_txid)
    assert cpfp_entry["fees"]["ancestor"] * COIN / cpfp_entry["ancestorsize"] >= 30
    assert len(cpfp_entry["depends"]) == len(to_be_cpfped)
    for txid in to_be_cpfped:
        assert txid in cpfp_entry["depends"]

    # Eventually, everything gets mined and everyone's happy
    bitcoind.generate_block(CSV, wait_for_mempool=to_be_cpfped)
    man.wait_for_log(f"broadcasted Spend tx '{third_spend}'")
    bitcoind.generate_block(1, wait_for_mempool=[third_spend])
    wait_for(lambda: len(man.rpc.listvaults(["spent"])["vaults"]) == len(vaults))


def test_rbfed_cpfp_transaction(revault_network, bitcoind):
    """We don't have explicit RBF logic, but since we signal for it we should
    be able to replace a previous CPFP with a higher-fee, higher-feerate one.
    NOTE: we unfortunately can't replace it with one adding new to_be_cpfped transactions
    as it would add new unconfirmed inputs. Hopefully this is going to change soon.
    """
    rn = revault_network
    CSV = 6
    rn.deploy(
        2,
        1,
        csv=CSV,
        with_watchtowers=False,
        bitcoind_rpc_mocks={"estimatesmartfee": {"feerate": 1 * 1_000 / COIN}},
    )
    man = rn.mans()[0]

    vaults = rn.fundmany(list(range(1, 4)))
    rn.activate_fresh_vaults(vaults)

    # Trigger CPFP for all the unvaults
    unvaults = get_unvault_txids(man, vaults)
    revault_network.broadcast_unvaults_anyhow(vaults, priority=True)
    revault_network.bitcoind_proxy.mocks["estimatesmartfee"] = {
        "feerate": 50 * 1_000 / COIN
    }
    bitcoind.generate_blocks_censor(1, unvaults)
    man.wait_for_log(
        f"CPFPed transactions with ids '{{.*{unvaults[0]}.*}}'",
    )
    wait_for(lambda: len(bitcoind.rpc.getrawmempool()) == len(unvaults) + 1)
    cpfp_txid = next(
        txid for txid in bitcoind.rpc.getrawmempool() if txid not in unvaults
    )
    cpfp_entry = bitcoind.rpc.getmempoolentry(cpfp_txid)
    assert cpfp_entry["fees"]["ancestor"] * COIN / cpfp_entry["ancestorsize"] >= 50
    assert len(cpfp_entry["depends"]) == len(unvaults)
    for txid in unvaults:
        assert txid in cpfp_entry["depends"]

    # Now if the feerate spikes we should be able to replace the former CPFP tx
    # with an updated one.
    revault_network.bitcoind_proxy.mocks["estimatesmartfee"] = {
        "feerate": 80 * 1_000 / COIN
    }
    bitcoind.generate_blocks_censor(1, unvaults)
    wait_for(lambda: cpfp_txid not in bitcoind.rpc.getrawmempool())
    wait_for(lambda: len(bitcoind.rpc.getrawmempool()) == len(unvaults) + 1)
    new_cpfp_txid = next(
        txid for txid in bitcoind.rpc.getrawmempool() if txid not in unvaults
    )
    assert new_cpfp_txid != cpfp_txid
    cpfp_entry = bitcoind.rpc.getmempoolentry(new_cpfp_txid)
    assert cpfp_entry["fees"]["ancestor"] * COIN / cpfp_entry["ancestorsize"] >= 80
    assert len(cpfp_entry["depends"]) == len(unvaults)
    for txid in unvaults:
        assert txid in cpfp_entry["depends"]

    # And if the first Unvault automagically gets confirmed alone and feerate
    # continue to spike, we can replace the CPFP with one paying a higher feerate
    # (and fee) but spending only the two remaining ones
    revault_network.bitcoind_proxy.mocks["estimatesmartfee"] = {
        "feerate": 110 * 1_000 / COIN
    }
    bitcoind.generate_blocks_censor(1, unvaults[1:])
    man.wait_for_log(f"Unvault transaction at {unvaults[0]}.* is now confirmed")
    bitcoind.generate_blocks_censor(1, unvaults[1:])
    cpfp_txid = new_cpfp_txid
    wait_for(lambda: cpfp_txid not in bitcoind.rpc.getrawmempool())
    wait_for(lambda: len(bitcoind.rpc.getrawmempool()) == len(unvaults[1:]) + 1)
    new_cpfp_txid = next(
        txid for txid in bitcoind.rpc.getrawmempool() if txid not in unvaults[1:]
    )
    assert new_cpfp_txid != cpfp_txid
    cpfp_entry = bitcoind.rpc.getmempoolentry(new_cpfp_txid)
    assert len(cpfp_entry["depends"]) == len(unvaults[1:])
    for txid in unvaults[1:]:
        assert txid in cpfp_entry["depends"]
    assert unvaults[0] not in cpfp_entry["depends"]
