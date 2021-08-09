import bip32
import bitcoin
import logging
import os
import random

from bitcoin.wallet import CBitcoinSecret
from ephemeral_port_reserve import reserve
from nacl.public import PrivateKey as Curve25519Private
from test_framework import serializations
from test_framework.coordinatord import Coordinatord
from test_framework.cosignerd import Cosignerd
from test_framework.revaultd import ManagerRevaultd, StakeholderRevaultd, StkManRevaultd
from test_framework.utils import (
    get_descriptors,
    get_participants,
    wait_for,
    RpcError,
    TIMEOUT,
)


class RevaultNetwork:
    # FIXME: we use a single bitcoind for all the wallets because it's much
    # more efficient. Eventually, we may have to test with separate ones.
    def __init__(
        self,
        root_dir,
        bitcoind,
        executor,
        postgres_user,
        postgres_pass,
        postgres_host="localhost",
    ):
        self.root_dir = root_dir
        self.bitcoind = bitcoind
        self.daemons = []

        self.executor = executor

        self.postgres_user = postgres_user
        self.postgres_pass = postgres_pass
        self.postgres_host = postgres_host
        self.coordinator_port = reserve()

        self.stk_wallets = []
        self.stkman_wallets = []
        self.man_wallets = []

        self.csv = None
        self.emergency_address = None

    def deploy(
        self,
        n_stakeholders,
        n_managers,
        n_stkmanagers=0,
        csv=None,
        managers_threshold=None,
    ):
        """
        Deploy a revault setup with {n_stakeholders} stakeholders, {n_managers}
        managers.
        """
        # They didn't provide it, defaults to n_managers
        # PS: No I can't just managers_threshold=n_managers in the method's signature :(
        if managers_threshold == None:
            managers_threshold = n_managers + n_stkmanagers

        assert n_stakeholders + n_stkmanagers >= 2, "Not enough stakeholders"
        assert n_managers + n_stkmanagers >= 1, "Not enough managers"
        assert managers_threshold <= n_managers + n_stkmanagers, "Invalid threshold"

        (
            stkonly_keychains,
            stkonly_cosig_keychains,
            manonly_keychains,
            stkman_stk_keychains,
            stkman_cosig_keychains,
            stkman_man_keychains,
        ) = get_participants(n_stakeholders, n_managers, n_stkmanagers)
        stks_keychains = stkonly_keychains + stkman_stk_keychains
        cosigs_keychains = stkonly_cosig_keychains + stkman_cosig_keychains
        mans_keychains = manonly_keychains + stkman_man_keychains

        if csv is None:
            # Not more than 6 months
            csv = random.randint(1, 26784)
        self.csv = csv

        # TODO: implement CPFP
        cpfp_xpubs = [
            bip32.BIP32.from_seed(os.urandom(32)).get_master_xpub()
            for _ in range(len(mans_keychains))
        ]
        stks_xpubs = [stk.get_xpub() for stk in stks_keychains]
        cosigs_keys = [cosig.get_static_key().hex() for cosig in cosigs_keychains]
        mans_xpubs = [man.get_xpub() for man in mans_keychains]
        (deposit_desc, unvault_desc, cpfp_desc) = get_descriptors(
            stks_xpubs, cosigs_keys, mans_xpubs, managers_threshold, cpfp_xpubs, csv
        )
        # Generate a dummy 2of2 to be used as our Emergency address
        bitcoin.SelectParams("regtest")
        pka = str(CBitcoinSecret.from_secret_bytes(os.urandom(32)))
        pkb = str(CBitcoinSecret.from_secret_bytes(os.urandom(32)))
        desc = f"wsh(multi(2,{pka},{pkb}))"
        checksum = self.bitcoind.rpc.getdescriptorinfo(desc)["checksum"]
        desc = f"{desc}#{checksum}"
        self.emergency_address = self.bitcoind.rpc.deriveaddresses(desc)[0]
        desc_import = self.bitcoind.rpc.importdescriptors(
            [
                {
                    "desc": desc,
                    "timestamp": "now",
                    "label": "revault-emergency",
                }
            ]
        )
        if not desc_import[0]["success"]:
            raise Exception(desc_import)

        # FIXME: this is getting dirty.. We should re-centralize information
        # about each participant in specified data structures
        stkonly_cosigners_ports = []
        stkman_cosigners_ports = []

        # The Noise keys are interdependant, so generate everything in advance
        # to avoid roundtrips
        coordinator_noisepriv = os.urandom(32)
        coordinator_noisepub = bytes(
            Curve25519Private(coordinator_noisepriv).public_key
        )

        (stkonly_noiseprivs, stkonly_noisepubs) = ([], [])
        (stkonly_wt_noiseprivs, stkonly_wt_noisepubs) = ([], [])
        (stkonly_cosig_noiseprivs, stkonly_cosig_noisepubs) = ([], [])
        for i in range(len(stkonly_keychains)):
            stkonly_noiseprivs.append(os.urandom(32))
            stkonly_noisepubs.append(
                bytes(Curve25519Private(stkonly_noiseprivs[i]).public_key)
            )
            stkonly_cosig_noiseprivs.append(os.urandom(32))
            stkonly_cosig_noisepubs.append(
                bytes(Curve25519Private(stkonly_cosig_noiseprivs[i]).public_key)
            )
            # Unused yet
            stkonly_wt_noiseprivs.append(os.urandom(32))
            stkonly_wt_noisepubs.append(
                bytes(Curve25519Private(stkonly_wt_noiseprivs[i]).public_key)
            )

        (stkman_noiseprivs, stkman_noisepubs) = ([], [])
        (stkman_wt_noiseprivs, stkman_wt_noisepubs) = ([], [])
        (stkman_cosig_noiseprivs, stkman_cosig_noisepubs) = ([], [])
        for i in range(len(stkman_stk_keychains)):
            stkman_noiseprivs.append(os.urandom(32))
            stkman_noisepubs.append(
                bytes(Curve25519Private(stkman_noiseprivs[i]).public_key)
            )
            stkman_cosig_noiseprivs.append(os.urandom(32))
            stkman_cosig_noisepubs.append(
                bytes(Curve25519Private(stkman_cosig_noiseprivs[i]).public_key)
            )
            # Unused yet
            stkman_wt_noiseprivs.append(os.urandom(32))
            stkman_wt_noisepubs.append(
                bytes(Curve25519Private(stkman_wt_noiseprivs[i]).public_key)
            )

        (man_noiseprivs, man_noisepubs) = ([], [])
        for i in range(len(manonly_keychains)):
            man_noiseprivs.append(os.urandom(32))
            man_noisepubs.append(bytes(Curve25519Private(man_noiseprivs[i]).public_key))

        logging.debug(
            f"Using Noise pubkeys:\n- Stakeholders: {stkonly_noisepubs + stkman_noisepubs}"
            f" (of which {len(stkman_noisepubs)} are also managers)"
            f"\n- Managers: {man_noisepubs}\n- Watchtowers:"
            f"{stkonly_wt_noisepubs + stkman_wt_noisepubs}\n"
        )

        # Spin up the "Sync Server"
        coord_datadir = os.path.join(self.root_dir, "coordinatord")
        os.makedirs(coord_datadir, exist_ok=True)
        coordinatord = Coordinatord(
            coord_datadir,
            coordinator_noisepriv,
            man_noisepubs + stkman_noisepubs,
            stkonly_noisepubs + stkman_noisepubs,
            stkonly_wt_noisepubs + stkman_wt_noisepubs,
            self.coordinator_port,
            self.postgres_user,
            self.postgres_pass,
            self.postgres_host,
        )
        coordinatord.start()
        self.daemons.append(coordinatord)

        cosigners_info = []
        for (i, noisepub) in enumerate(stkonly_cosig_noisepubs):
            stkonly_cosigners_ports.append(reserve())
            cosigners_info.append(
                {
                    "host": f"127.0.0.1:{stkonly_cosigners_ports[i]}",
                    "noise_key": noisepub,
                }
            )
        for (i, noisepub) in enumerate(stkman_cosig_noisepubs):
            stkman_cosigners_ports.append(reserve())
            cosigners_info.append(
                {
                    "host": f"127.0.0.1:{stkman_cosigners_ports[i]}",
                    "noise_key": noisepub,
                }
            )

        # Start daemons in parallel, as it takes a few seconds for each
        start_jobs = []

        # Spin up the stakeholders wallets and their cosigning servers
        for i, stk in enumerate(stkonly_keychains):
            datadir = os.path.join(self.root_dir, f"revaultd-stk-{i}")
            os.makedirs(datadir, exist_ok=True)

            stk_config = {
                "keychain": stk,
                # FIXME: Eventually use real ones
                "watchtowers": [
                    {
                        "host": "127.0.0.1:1",
                        "noise_key": os.urandom(32),
                    }
                ],
                "emergency_address": self.emergency_address,
            }

            revaultd = StakeholderRevaultd(
                datadir,
                deposit_desc,
                unvault_desc,
                cpfp_desc,
                stkonly_noiseprivs[i],
                coordinator_noisepub.hex(),
                self.coordinator_port,
                self.bitcoind,
                stk_config,
            )
            start_jobs.append(self.executor.submit(revaultd.start))
            self.stk_wallets.append(revaultd)

            datadir = os.path.join(self.root_dir, f"cosignerd-stk-{i}")
            os.makedirs(datadir, exist_ok=True)

            cosignerd = Cosignerd(
                datadir,
                stkonly_cosig_noiseprivs[i],
                stkonly_cosig_keychains[i].get_bitcoin_priv(),
                stkonly_cosigners_ports[i],
                man_noisepubs + stkman_noisepubs,
            )
            start_jobs.append(self.executor.submit(cosignerd.start))
            self.daemons.append(cosignerd)

        # Spin up the stakeholder-managers wallets and their cosigning servers
        for i, stkman in enumerate(stkman_stk_keychains):
            datadir = os.path.join(self.root_dir, f"revaultd-stkman-{i}")
            os.makedirs(datadir, exist_ok=True)

            stk_config = {
                "keychain": stkman,
                # FIXME: Eventually use real ones
                "watchtowers": [
                    {
                        "host": "127.0.0.1:1",
                        "noise_key": os.urandom(32),
                    }
                ],
                "emergency_address": self.emergency_address,
            }
            man_config = {
                "keychain": stkman_man_keychains[i],
                "cosigners": cosigners_info,
            }

            revaultd = StkManRevaultd(
                datadir,
                deposit_desc,
                unvault_desc,
                cpfp_desc,
                stkman_noiseprivs[i],
                coordinator_noisepub.hex(),
                self.coordinator_port,
                self.bitcoind,
                stk_config,
                man_config,
            )
            start_jobs.append(self.executor.submit(revaultd.start))
            self.stkman_wallets.append(revaultd)

            datadir = os.path.join(self.root_dir, f"cosignerd-stkman-{i}")
            os.makedirs(datadir, exist_ok=True)

            cosignerd = Cosignerd(
                datadir,
                stkman_cosig_noiseprivs[i],
                stkman_cosig_keychains[i].get_bitcoin_priv(),
                stkman_cosigners_ports[i],
                man_noisepubs + stkman_noisepubs,
            )
            start_jobs.append(self.executor.submit(cosignerd.start))
            self.daemons.append(cosignerd)

        # Spin up the managers (only) wallets
        for i, man in enumerate(manonly_keychains):
            datadir = os.path.join(self.root_dir, f"revaultd-man-{i}")
            os.makedirs(datadir, exist_ok=True)

            man_config = {"keychain": man, "cosigners": cosigners_info}
            daemon = ManagerRevaultd(
                datadir,
                deposit_desc,
                unvault_desc,
                cpfp_desc,
                man_noiseprivs[i],
                coordinator_noisepub.hex(),
                self.coordinator_port,
                self.bitcoind,
                man_config,
            )
            start_jobs.append(self.executor.submit(daemon.start))
            self.man_wallets.append(daemon)

        for j in start_jobs:
            j.result(TIMEOUT)

        self.daemons += self.stk_wallets + self.stkman_wallets + self.man_wallets

    def mans(self):
        return self.stkman_wallets + self.man_wallets

    def stks(self):
        return self.stkman_wallets + self.stk_wallets

    def participants(self):
        return self.stkman_wallets + self.stk_wallets + self.man_wallets

    def man(self, n):
        """Get the {n}th manager (including the stakeholder-managers first)"""
        mans = self.stkman_wallets + self.man_wallets
        return mans[n]

    def stk(self, n):
        """Get the {n}th stakeholder (including the stakeholder-managers first)"""
        stks = self.stkman_wallets + self.stk_wallets
        return stks[n]

    def get_vault(self, address):
        """Get a vault entry by outpoint or by address"""
        for v in self.man(0).rpc.listvaults()["vaults"]:
            if v["address"] == address:
                return v

    def fund(self, amount=None):
        """Deposit coins into the architectures, by paying to the deposit
        descriptor and getting the tx 6 blocks confirmations."""
        assert (
            len(self.man_wallets + self.stkman_wallets) > 0
        ), "You must have deploy()ed first"

        man = self.man(0)

        if amount is None:
            amount = 49.9999

        addr = man.rpc.getdepositaddress()["address"]
        txid = self.bitcoind.rpc.sendtoaddress(addr, amount)
        man.wait_for_log(f"Got a new unconfirmed deposit at {txid}")
        self.bitcoind.generate_block(6, wait_for_mempool=txid)
        man.wait_for_log(f"Vault at {txid}.* is now confirmed")

        vaults = man.rpc.listvaults(["funded"])["vaults"]
        for v in vaults:
            if v["txid"] == txid:
                for w in self.man_wallets + self.stk_wallets:
                    w.wait_for_deposits([f"{txid}:{v['vout']}"])
                return v

        raise Exception(f"Vault created by '{txid}' got in logs but not in listvaults?")

    def fundmany(self, amounts=[]):
        """Deposit coins into the architectures in a single transaction"""
        assert (
            len(self.man_wallets + self.stkman_wallets) > 0
        ), "You must have deploy()ed first"
        assert len(amounts) > 0, "You must provide at least an amount!"

        man = self.man(0)

        curr_index = 0
        vaults = man.rpc.listvaults()["vaults"]
        for v in vaults:
            if v["derivation_index"] > curr_index:
                curr_index = v["derivation_index"]

        indexes = list(range(curr_index + 1, curr_index + 1 + len(amounts)))
        amounts_sendmany = {}
        for i, amount in enumerate(amounts):
            amounts_sendmany[man.rpc.getdepositaddress(indexes[i])["address"]] = amount

        txid = self.bitcoind.rpc.sendmany("", amounts_sendmany)
        man.wait_for_logs(
            [f"Got a new unconfirmed deposit at {txid}" for _ in range(len(amounts))]
        )
        self.bitcoind.generate_block(6, wait_for_mempool=txid)
        man.wait_for_logs(
            [f"Vault at {txid}.* is now confirmed" for _ in range(len(amounts))]
        )

        # Return the vaults we created
        all_vaults = man.rpc.listvaults(["funded"])["vaults"]
        created_vaults = []
        for v in all_vaults:
            if v["txid"] == txid:
                created_vaults.append(v)
        assert len(created_vaults) == len(amounts)

        return created_vaults

    def secure_vault(self, vault):
        """Make all stakeholders share signatures for all revocation txs"""
        deposit = f"{vault['txid']}:{vault['vout']}"
        for stk in self.stks():
            stk.wait_for_deposits([deposit])
            psbts = stk.rpc.getrevocationtxs(deposit)
            cancel_psbt = stk.stk_keychain.sign_revocation_psbt(
                psbts["cancel_tx"], vault["derivation_index"]
            )
            emer_psbt = stk.stk_keychain.sign_revocation_psbt(
                psbts["emergency_tx"], vault["derivation_index"]
            )
            unemer_psbt = stk.stk_keychain.sign_revocation_psbt(
                psbts["emergency_unvault_tx"], vault["derivation_index"]
            )
            stk.rpc.revocationtxs(deposit, cancel_psbt, emer_psbt, unemer_psbt)
        for w in self.participants():
            w.wait_for_secured_vaults([deposit])

    def secure_vaults(self, vaults):
        """Secure all these vaults, concurrently."""
        sec_jobs = []
        for v in vaults:
            sec_jobs.append(self.executor.submit(self.secure_vault, v))
        for j in sec_jobs:
            j.result(TIMEOUT)

    def activate_vault(self, vault):
        """Make all stakeholders share signatures for the unvault tx"""
        deposit = f"{vault['txid']}:{vault['vout']}"
        for stk in self.stks():
            stk.wait_for_secured_vaults([deposit])
            unvault_psbt = stk.rpc.getunvaulttx(deposit)["unvault_tx"]
            unvault_psbt = stk.stk_keychain.sign_unvault_psbt(
                unvault_psbt, vault["derivation_index"]
            )
            stk.rpc.unvaulttx(deposit, unvault_psbt)
        for w in self.participants():
            w.wait_for_active_vaults([deposit])

    def activate_fresh_vaults(self, vaults):
        """Secure then activate all these vaults, concurrently."""
        # TODO: i'm sure we don't even need to wait for all sec jobs to be complete
        # before starting the activate_vault futures, given a high enough TIMEOUT.
        self.secure_vaults(vaults)

        act_jobs = []
        for v in vaults:
            act_jobs.append(self.executor.submit(self.activate_vault, v))
        for j in act_jobs:
            j.result(TIMEOUT)

    def unvault_vaults(self, vaults, destinations, feerate):
        """
        Unvault these {vaults}, advertizing a Spend tx spending to these {destinations}
        (mapping of addresses to amounts)
        """
        man = self.man(0)
        deposits = []
        deriv_indexes = []
        for v in vaults:
            deposits.append(f"{v['txid']}:{v['vout']}")
            deriv_indexes.append(v["derivation_index"])
        man.wait_for_active_vaults(deposits)

        spend_tx = man.rpc.getspendtx(deposits, destinations, feerate)["spend_tx"]
        for man in self.mans():
            spend_tx = man.man_keychain.sign_spend_psbt(spend_tx, deriv_indexes)
            man.rpc.updatespendtx(spend_tx)

        spend_psbt = serializations.PSBT()
        spend_psbt.deserialize(spend_tx)
        spend_psbt.tx.calc_sha256()
        man.rpc.setspendtx(spend_psbt.tx.hash)

        self.bitcoind.generate_block(1, wait_for_mempool=len(deposits))
        for w in self.participants():
            wait_for(
                lambda: len(w.rpc.listvaults(["unvaulted"], deposits)["vaults"])
                == len(deposits)
            )

    def spend_vaults_unconfirmed(self, vaults, destinations, feerate):
        """
        Spend these {vaults} to these {destinations} (mapping of addresses to amounts), not
        confirming the Spend transaction.
        Make sure to call this only with revault deployment with a low (<500) CSV, or you'll encounter
        an ugly timeout from bitcoinlib.

        :return: the list of spent deposits along with the Spend PSBT.
        """
        man = self.man(0)
        deposits = []
        deriv_indexes = []
        for v in vaults:
            deposits.append(f"{v['txid']}:{v['vout']}")
            deriv_indexes.append(v["derivation_index"])

        for man in self.mans():
            man.wait_for_active_vaults(deposits)

        spend_tx = man.rpc.getspendtx(deposits, destinations, feerate)["spend_tx"]
        for man in self.mans():
            spend_tx = man.man_keychain.sign_spend_psbt(spend_tx, deriv_indexes)
            man.rpc.updatespendtx(spend_tx)

        spend_psbt = serializations.PSBT()
        spend_psbt.deserialize(spend_tx)
        spend_psbt.tx.calc_sha256()
        man.rpc.setspendtx(spend_psbt.tx.hash)

        self.bitcoind.generate_block(1, wait_for_mempool=len(deposits))
        self.bitcoind.generate_block(self.csv)
        man.wait_for_log(
            f"Succesfully broadcasted Spend tx '{spend_psbt.tx.hash}'",
        )
        wait_for(
            lambda: len(self.man(0).rpc.listvaults(["spending"], deposits)["vaults"])
            == len(deposits)
        )

        return deposits, spend_psbt

    def spend_vaults(self, vaults, destinations, feerate):
        """
        Spend these {vaults} to these {destinations} (mapping of addresses to amounts).
        Make sure to call this only with revault deployment with a low (<500) CSV, or you'll encounter
        an ugly timeout from bitcoinlib.

        :return: the list of spent deposits along with the Spend PSBT.
        """
        deposits, spend_psbt = self.spend_vaults_unconfirmed(
            vaults, destinations, feerate
        )

        self.bitcoind.generate_block(1, wait_for_mempool=[spend_psbt.tx.hash])
        wait_for(
            lambda: len(self.man(0).rpc.listvaults(["spent"], deposits)["vaults"])
            == len(deposits)
        )

        return deposits, spend_psbt.tx.hash

    def _any_spend_data(self, vaults):
        addr = self.bitcoind.rpc.getnewaddress()
        total_spent = sum(v["amount"] for v in vaults)
        feerate = 2
        fees = self.compute_spendtx_fees(feerate, len(vaults), 1)
        return {addr: total_spent - fees}, feerate

    def unvault_vaults_anyhow(self, vaults):
        """
        Unvault these vaults with a random Spend transaction for a maximum amount and a
        fixed feerate.
        """
        destinations, feerate = self._any_spend_data(vaults)
        return self.unvault_vaults(vaults, destinations, feerate)

    def spend_vaults_anyhow(self, vaults):
        """Spend these vaults to a random address for a maximum amount for a fixed feerate"""
        destinations, feerate = self._any_spend_data(vaults)
        return self.spend_vaults(vaults, destinations, feerate)

    def spend_vaults_anyhow_unconfirmed(self, vaults):
        """
        Spend these vaults to a random address for a maximum amount for a fixed feerate,
        not confirming the Spend transaction.
        """
        destinations, feerate = self._any_spend_data(vaults)
        return self.spend_vaults_unconfirmed(vaults, destinations, feerate)

    def compute_spendtx_fees(
        self, spendtx_feerate, n_vaults_spent, n_destinations, with_change=False
    ):
        """Get the fees necessary to include in a Spend transaction.
        This assumes the destinations to be P2WPKH
        """
        n_stk = len(self.stks())
        n_man = len(self.mans())

        # witscript PUSH, keys , Unvault Script overhead, signatures
        spend_witness_vb = (
            1 + (n_man + n_stk * 2) * 34 + 15 + (n_man + n_stk) * 73
        ) // 4
        # Overhead, P2WPKH, P2WSH, inputs, witnesses
        spend_witstrip_vb = (
            11
            + 31 * n_destinations
            + 43 * (1 + (1 if with_change else 0))
            + (32 + 4 + 4 + 1) * n_vaults_spent
        )
        spendtx_vbytes = spend_witstrip_vb + spend_witness_vb * n_vaults_spent

        # witscript PUSH, keys , Deposit Script overhead, signatures
        unvault_witness_vb = (1 + n_stk * (34 + 73) + 3) // 4
        # Overhead, P2WSH * 2, inputs + witness
        unvaulttxs_vbytes = (
            11 + 43 * 2 + (32 + 4 + 4 + 1) + unvault_witness_vb
        ) * n_vaults_spent

        return (
            spendtx_vbytes * spendtx_feerate  # Spend fees
            + 2 * 32 * spendtx_vbytes  # Spend CPFP
            + unvaulttxs_vbytes * 24  # Unvault fees (6sat/WU feerate)
            + 30_000 * n_vaults_spent  # Unvault CPFP
        )

    def cancel_vault(self, vault):
        deposit = f"{vault['txid']}:{vault['vout']}"

        for w in self.participants():
            wait_for(
                lambda: len(
                    w.rpc.listvaults(
                        ["unvaulting", "unvaulted", "spending"], [deposit]
                    )["vaults"]
                )
                == 1
            )

        self.stk(0).rpc.revault(deposit)
        self.bitcoind.generate_block(1, wait_for_mempool=1)
        for w in self.participants():
            wait_for(
                lambda: len(w.rpc.listvaults(["canceled"], [deposit])["vaults"]) == 1
            )

    def stop_wallets(self):
        jobs = [self.executor.submit(w.stop) for w in self.participants()]
        for j in jobs:
            j.result(TIMEOUT)

    def start_wallets(self):
        jobs = [self.executor.submit(w.start) for w in self.participants()]
        for j in jobs:
            j.result(TIMEOUT)

    def cleanup(self):
        for n in self.daemons:
            n.cleanup()
