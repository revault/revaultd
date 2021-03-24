import logging
import os
import random

from ephemeral_port_reserve import reserve
from nacl.public import PrivateKey as Curve25519Private
from test_framework.coordinatord import Coordinatord
from test_framework.revaultd import ManagerRevaultd, StakeholderRevaultd
from test_framework.utils import get_participants, wait_for


class RevaultNetwork:
    # FIXME: we use a single bitcoind for all the wallets because it's much
    # more efficient. Eventually, we may have to test with separate ones.
    def __init__(
        self,
        root_dir,
        bitcoind,
        postgres_user,
        postgres_pass,
        postgres_host="localhost",
    ):
        self.root_dir = root_dir
        self.bitcoind = bitcoind
        self.daemons = []

        self.postgres_user = postgres_user
        self.postgres_pass = postgres_pass
        self.postgres_host = postgres_host
        self.coordinator_port = reserve()

        self.stk_wallets = []
        self.man_wallets = []

    def deploy(self, n_stakeholders, n_managers, csv=None):
        """
        Deploy a revault setup with {n_stakeholders} stakeholders, {n_managers}
        managers and optionally fund it with {funding} sats.
        """
        (stks, cosigs, mans) = get_participants(n_stakeholders, n_managers)
        if csv is None:
            # Not more than 6 months
            csv = random.randint(1, 26784)

        # The Noise keys are interdependant, so generate everything in advance
        # to avoid roundtrips
        coordinator_noisepriv = os.urandom(32)
        coordinator_noisepub = bytes(
            Curve25519Private(coordinator_noisepriv).public_key
        )
        (stk_noiseprivs, stk_noisepubs) = ([], [])
        (wt_noiseprivs, wt_noisepubs) = ([], [])
        for i in range(len(stks)):
            stk_noiseprivs.append(os.urandom(32))
            stk_noisepubs.append(bytes(Curve25519Private(stk_noiseprivs[i]).public_key))
            # Unused yet
            wt_noiseprivs.append(os.urandom(32))
            wt_noisepubs.append(bytes(Curve25519Private(wt_noiseprivs[i]).public_key))
        (man_noiseprivs, man_noisepubs) = ([], [])
        for i in range(len(mans)):
            man_noiseprivs.append(os.urandom(32))
            man_noisepubs.append(bytes(Curve25519Private(man_noiseprivs[i]).public_key))
        logging.debug(
            f"Using Noise pubkeys:\n- Stakeholders: {stk_noisepubs}"
            f"\n- Managers: {man_noisepubs}\n- Watchtowers:"
            f"{wt_noisepubs}\n"
        )

        # Spin up the "Sync Server"
        coord_datadir = os.path.join(self.root_dir, "coordinatord")
        os.makedirs(coord_datadir, exist_ok=True)
        coordinatord = Coordinatord(
            coord_datadir,
            coordinator_noisepriv,
            man_noisepubs,
            stk_noisepubs,
            wt_noisepubs,
            self.coordinator_port,
            self.postgres_user,
            self.postgres_pass,
            self.postgres_host,
        )
        coordinatord.start()
        self.daemons.append(coordinatord)

        # Spin up the stakeholders wallets
        for i in range(len(stks)):
            datadir = os.path.join(self.root_dir, f"revaultd-stk-{i}")
            os.makedirs(datadir, exist_ok=True)

            stk_config = {
                "keychain": stks[i],
                # FIXME: Eventually use real ones
                "watchtowers": [
                    {
                        "host": "127.0.0.1:1",
                        "noise_key": "03c3fee141e97ed33a50875a092179684c1145"
                        "5cc6f49a9bddaacf93cd77def697",
                    }
                ],
            }
            daemon = StakeholderRevaultd(
                datadir,
                stks,
                cosigs,
                mans,
                csv,
                stk_noiseprivs[i],
                coordinator_noisepub.hex(),
                self.coordinator_port,
                self.bitcoind,
                stk_config,
            )
            daemon.start()
            self.stk_wallets.append(daemon)

        # Spin up the managers wallets
        for i in range(len(mans)):
            datadir = os.path.join(self.root_dir, f"revaultd-man-{i}")
            os.makedirs(datadir, exist_ok=True)

            man_config = {
                "keychain": mans[i],
                # FIXME: Eventually use real ones
                "cosigners": [
                    {
                        "host": "127.0.0.1:1",
                        "noise_key": "03c3fee141e97ed33a50875a092179684c1145"
                        "5cc6f49a9bddaacf93cd77def697",
                    }
                ],
            }
            daemon = ManagerRevaultd(
                datadir,
                stks,
                cosigs,
                mans,
                csv,
                man_noiseprivs[i],
                coordinator_noisepub.hex(),
                self.coordinator_port,
                self.bitcoind,
                man_config,
            )
            daemon.start()
            self.man_wallets.append(daemon)

        self.daemons += self.stk_wallets + self.man_wallets
        # FIXME: we should not return them, they should access our members
        return (self.stk_wallets, self.man_wallets)

    def get_vault(self, address):
        """Get a vault entry by outpoint or by address"""
        for v in self.man_wallets[0].rpc.listvaults()["vaults"]:
            if v["address"] == address:
                return v

    def fund(self, amount=None):
        """Deposit coins into the architectures, by paying to the deposit
        descriptor and getting the tx 6 blocks confirmations."""
        assert len(self.man_wallets) > 0, "You must have deploy()ed first"

        if amount is None:
            amount = 49.9999

        addr = self.man_wallets[0].rpc.getdepositaddress()["address"]
        txid = self.bitcoind.rpc.sendtoaddress(addr, amount)
        self.bitcoind.generate_block(6, wait_for_mempool=txid)
        wait_for(lambda: self.get_vault(addr) is not None)

        return self.get_vault(addr)

    def secure_vault(self, vault):
        """Make all stakeholders share signatures for all revocation txs"""
        deposit = f"{vault['txid']}:{vault['vout']}"
        for stk in self.stk_wallets:
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
        for w in self.stk_wallets + self.man_wallets:
            w.wait_for_secured_vaults([deposit])

    def activate_vault(self, vault):
        """Make all stakeholders share signatures for the unvault tx"""
        deposit = f"{vault['txid']}:{vault['vout']}"
        for stk in self.stk_wallets:
            stk.wait_for_secured_vaults([deposit])
            unvault_psbt = stk.rpc.getunvaulttx(deposit)["unvault_tx"]
            unvault_psbt = stk.stk_keychain.sign_unvault_psbt(
                unvault_psbt, vault["derivation_index"]
            )
            stk.rpc.unvaulttx(deposit, unvault_psbt)
        for w in self.stk_wallets + self.man_wallets:
            w.wait_for_active_vaults([deposit])

    def stop_wallets(self):
        for w in self.stk_wallets + self.man_wallets:
            assert w.stop() == 0

    def start_wallets(self):
        for w in self.stk_wallets + self.man_wallets:
            w.start()

    def cleanup(self):
        for n in self.daemons:
            n.cleanup()
