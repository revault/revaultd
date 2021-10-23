import logging
import os

from test_framework.utils import (
    TailableProc,
    VERBOSE,
    UnixDomainSocketRpc,
    LOG_LEVEL,
    wait_for,
    REVAULTD_PATH,
)


class Revaultd(TailableProc):
    def __init__(
        self,
        datadir,
        deposit_desc,
        unvault_desc,
        cpfp_desc,
        noise_priv,
        coordinator_noise_key,
        coordinator_port,
        bitcoind,
        stk_config=None,
        man_config=None,
    ):
        # set descriptors
        self.cpfp_desc = cpfp_desc
        self.deposit_desc = deposit_desc
        self.unvault_desc = unvault_desc

        assert stk_config is not None or man_config is not None
        TailableProc.__init__(self, datadir, verbose=VERBOSE)

        self.prefix = os.path.split(datadir)[-1]

        # The data is stored in a per-network directory. We need to create it
        # in order to write the Noise private key
        self.datadir_with_network = os.path.join(datadir, "regtest")
        os.makedirs(self.datadir_with_network, exist_ok=True)

        self.conf_file = os.path.join(datadir, "config.toml")
        self.cmd_line = [REVAULTD_PATH, "--conf", f"{self.conf_file}"]
        socket_path = os.path.join(self.datadir_with_network, "revaultd_rpc")
        self.rpc = UnixDomainSocketRpc(socket_path)

        noise_secret_file = os.path.join(self.datadir_with_network, "noise_secret")
        with open(noise_secret_file, "wb") as f:
            f.write(noise_priv)

        bitcoind_cookie = os.path.join(bitcoind.bitcoin_dir, "regtest", ".cookie")
        with open(self.conf_file, "w") as f:
            f.write(f"data_dir = '{datadir}'\n")
            f.write("daemon = false\n")
            f.write(f"log_level = '{LOG_LEVEL}'\n")

            f.write(f'coordinator_host = "127.0.0.1:{coordinator_port}"\n')
            f.write(f'coordinator_noise_key = "{coordinator_noise_key}"\n')
            f.write("coordinator_poll_seconds = 5\n")

            f.write("[scripts_config]\n")
            f.write(f'deposit_descriptor = "{deposit_desc}"\n')
            f.write(f'unvault_descriptor = "{unvault_desc}"\n')
            f.write(f'cpfp_descriptor = "{cpfp_desc}"\n')

            f.write("[bitcoind_config]\n")
            f.write('network = "regtest"\n')
            f.write(f"cookie_path = '{bitcoind_cookie}'\n")
            f.write(f"addr = '127.0.0.1:{bitcoind.rpcport}'\n")
            f.write("poll_interval_secs = 2\n")

            if stk_config is not None:
                f.write("[stakeholder_config]\n")
                self.stk_keychain = stk_config["keychain"]
                f.write(f'xpub = "{self.stk_keychain.get_xpub()}"\n')
                f.write("watchtowers = [")
                for wt in stk_config["watchtowers"]:
                    f.write(
                        f"{{ \"host\" = \"{wt['host']}\", \"noise_key\" = "
                        f"\"{wt['noise_key'].hex()}\" }}, "
                    )
                f.write("]\n")
                f.write(f"emergency_address = \"{stk_config['emergency_address']}\"\n")

            if man_config is not None:
                f.write("[manager_config]\n")
                self.man_keychain = man_config["keychain"]
                f.write(f'xpub = "{self.man_keychain.get_xpub()}"\n')
                for cosig in man_config["cosigners"]:
                    f.write("[[manager_config.cosigners]]\n")
                    f.write(f"host = \"{cosig['host']}\"\n")
                    f.write(f"noise_key = \"{cosig['noise_key'].hex()}\"\n")

    def wait_for_deposits(self, outpoints):
        """
        Polls listvaults until we acknowledge the confirmed vaults at {outpoints}
        """
        assert isinstance(outpoints, list)
        wait_for(
            lambda: len(self.rpc.listvaults(["funded"], outpoints)["vaults"])
            == len(outpoints)
        )

    def wait_for_secured_vaults(self, outpoints):
        """
        Polls listvaults until we acknowledge the 'secured' :tm: vaults at {outpoints}
        """
        assert isinstance(outpoints, list)
        wait_for(
            lambda: len(self.rpc.listvaults(["secured"], outpoints)["vaults"])
            == len(outpoints)
        )

    def wait_for_active_vaults(self, outpoints):
        """
        Polls listvaults until we acknowledge the active vaults at {outpoints}
        """
        assert isinstance(outpoints, list)
        wait_for(
            lambda: len(self.rpc.listvaults(["active"], outpoints)["vaults"])
            == len(outpoints)
        )

    def start(self):
        TailableProc.start(self)
        self.wait_for_logs(
            [
                "revaultd started on network regtest",
                "bitcoind now synced",
                "JSONRPC server started",
                "Signature fetcher thread started",
            ]
        )

    def stop(self, timeout=10):
        try:
            self.rpc.stop()
            self.wait_for_logs(
                [
                    "Stopping revaultd.",
                    "Bitcoind received shutdown.",
                    "Signature fetcher thread received shutdown.",
                ]
            )
            self.proc.wait(timeout)
        except Exception as e:
            logging.error(f"{self.prefix} : error when calling stop: '{e}'")
        return TailableProc.stop(self)

    def cleanup(self):
        try:
            self.stop()
        except Exception:
            self.proc.kill()


class ManagerRevaultd(Revaultd):
    def __init__(
        self,
        datadir,
        deposit_desc,
        unvault_desc,
        cpfp_desc,
        noise_priv,
        coordinator_noise_key,
        coordinator_port,
        bitcoind,
        man_config,
    ):
        """The wallet daemon for a manager.
        Needs to know all xpubs, and needs to be able to connect to the
        coordinator and the cosigners.
        """
        super(ManagerRevaultd, self).__init__(
            datadir,
            deposit_desc,
            unvault_desc,
            cpfp_desc,
            noise_priv,
            coordinator_noise_key,
            coordinator_port,
            bitcoind,
            man_config=man_config,
        )
        assert self.man_keychain is not None


class StakeholderRevaultd(Revaultd):
    def __init__(
        self,
        datadir,
        deposit_desc,
        unvault_desc,
        cpfp_desc,
        noise_priv,
        coordinator_noise_key,
        coordinator_port,
        bitcoind,
        stk_config,
    ):
        """The wallet daemon for a stakeholder.
        Needs to know all xpubs, and needs to be able to connect to the
        coordinator and its watchtower(s).
        """
        super(StakeholderRevaultd, self).__init__(
            datadir,
            deposit_desc,
            unvault_desc,
            cpfp_desc,
            noise_priv,
            coordinator_noise_key,
            coordinator_port,
            bitcoind,
            stk_config,
            man_config=None,
        )
        assert self.stk_keychain is not None


class StkManRevaultd(Revaultd):
    def __init__(
        self,
        datadir,
        deposit_desc,
        unvault_desc,
        cpfp_desc,
        noise_priv,
        coordinator_noise_key,
        coordinator_port,
        bitcoind,
        stk_config,
        man_config,
    ):
        """A revaultd instance that is both stakeholder and manager."""
        super(StkManRevaultd, self).__init__(
            datadir,
            deposit_desc,
            unvault_desc,
            cpfp_desc,
            noise_priv,
            coordinator_noise_key,
            coordinator_port,
            bitcoind,
            stk_config,
            man_config,
        )
