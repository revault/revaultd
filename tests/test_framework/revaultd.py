import logging
import os

from test_framework.utils import (
    TailableProc,
    VERBOSE,
    UnixDomainSocketRpc,
    LOG_LEVEL,
    wait_for,
)


class Revaultd(TailableProc):
    def __init__(
        self,
        datadir,
        stks,
        cosigs,
        mans,
        csv,
        noise_priv,
        coordinator_noise_key,
        coordinator_port,
        bitcoind,
        stk_config=None,
        man_config=None,
    ):
        assert stk_config is not None or man_config is not None
        assert len(stks) == len(cosigs)
        TailableProc.__init__(self, datadir, verbose=VERBOSE)

        self.prefix = os.path.split(datadir)[-1]

        # The data is stored in a per-network directory. We need to create it
        # in order to write the Noise private key
        datadir_with_network = os.path.join(datadir, "regtest")
        os.makedirs(datadir_with_network, exist_ok=True)

        bin = os.path.join(
            os.path.dirname(__file__), "..", "..", "target/debug/revaultd"
        )
        self.conf_file = os.path.join(datadir, "config.toml")
        self.cmd_line = [bin, "--conf", f"{self.conf_file}"]
        socket_path = os.path.join(datadir_with_network, "revaultd_rpc")
        self.rpc = UnixDomainSocketRpc(socket_path)

        noise_secret_file = os.path.join(datadir_with_network, "noise_secret")
        with open(noise_secret_file, "wb") as f:
            f.write(noise_priv)

        bitcoind_cookie = os.path.join(bitcoind.bitcoin_dir, "regtest", ".cookie")
        with open(self.conf_file, "w") as f:
            f.write(f"unvault_csv = {csv}\n")
            f.write(f"data_dir = '{datadir}'\n")
            f.write("daemon = false\n")
            f.write(f"log_level = '{LOG_LEVEL}'\n")

            f.write(f'coordinator_host = "127.0.0.1:{coordinator_port}"\n')
            f.write(f'coordinator_noise_key = "{coordinator_noise_key}"\n')
            f.write("coordinator_poll_seconds = 2\n")

            f.write("stakeholders_xpubs = [")
            for stk in stks:
                f.write(f'"{stk.get_xpub()}", ')
            f.write("]\n")

            f.write("managers_xpubs = [")
            for man in mans:
                f.write(f'"{man.get_xpub()}", ')
            f.write("]\n")

            f.write("cosigners_keys = [")
            for cosig in cosigs:
                f.write(f'"{cosig.get_static_key().hex()}", ')
            f.write("]\n")

            f.write("[bitcoind_config]\n")
            f.write('network = "regtest"\n')
            f.write(f"cookie_path = '{bitcoind_cookie}'\n")
            f.write(f"addr = '127.0.0.1:{bitcoind.rpcport}'\n")
            f.write("poll_interval_secs = 3\n")

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
                # FIXME: eventually use a real one here
                f.write(
                    "emergency_address = "
                    '"bcrt1qewc2348370pgw8kjz8gy09z8xyh0d9fxde6nzamd3txc9gkmjqmq8m4cdq"\n'
                )

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

    def stop(self):
        try:
            self.rpc.stop()
            self.wait_for_logs(
                [
                    "Stopping revaultd.",
                    "Bitcoind received shutdown.",
                    "Signature fetcher thread received shutdown.",
                ]
            )
            return 0
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
        stks,
        cosigs,
        mans,
        csv,
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
            stks,
            cosigs,
            mans,
            csv,
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
        stks,
        cosigs,
        mans,
        csv,
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
            stks,
            cosigs,
            mans,
            csv,
            noise_priv,
            coordinator_noise_key,
            coordinator_port,
            bitcoind,
            stk_config=stk_config,
        )
        assert self.stk_keychain is not None
