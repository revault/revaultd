import logging
import os
import toml

from test_framework.utils import (
    TailableProc,
    VERBOSE,
    LOG_LEVEL,
    MIRADORD_PATH,
)
from nacl.public import PrivateKey as Curve25519Private


# FIXME: it's a bit clumsy. Miradord should stick to be the `miradord` process object
# and we should have another class (PartialRevaultNetwork?) to stuff helpers and all
# info not strictly necessary to running the process.
class Miradord(TailableProc):
    def __init__(
        self,
        datadir,
        deposit_desc,
        unvault_desc,
        cpfp_desc,
        emer_addr,
        listen_port,
        noise_priv,
        stk_noise_key,
        coordinator_noise_key,
        coordinator_port,
        bitcoind,
        plugins=[],
    ):
        """All public keys must be hex"""
        TailableProc.__init__(self, datadir, verbose=VERBOSE)

        self.prefix = os.path.split(datadir)[-1]
        self.noise_secret = noise_priv
        self.listen_port = listen_port
        self.deposit_desc = deposit_desc
        self.unvault_desc = unvault_desc
        self.cpfp_desc = cpfp_desc
        self.emer_addr = emer_addr
        self.bitcoind = bitcoind

        # The data is stored in a per-network directory. We need to create it
        # in order to write the Noise private key
        self.datadir_with_network = os.path.join(datadir, "regtest")
        os.makedirs(self.datadir_with_network, exist_ok=True)

        self.conf_file = os.path.join(datadir, "config.toml")
        self.cmd_line = [MIRADORD_PATH, "--conf", f"{self.conf_file}"]

        self.noise_secret_file = os.path.join(self.datadir_with_network, "noise_secret")
        with open(self.noise_secret_file, "wb") as f:
            f.write(noise_priv)
        wt_noise_key = bytes(Curve25519Private(noise_priv).public_key)
        logging.debug(
            f"Watchtower Noise key: {wt_noise_key.hex()}, Stakeholder Noise key: {stk_noise_key}"
        )

        bitcoind_cookie = os.path.join(bitcoind.bitcoin_dir, "regtest", ".cookie")
        with open(self.conf_file, "w") as f:
            f.write(f"data_dir = '{datadir}'\n")
            f.write("daemon = false\n")
            f.write(f"log_level = '{LOG_LEVEL}'\n")

            f.write(f'stakeholder_noise_key = "{stk_noise_key}"\n')

            f.write(f'coordinator_host = "127.0.0.1:{coordinator_port}"\n')
            f.write(f'coordinator_noise_key = "{coordinator_noise_key}"\n')
            f.write("coordinator_poll_seconds = 5\n")

            f.write(f'listen = "127.0.0.1:{listen_port}"\n')

            f.write("[scripts_config]\n")
            f.write(f'deposit_descriptor = "{deposit_desc}"\n')
            f.write(f'unvault_descriptor = "{unvault_desc}"\n')
            f.write(f'cpfp_descriptor = "{cpfp_desc}"\n')
            f.write(f'emergency_address = "{emer_addr}"\n')

            f.write("[bitcoind_config]\n")
            f.write('network = "regtest"\n')
            f.write(f"cookie_path = '{bitcoind_cookie}'\n")
            f.write(f"addr = '127.0.0.1:{bitcoind.rpcport}'\n")
            f.write("poll_interval_secs = 5\n")

            f.write(f"\n{toml.dumps({'plugins': plugins})}\n")

    def start(self):
        TailableProc.start(self)
        self.wait_for_logs(
            ["bitcoind now synced", "Listener thread started", "Started miradord."]
        )

    def stop(self, timeout=10):
        return TailableProc.stop(self)

    def cleanup(self):
        try:
            self.stop()
        except Exception:
            self.proc.kill()

    def add_plugins(self, plugins):
        """Takes a list of dict representing plugin config to add to the watchtower and
        restarts it."""
        self.stop()
        conf = toml.loads(open(self.conf_file, "r").read())
        if "plugins" not in conf:
            conf["plugins"] = []
        conf["plugins"] += plugins
        open(self.conf_file, "w").write(toml.dumps(conf))
        self.start()
