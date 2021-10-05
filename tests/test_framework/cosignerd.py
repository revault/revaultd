import os

from test_framework.utils import (
    TailableProc,
    VERBOSE,
    LOG_LEVEL,
    COSIGNERD_PATH,
)


class Cosignerd(TailableProc):
    def __init__(
        self,
        datadir,
        noise_priv,
        bitcoin_priv,
        listen_port,
        managers_noisekeys,
    ):
        TailableProc.__init__(self, datadir, verbose=VERBOSE)
        self.conf_file = os.path.join(datadir, "config.toml")
        self.cmd_line = [COSIGNERD_PATH, "--conf", f"{self.conf_file}"]
        self.prefix = "cosignerd"

        noise_secret_file = os.path.join(datadir, "noise_secret")
        with open(noise_secret_file, "wb") as f:
            f.write(noise_priv)

        bitcoin_secret_file = os.path.join(datadir, "bitcoin_secret")
        with open(bitcoin_secret_file, "wb") as f:
            f.write(bitcoin_priv)

        with open(self.conf_file, "w") as f:
            f.write("daemon = false\n")
            f.write(f'data_dir = "{datadir}"\n')
            f.write(f'log_level = "{LOG_LEVEL}"\n')
            f.write(f'listen = "127.0.0.1:{listen_port}"\n')

            for k in managers_noisekeys:
                f.write("[[managers]]\n")
                f.write(f'    noise_key = "{k.hex()}"\n')

    def start(self):
        TailableProc.start(self)
        self.wait_for_log("Started cosignerd daemon")

    def cleanup(self):
        try:
            self.stop()
        except Exception:
            self.proc.kill()
