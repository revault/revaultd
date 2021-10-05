import os
import psycopg2

from test_framework.utils import TailableProc, VERBOSE, LOG_LEVEL, COORDINATORD_PATH


class Coordinatord(TailableProc):
    def __init__(
        self,
        datadir,
        noise_priv,
        managers_keys,
        stakeholders_keys,
        watchtowers_keys,
        listen_port,
        postgres_user,
        postgres_pass,
        postgres_host="localhost",
    ):
        # FIXME: reduce DEBUG log load
        TailableProc.__init__(self, datadir, verbose=VERBOSE)
        self.conf_file = os.path.join(datadir, "config.toml")
        self.cmd_line = [COORDINATORD_PATH, "--conf", f"{self.conf_file}"]
        self.prefix = "coordinatord"

        self.postgres_user = postgres_user
        self.postgres_pass = postgres_pass
        self.postgres_host = postgres_host
        # Use the directory fixture uid
        uid = os.path.basename(os.path.dirname(datadir))
        self.db_name = f"revault_coordinatord_{uid}"
        # Cleanup a potential leftover from a crashed test
        try:
            self.postgres_exec(f"DROP DATABASE {self.db_name}")
        except psycopg2.errors.InvalidCatalogName:
            pass
        # Now actually create it
        self.postgres_exec(f"CREATE DATABASE {self.db_name} OWNER {postgres_user}")

        noise_secret_file = os.path.join(datadir, "noise_secret")
        with open(noise_secret_file, "wb") as f:
            f.write(noise_priv)

        with open(self.conf_file, "w") as f:
            f.write("daemon = false\n")
            f.write(f'data_dir = "{datadir}"\n')
            f.write(f'log_level = "{LOG_LEVEL}"\n')

            uri = (
                f"postgresql://{postgres_user}:{postgres_pass}"
                f"@{postgres_host}/{self.db_name}"
            )
            f.write(f'postgres_uri = "{uri}"\n')

            f.write("managers = [")
            for k in managers_keys:
                f.write(f'"{k.hex()}", ')
            f.write("]\n")

            f.write("stakeholders = [")
            for k in stakeholders_keys:
                f.write(f'"{k.hex()}", ')
            f.write("]\n")

            f.write("watchtowers = [")
            for k in watchtowers_keys:
                f.write(f'"{k.hex()}", ')
            f.write("]\n")

            f.write(f'listen = "127.0.0.1:{listen_port}"')

    def postgres_exec(self, sql):
        conn = psycopg2.connect(
            f"dbname=postgres host={self.postgres_host} "
            f"user={self.postgres_user} "
            f"password={self.postgres_pass}"
        )
        conn.autocommit = True
        conn.cursor().execute(sql)
        conn.close()

    def start(self):
        TailableProc.start(self)
        self.wait_for_logs(["Started revault_coordinatord"])

    def cleanup(self):
        try:
            self.stop()
        except Exception:
            self.proc.kill()
        self.postgres_exec(f"DROP DATABASE {self.db_name}")
