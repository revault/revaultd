## Revaultd blackbox tests

Here we test `revaultd` by starting it on a regression testing Bitcoin network,
and by then talking to it as an user would, from the outside.

Python scripts are used for the automation, and specifically the [`pytest` framework](https://docs.pytest.org/en/stable/index.html).

Credits: initially a lot of the fixtures and utilities were taken from the great
[C-lightning test framework](https://github.com/ElementsProject/lightning/tree/master/contrib/pyln-testing)
and adapted.

### Test dependencies

Functional tests dependencies can be installed like for any Python project.
```
# Create a new virtual environment, preferably.
python3 -m venv venv
. venv/bin/activate
# Get the deps
pip install -r tests/requirements.txt
```
Additionaly you need to have `bitcoind` installed on your computer, please
refer to [bitcoincore](https://bitcoincore.org/en/download/) for installation.

### Test modes

Revault requires multiple servers and the version 0 of the protocol for deploying
it also specifies an additional coordination server. The wallet daemon, `revaultd`, will
therefore need to establish connections to those servers for some tests.

For these tests, the `RevaultNetwork` fixture will start multiple wallets (for the
stakeholders and the managers) as well as the required servers (coordinator, watchtowers
and cosigning servers). The code of these repositories is tracked as submodules in the
`tests/servers/` directory.

> Note: only the coordinator is implemented for now.

As the servers require a PostgreSQL backend, the functional testing framework will need
access to a running postgres instance. The credentials must be passed as environment
variables: `POSTGRES_USER`, `POSTGRES_PASS` and optionally `POSTGRES_HOST` (if not
`localhost`). The framework will take care of creating a database for each process
launched, and to drop it at teardown time.  

#### Without the servers

You can write and run tests that don't need the servers. By default, if no `POSTGRES_*`
environment variables are passed, the framework will skip the tests that depends on
servers:

```
# Adapt `-n`, `-v`, `timeout` and other environment variables to your needs
pytest tests/ -vvv -n4 --ignore tests/servers/
```

#### With the servers

For spinning up the servers, the framework will need access to the binaries. Therefore you
must `init` the submodules (if you did not `clone` with `--recursive`) and compile the
servers code:
```
# From the root of the repository
./contrib/recompile_tests_servers.sh
```
To fetch the new version of the servers, you can reuse the same script.

First, setup the docker image required for running server-requiring tests:
```
docker run --rm -d -p 5432:5432 --name postgres-coordinatord -e POSTGRES_PASSWORD=test -e POSTGRES_USER=test -e POSTGRES_DB=coordinator_db postgres:alpine
```

To run the server-requiring tests, pass the postgres credentials to the framework:
```
POSTGRES_USER="test" POSTGRES_PASS="test" TEST_DEBUG=1 pytest -vvv -n8 --timeout=1800
```

It is plausible that your functional tests encounter timeout error, you can 
increase it by setting the environment variable to a higher value (for instance
`TIMEOUT=120`). Running in single-threaded mode (by not specifying the `-n` 
parameter) might also help.

### Tips and tricks
#### Logging

We use the [Live Logging](https://docs.pytest.org/en/latest/logging.html#live-logs)
functionality from pytest. It is configured in (`pyproject.toml`)[../pyproject.toml] to
output `INFO`-level to the console. If a test fails, the entire `DEBUG` log is output.

You can override the config at runtime with the `--log-cli-level` option:
```
POSTGRES_USER=test POSTGRES_PASS=test pytest -vvv --log-cli-level=DEBUG -k test_getrevocationtxs
```

Note that we log each daemon log, and we start them with `log_level = "trace"`.

#### Profiling

It can be very useful to profile a test or the test framework itself. To do so you can use the great
[`pytest-profiling`](https://github.com/man-group/pytest-plugins/tree/master/pytest-profiling)
plugin for pytest.
```
pip install pytest-profile
```

Run a test with `--profile` for it to create a `prof/` folder in the current working directory:
```
# For instance, of course adapt env vars to your own setup
cargo build --release && TEST_PROFILING=1 TEST_DIR=/mnt/tmp BITCOIND_PATH=$PWD/../tmp/bitcoind-22.0 REVAULTD_PATH=$PWD/target/release/revaultd POSTGRES_PASS=revault POSTGRES_USER=revault pytest -vvv --ignore tests/servers/ -k test_revault_network_securing --profile
```

The `--profile-svg` option is pretty handy for a quick summary:
```
# For instance, of course adapt env vars to your own setup
cargo build --release && TEST_PROFILING=1 TEST_DIR=/mnt/tmp BITCOIND_PATH=$PWD/../tmp/bitcoind-22.0 REVAULTD_PATH=$PWD/target/release/revaultd POSTGRES_PASS=revault POSTGRES_USER=revault pytest -vvv --ignore tests/servers/ -k test_revault_network_securing --profile --profile-svg
```

[`snakeviz`](https://github.com/jiffyclub/snakeviz) is another way of visualizing the profile
information:
```
pip install snakeviz
# For instance
snakeviz prof/test_large_spends.prof
```

A test module is present containing small tests to profile the test framework at
`tests/test_profiling.py`.

For more about profiling in Python generally, see [the
doc](https://docs.python.org/3/library/profile.html).

### Test lints

Just use [`black`](https://github.com/psf/black).
