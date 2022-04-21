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
git submodule update --init --recursive
cd tests/servers
cd coordinatord && cargo build && cd ..
cd cosignerd && cargo build && cd ..
cd miradord && cargo build && cd ..
```

When you need a new version of the servers, you can update the submodules:
```
# From the root of the repository
cd tests/servers
git submodule update --remote --recursive
```

To run the server-requiring tests, pass the postgres credentials to the framework:
```
POSTGRES_USER="test" POSTGRES_PASS="test" TEST_DEBUG=1 pytest -vvv -n8 --timeout=1800
```

#### Using the containerized testing environment

Ensure that all git submodules are included in the repository:

```bash
git submodule update --init --recursive
```

Build the container image using podman (docker can also build the container):

```bash
podman build -t revault_blackbox_tests -f ./tests/Containerfile .
```

Start a podman pod to simplify inter-container communication:

```bash
podman pod create --name=revault_test_pod
```

Start postgres within the pod:

```bash
podman run --pod=revault_test_pod --rm -d --name postgres-coordinatord -e POSTGRES_PASSWORD=revault -e POSTGRES_USER=revault -e POSTGRES_DB=coordinator_db postgres:alpine
```

Run the test environment container within the pod:

```bash
podman run --pod=revault_test_pod -it revault_blackbox_tests /bin/bash
```

Activate the Python environment:

```bash
. venv/bin/activate
```

Run the tests:

```bash
pytest tests/ -vvv -n4 --ignore tests/servers/
```

```bash
POSTGRES_USER=revault POSTGRES_PASS=revault pytest -vvv -n8 --timeout=1800
```

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


### Test lints

Just use [`black`](https://github.com/psf/black).
