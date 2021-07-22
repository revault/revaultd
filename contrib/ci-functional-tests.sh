set -xe

REPO_ROOT=$(pwd)

# Build the revaultd binary
cargo build --release

# Download the bitcoind binary
BITCOIND_VERSION="0.21.0"
DIR_NAME="bitcoin-$BITCOIND_VERSION"
ARCHIVE_NAME="$DIR_NAME.tar.gz"
curl https://bitcoincore.org/bin/bitcoin-core-$BITCOIND_VERSION/bitcoin-$BITCOIND_VERSION-x86_64-linux-gnu.tar.gz -o $ARCHIVE_NAME
tar -xzf $ARCHIVE_NAME
sudo mv $DIR_NAME/bin/bitcoind /usr/local/bin/

# Setup the postgres instance for the servers
sudo apt update && sudo apt install postgresql-12
sudo systemctl start postgresql
sudo su -c "psql -c \"CREATE ROLE test CREATEDB LOGIN PASSWORD 'test'\"" - postgres

# Build the servers
git submodule update --init
cd tests/servers/coordinatord && cargo build && cd "$REPO_ROOT"
cd tests/servers/cosignerd && cargo build && cd "$REPO_ROOT"

# Run the functional tests
python3 -m venv venv
. venv/bin/activate
pip install -r tests/requirements.txt
for i in $(seq 10); do
    echo "\n\n\n\n=========== Run $i ==============\n\n\n\n"
    EXECUTOR_WORKERS=10 VERBOSE=1 LOG_LEVEL=debug TIMEOUT=120 TEST_DEBUG=1 POSTGRES_USER="test" POSTGRES_PASS="test" pytest -n5 -vvv --log-cli-level=DEBUG --timeout=1800 tests/
done
