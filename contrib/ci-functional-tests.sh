set -xe

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

# Run the functional tests
cd tests/servers/coordinatord && cargo build && git submodule update --init && cd ../../../
python3 -m venv venv
. venv/bin/activate
pip install -r tests/requirements.txt
TIMEOUT=120 TEST_DEBUG=1 POSTGRES_USER="test" POSTGRES_PASS="test" pytest -vvv -n2 --log-cli-level=DEBUG tests/
