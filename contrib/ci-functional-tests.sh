set -xe

# Build the revaultd binary
cargo build --release

# Download the bitcoind binary
BITCOIND_VERSION="0.21.0rc2"
DIR_NAME="bitcoin-$BITCOIND_VERSION"
ARCHIVE_NAME="$DIR_NAME.tar.gz"
curl https://bitcoincore.org/bin/bitcoin-core-0.21.0/test.rc2/bitcoin-0.21.0rc2-x86_64-linux-gnu.tar.gz -o $ARCHIVE_NAME
tar -xzf $ARCHIVE_NAME
sudo mv $DIR_NAME/bin/bitcoind /usr/local/bin/

# Run the functional tests
python3 -m venv venv
. venv/bin/activate
pip install -r tests/requirements.txt
TEST_DEBUG=1 pytest -vvv -n4 tests/
