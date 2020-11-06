pub mod actions;
pub mod interface;

#[derive(PartialEq, Eq, Debug)]
pub struct BitcoindError(pub String);

impl std::fmt::Display for BitcoindError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Bitcoind error: {}", self.0)
    }
}
