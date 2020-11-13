pub mod actions;
pub mod interface;
mod schema;

#[derive(PartialEq, Eq, Debug)]
pub struct DatabaseError(pub String);

impl std::fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Database error: {}", self.0)
    }
}

pub const VERSION: u32 = 0;
