mod api;
pub mod server;

/// Some calls are Stakeholder-only or Manager-only. This makes the API code
/// aware of whether we were started as such to immediately forbid some of them.
#[derive(Debug, Clone, Copy)]
pub enum UserRole {
    Manager,
    Stakeholder,
    ManagerStakeholder,
}
