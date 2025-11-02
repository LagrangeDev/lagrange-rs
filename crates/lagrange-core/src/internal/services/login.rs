use lagrange_macros::auto_reexport;

auto_reexport! {
    pub mod exchange_emp;
    pub mod password;
    pub mod qrlogin;
    pub mod trans_emp;
    pub mod uin_resolve;
}

// Manual re-exports for renamed types (to preserve backward compatibility)
pub use password::{Command as LoginCommand, States as LoginStates};
