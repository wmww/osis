//! Error classes (notes/architecture.md §3) and the `impl_error!` macro.

/// How the node reacts to an error, mechanically.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorClass {
    /// Peer or stored data violates the format or a rule: reject, diagnostic, never store.
    BadInput,
    /// Data this build cannot interpret: store and relay as bytes, re-examine after upgrade.
    Parked,
    /// Storage, I/O or bug class: surfaced to the app, never attributed to a peer.
    Local,
}

/// Every crate's error type reports its class.
pub trait Classified {
    fn class(&self) -> ErrorClass;
}

/// Implements `Display` and `std::error::Error`. For an enum, arms are
/// `Pattern => ("format", args...)` with variants named bare; for a struct, one message.
/// ```
/// #[derive(Debug)]
/// enum E { Short, Bad(u8) }
/// osis_base::impl_error!(E { Short => ("truncated"), Bad(b) => ("bad byte {b:#04x}") });
/// assert_eq!(E::Bad(1).to_string(), "bad byte 0x01");
/// #[derive(Debug)]
/// struct Invalid;
/// osis_base::impl_error!(Invalid, "invalid");
/// assert_eq!(Invalid.to_string(), "invalid");
/// ```
#[macro_export]
macro_rules! impl_error {
    ($ty:ident { $($pat:pat => ($($arg:tt)*)),* $(,)? }) => {
        impl ::core::fmt::Display for $ty {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                #[allow(unused_imports)]
                use $ty::*;
                match self {
                    $($pat => write!(f, $($arg)*),)*
                }
            }
        }
        impl ::std::error::Error for $ty {}
    };
    ($ty:ident, $msg:literal) => {
        impl ::core::fmt::Display for $ty {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str($msg)
            }
        }
        impl ::std::error::Error for $ty {}
    };
}
