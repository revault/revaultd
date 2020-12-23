/// When an expression returning an option MUST return Some() or it's preferable
/// to fail. Similar to expect() but logs so that we have a trace when the daemon
/// crashes.
#[macro_export]
macro_rules! assume_some {
    ($expression:expr, $($reason:expr),* $(,)?) => {
        $expression.unwrap_or_else(|| {
            log::error!($($reason, )*);
            process::exit(1);
        })
    };
}

/// When an expression returning a Result MUST return Ok() or it's preferable
/// to fail. Similar to expect() but logs so that we have a trace when the daemon
/// crashes.
#[macro_export]
macro_rules! assume_ok {
    ($expression:expr, $($reason:expr),* $(,)?) => {
        $expression.unwrap_or_else(|e| {
            log::error!($($reason, )*);
            // FIXME: a workaround for keeping it single line ?
            log::error!("'{:?}'", e);
            process::exit(1);
        })
    };
}
