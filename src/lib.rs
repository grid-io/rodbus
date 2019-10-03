use crate::channel::Channel;

#[macro_use]
#[cfg(test)]
extern crate assert_matches;

use tokio::runtime::Runtime;
use std::net::SocketAddr;
use std::rc::Rc;

pub mod channel;
pub mod requests;
pub mod session;

mod requests_info;
mod error_conversion;
mod format;
mod frame;
mod cursor;

/// errors that should only occur
/// if there is a logic error in the library
/// but need to be handled regardless
#[derive(Debug)]
pub enum LogicError {
    /// We tried to write
    InsufficientBuffer,
    /// Frame or ADU had a bad size (outgoing)
    BadWriteSize,
    /// Bad cursor seek
    InvalidSeek,
    /// We expected a None to be Some
    NoneError,
    /// Logic error from underlying type that couldn't be converted
    Stdio(std::io::Error)
}

impl LogicError {
    pub fn from(err: std::io::Error) -> LogicError {
        match err.kind() {
            std::io::ErrorKind::WriteZero => LogicError::InsufficientBuffer,
            std::io::ErrorKind::InvalidInput => LogicError::InvalidSeek,
            _ => LogicError::Stdio(err)
        }
    }
}

#[derive(Debug)]
pub enum Error {
    /// We just bubble up std errors from reading/writing/connecting/etc
    Stdio(std::io::Error),
    /// Logic errors that shouldn't happen
    Logic(LogicError),
    /// Occurs when a channel is used after close
    ChannelClosed,
}

/// Result type used everywhere in this library
pub type Result<T> = std::result::Result<T, Error>;

/// Entry point of the library.
///
/// Create a single manager with a runtime, then use it to
/// create channels and associated sessions. They will all
/// share the same runtime.
///
/// When the manager is dropped, all the channels (and their
/// associated sessions) are shutdown automatically.
pub struct ModbusManager {
    rt: Rc<Runtime>,
}

impl ModbusManager {
    /// Create a new manager with the runtime.
    pub fn new(rt: Rc<Runtime>) -> Self {
        ModbusManager { rt }
    }

    pub fn create_channel(&self, addr: SocketAddr) -> Channel {
        Channel::new(addr, &self.rt)
    }
}