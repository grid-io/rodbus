use std::net::SocketAddr;

use tracing::Instrument;

use crate::decode::DecodeLevel;
use crate::tcp::server::ServerTask;
use crate::tokio;

/// server handling
pub(crate) mod handler;
pub(crate) mod request;
pub(crate) mod response;
pub(crate) mod task;
pub(crate) mod types;

// re-export to the public API
pub use handler::*;
pub use types::*;

/// A handle to the server async task. The task is shutdown when the handle is dropped.
#[derive(Debug)]
pub struct ServerHandle {
    tx: tokio::sync::mpsc::Sender<()>,
    handle: tokio::task::JoinHandle<()>,
}

impl ServerHandle {
    /// Construct a [ServerHandle] from its fields
    ///
    /// This function is only required for the C bindings
    pub fn new(tx: tokio::sync::mpsc::Sender<()>, handle: tokio::task::JoinHandle<()>) -> Self {
        ServerHandle { tx, handle }
    }
}

/// Spawns a TCP server task onto the runtime. This method can only
/// be called from within the runtime context. Use [`create_tcp_server_task`]
/// and then spawn it manually if using outside the Tokio runtime.
///
/// Each incoming connection will spawn a new task to handle it.
///
/// * `max_sessions` - Maximum number of concurrent sessions
/// * `addr` - A socket address to bound to
/// * `handlers` - A map of handlers keyed by a unit id
/// * `decode` - Decode log level
pub async fn spawn_tcp_server_task<T: RequestHandler>(
    max_sessions: usize,
    addr: SocketAddr,
    handlers: ServerHandlerMap<T>,
    decode: DecodeLevel,
) -> Result<ServerHandle, crate::tokio::io::Error> {
    let listener = crate::tokio::net::TcpListener::bind(addr).await?;

    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let handle = tokio::spawn(create_tcp_server_task_impl(
        rx,
        max_sessions,
        addr,
        listener,
        handlers,
        decode,
    ));

    Ok(ServerHandle::new(tx, handle))
}

/// Creates a TCP server task that can then be spawned onto the runtime manually.
/// Most users will prefer [`spawn_tcp_server_task`] unless they are using the library from
/// outside the Tokio runtime and need to spawn it using a Runtime handle instead of the
/// `tokio::spawn` function.
///
/// Each incoming connection will spawn a new task to handle it.
///
/// * `max_sessions` - Maximum number of concurrent sessions
/// * `addr` - A socket address to bound to
/// * `handlers` - A map of handlers keyed by a unit id
/// * `decode` - Decode log level
pub async fn create_tcp_server_task<T: RequestHandler>(
    rx: tokio::sync::mpsc::Receiver<()>,
    max_sessions: usize,
    addr: SocketAddr,
    handlers: ServerHandlerMap<T>,
    decode: DecodeLevel,
) -> Result<impl std::future::Future<Output = ()>, crate::tokio::io::Error> {
    let listener = crate::tokio::net::TcpListener::bind(addr).await?;
    Ok(create_tcp_server_task_impl(
        rx,
        max_sessions,
        addr,
        listener,
        handlers,
        decode,
    ))
}

async fn create_tcp_server_task_impl<T: RequestHandler>(
    rx: tokio::sync::mpsc::Receiver<()>,
    max_sessions: usize,
    addr: SocketAddr,
    listener: crate::tokio::net::TcpListener,
    handlers: ServerHandlerMap<T>,
    decode: DecodeLevel,
) {
    ServerTask::new(max_sessions, listener, handlers, decode)
        .run(rx)
        .instrument(tracing::info_span!("Modbus-Server-TCP", "listen" = ?addr))
        .await;
}
