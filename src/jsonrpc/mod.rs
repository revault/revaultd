mod api;
use crate::threadmessages::ThreadMessage;
use api::{JsonRpcMetaData, RpcApi, RpcImpl};

use std::{
    io::{self, Read},
    path::PathBuf,
    process,
    sync::mpsc::Sender,
    time::Duration,
};

#[cfg(not(windows))]
use mio::{
    net::{UnixListener, UnixStream},
    Events, Interest, Poll, Token,
};
#[cfg(windows)]
use uds_windows::{UnixListener, UnixStream};

// Remove trailing newlines from utf-8 byte stream
fn trimmed(mut vec: Vec<u8>, bytes_read: usize) -> Vec<u8> {
    vec.truncate(bytes_read);

    // Until there is some whatever-newline character, pop.
    while let Some(byte) = vec.last() {
        // Of course, we assume utf-8
        if byte < &0x0a || byte > &0x0d {
            break;
        }
        vec.pop();
    }

    vec
}

// Returns an error only on a fatal one, and None on recoverable ones.
fn read_bytes_from_stream(mut stream: UnixStream) -> Result<Option<Vec<u8>>, io::Error> {
    let mut buf = vec![0; 512];
    let mut bytes_read = 0;

    loop {
        match stream.read(&mut buf) {
            Ok(0) => return Ok(Some(trimmed(buf, bytes_read))),
            Ok(n) => {
                bytes_read += n;
                if bytes_read == buf.len() {
                    buf.resize(bytes_read * 2, 0);
                } else {
                    return Ok(Some(trimmed(buf, bytes_read)));
                }
            }
            Err(err) => {
                match err.kind() {
                    io::ErrorKind::WouldBlock => {
                        if bytes_read == 0 {
                            // We can't read it just yet, but it's fine.
                            return Ok(None);
                        }
                        return Ok(Some(trimmed(buf, bytes_read)));
                    }
                    io::ErrorKind::Interrupted => {
                        // Try again on interruption.
                        continue;
                    }
                    // Now that's actually bad
                    _ => return Err(err),
                }
            }
        }
    }
}

// Try to parse and interpret bytes from the stream
fn handle_byte_stream(
    jsonrpc_io: &jsonrpc_core::MetaIoHandler<JsonRpcMetaData>,
    stream: UnixStream,
    metadata: JsonRpcMetaData,
) -> Result<(), io::Error> {
    if let Some(bytes) = read_bytes_from_stream(stream)? {
        match String::from_utf8(bytes) {
            Ok(string) => {
                log::trace!("JSONRPC server: got '{}'", &string);
                // FIXME: couldn't we just spawn it in a thread or handle the future?
                jsonrpc_io.handle_request_sync(&string, metadata);
            }
            Err(e) => {
                log::error!(
                    "JSONRPC server: error interpreting request: '{}'",
                    e.to_string()
                );
            }
        }
    }

    Ok(())
}

// For all but Windows, we use Mio.
#[cfg(not(windows))]
fn mio_loop(
    mut listener: UnixListener,
    jsonrpc_io: jsonrpc_core::MetaIoHandler<JsonRpcMetaData>,
    metadata: JsonRpcMetaData,
) -> Result<(), io::Error> {
    const JSONRPC_SERVER: Token = Token(0);
    let mut poller = Poll::new()?;
    let mut events = Events::with_capacity(16);

    poller
        .registry()
        .register(&mut listener, JSONRPC_SERVER, Interest::READABLE)?;

    while !metadata.is_shutdown() {
        poller.poll(&mut events, Some(Duration::from_millis(100)))?;

        for event in &events {
            // FIXME: remove, was just out of curiosity
            if event.is_error() {
                log::error!("Got error polling the JSONRPC socket: {:?}", event.token());
            }

            // A connection was established; loop to process all the messages
            if event.token() == JSONRPC_SERVER && event.is_readable() {
                // This is not a while !metadata.is_shutdown() on purpose: if we are told
                // to stop, we finish what we were previously told to.
                loop {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            handle_byte_stream(&jsonrpc_io, stream, metadata.clone())?;
                        }
                        Err(e) => {
                            // Ok; next time then!
                            if e.kind() == io::ErrorKind::WouldBlock {
                                break;
                            }

                            // This one is not expected!
                            return Err(e);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

// For windows, we don't: Mio UDS support for Windows is not yet implemented.
#[cfg(windows)]
fn windows_loop(
    listener: UnixListener,
    jsonrpc_io: jsonrpc_core::MetaIoHandler<JsonRpcMetaData>,
    metadata: JsonRpcMetaData,
) -> Result<(), io::Error> {
    for stream in listener.incoming() {
        handle_byte_stream(&jsonrpc_io, stream?, metadata.clone())?;
    }

    Ok(())
}

// Tries to bind to the socket, if we are told it's already in use try to connect
// to check there is actually someone listening and it's not a leftover from a
// crash.
fn bind(socket_path: PathBuf) -> Result<UnixListener, io::Error> {
    match UnixListener::bind(&socket_path) {
        Ok(l) => Ok(l),
        Err(e) => {
            if e.kind() == io::ErrorKind::AddrInUse {
                return match UnixStream::connect(&socket_path) {
                    Ok(_) => Err(e),
                    Err(_) => {
                        // Ok, no one's here. Just delete the socket and bind.
                        log::debug!("Removing leftover rpc socket.");
                        std::fs::remove_file(&socket_path)?;
                        UnixListener::bind(&socket_path)
                    }
                };
            }
            return Err(e);
        }
    }
}

/// The main event loop for the JSONRPC interface, polling the UDS at `socket_path`
pub fn jsonrpcapi_loop(tx: Sender<ThreadMessage>, socket_path: PathBuf) -> Result<(), io::Error> {
    // Create the socket with RW permissions only for the user
    // FIXME: find a workaround for Windows...
    #[cfg(unix)]
    let old_umask = unsafe { libc::umask(0o177) };
    let listener = bind(socket_path);
    #[cfg(unix)]
    unsafe {
        libc::umask(old_umask);
    }
    let listener = listener?;
    let mut jsonrpc_io = jsonrpc_core::MetaIoHandler::<JsonRpcMetaData, _>::default();
    jsonrpc_io.extend_with(RpcImpl.to_delegate());
    let metadata = JsonRpcMetaData::from_tx(tx);

    #[cfg(not(windows))]
    return mio_loop(listener, jsonrpc_io, metadata);
    #[cfg(windows)]
    return windows_loop(listener, jsonrpc_io, metadata);
}
