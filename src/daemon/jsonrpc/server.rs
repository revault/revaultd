//! Here we handle incoming connections and communication on the RPC socket.
//! Actual JSONRPC2 commands are handled in the `api` mod.

use crate::{
    jsonrpc::api::{JsonRpcMetaData, RpcApi, RpcImpl},
    threadmessages::RpcMessageIn,
};

use std::{
    collections::{HashMap, VecDeque},
    io::{self, Read, Write},
    path::PathBuf,
    sync::{mpsc::Sender, Arc, RwLock},
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
fn read_bytes_from_stream(mut stream: &UnixStream) -> Result<Option<Vec<u8>>, io::Error> {
    let mut buf = vec![0; 512];
    let mut total_read = 0;

    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                if total_read == 0 {
                    return Ok(None);
                }
                return Ok(Some(trimmed(buf, total_read)));
            }
            Ok(n) => {
                total_read += n;
                if total_read == buf.len() {
                    buf.resize(total_read * 2, 0);
                } else {
                    return Ok(Some(trimmed(buf, total_read)));
                }
            }
            Err(err) => {
                match err.kind() {
                    io::ErrorKind::WouldBlock => {
                        if total_read == 0 {
                            // We can't read it just yet, but it's fine.
                            return Ok(None);
                        }
                        // Note that we don't return if it's appear that we read till the end
                        // here: we always wait for a WouldBlock so that we are sure they are
                        // done writing.
                    }
                    io::ErrorKind::Interrupted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe => {
                        // Try again on interruption or disconnection. In the latter case we'll
                        // remove the stream anyways.
                        continue;
                    }
                    // Now that's actually bad
                    _ => return Err(err),
                }
            }
        }
    }
}

// Returns Ok(true) on written data and Ok(false) on non-fatal error but non-written data
fn write_byte_stream(stream: &mut UnixStream, resp: &str) -> Result<bool, io::Error> {
    match stream.write(resp.as_bytes()) {
        Ok(n) => {
            if n < resp.len() {
                // We didn't write everything!
                Err(io::ErrorKind::WriteZero.into())
            } else {
                Ok(true)
            }
        }
        Err(e) => match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::BrokenPipe => Ok(false),
            io::ErrorKind::Interrupted => write_byte_stream(stream, resp),
            _ => Err(e),
        },
    }
}

// Used to check if, when receiving an event for a token, we have an ongoing connection and stream
// for it.
#[cfg(not(windows))]
type ConnectionMap = HashMap<Token, (UnixStream, Arc<RwLock<VecDeque<String>>>)>;

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

    // Edge case: we might close the socket before writing the response to the
    // 'stop' call that made us shutdown. This tracks that we answer politely.
    let mut stop_token = Token(JSONRPC_SERVER.0 + 1);

    // UID per connection
    let mut unique_token = Token(stop_token.0 + 1);
    let mut connections_map: ConnectionMap = HashMap::with_capacity(32);

    poller
        .registry()
        .register(&mut listener, JSONRPC_SERVER, Interest::READABLE)?;

    loop {
        poller.poll(&mut events, None)?;

        for event in &events {
            // A connection was established; loop to process all the messages
            if event.token() == JSONRPC_SERVER && event.is_readable() {
                // This is not a while !metadata.is_shutdown() on purpose: if we are told
                // to stop, we finish what we were previously told to.
                loop {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let curr_token = Token(unique_token.0); // Hopefully this copies?
                            unique_token.0 += 1;

                            // So we actually know they want to discuss :)
                            poller.registry().register(
                                &mut stream,
                                curr_token,
                                Interest::READABLE,
                            )?;

                            // So we can retrieve it when they start the discussion
                            connections_map.insert(
                                curr_token,
                                (
                                    stream,
                                    Arc::new(RwLock::new(VecDeque::<String>::with_capacity(32))),
                                ),
                            );
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
            } else if connections_map.contains_key(&event.token()) {
                if event.is_read_closed() {
                    log::trace!("Dropping connection for {:?}", event.token());
                    connections_map.remove(&event.token());

                    if event.token() == stop_token {
                        return Ok(());
                    }
                    continue;
                }

                if event.is_readable() {
                    log::trace!("Readable event for {:?}", event.token());
                    let (stream, resp_queue) = connections_map
                        .get_mut(&event.token())
                        .expect("We checked it existed just above.");

                    // Ok, so we got something to read (we don't respond to garbage)
                    if let Some(bytes) = read_bytes_from_stream(stream)? {
                        // Is it actually readable?
                        match String::from_utf8(bytes) {
                            Ok(string) => {
                                // FIXME: Spawn it in a thread
                                if let Some(resp) =
                                    jsonrpc_io.handle_request_sync(&string, metadata.clone())
                                {
                                    // If we got a response, append it to the response queue
                                    resp_queue.write().unwrap().push_back(resp);
                                    // And tell Mio we'd like to write it
                                    poller.registry().reregister(
                                        stream,
                                        event.token(),
                                        Interest::READABLE.add(Interest::WRITABLE),
                                    )?;

                                    if metadata.is_shutdown() {
                                        stop_token = event.token();
                                    }
                                }
                            }
                            Err(e) => {
                                log::error!(
                                    "JSONRPC server: error interpreting request: '{}'",
                                    e.to_string()
                                );
                            }
                        }
                    }
                }

                if event.is_writable() {
                    log::trace!("Writable event for {:?}", event.token());
                    let (stream, resp_queue) = connections_map
                        .get_mut(&event.token())
                        .expect("We checked it existed just above.");

                    // FIFO
                    loop {
                        // We can't use while let Some(resp) because deadlock
                        let resp = match resp_queue.write().unwrap().pop_front() {
                            Some(resp) => resp,
                            None => break,
                        };

                        log::trace!("Writing response '{:?}' for {:?}", &resp, event.token());
                        if !write_byte_stream(stream, &resp)? {
                            // If we could not write the data, don't lose track of it!
                            resp_queue.write().unwrap().push_front(resp);
                        }
                    }
                }
            }
        }
    }
}

// For windows, we don't: Mio UDS support for Windows is not yet implemented.
#[cfg(windows)]
fn windows_loop(
    listener: UnixListener,
    jsonrpc_io: jsonrpc_core::MetaIoHandler<JsonRpcMetaData>,
    metadata: JsonRpcMetaData,
) -> Result<(), io::Error> {
    for mut stream in listener.incoming() {
        let mut stream = stream?;

        // Ok, so we got something to read (we don't respond to garbage)
        while let Some(bytes) = read_bytes_from_stream(&stream)? {
            // Is it actually readable?
            match String::from_utf8(bytes) {
                Ok(string) => {
                    // If it is and wants a response, write it directly
                    if let Some(resp) = jsonrpc_io.handle_request_sync(&string, metadata.clone()) {
                        while !write_byte_stream(&mut stream, &resp)? {}
                    }
                }
                Err(e) => {
                    log::error!(
                        "JSONRPC server: error interpreting request: '{}'",
                        e.to_string()
                    );
                }
            }
        }

        // We can't loop until is_shutdown() as we block until we got a message.
        // So, to handle shutdown the cleanest way is to check if the above handler
        // just set shutdown.
        if metadata.is_shutdown() {
            break;
        }
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

            Err(e)
        }
    }
}

/// Bind to the UDS at `socket_path`
pub fn rpcserver_setup(socket_path: PathBuf) -> Result<UnixListener, io::Error> {
    // Create the socket with RW permissions only for the user
    // FIXME: find a workaround for Windows...
    #[cfg(unix)]
    let old_umask = unsafe { libc::umask(0o177) };
    let listener = bind(socket_path);
    #[cfg(unix)]
    unsafe {
        libc::umask(old_umask);
    }

    listener
}

/// The main event loop for the JSONRPC interface, polling the UDS listener
pub fn rpcserver_loop(tx: Sender<RpcMessageIn>, listener: UnixListener) -> Result<(), io::Error> {
    let mut jsonrpc_io = jsonrpc_core::MetaIoHandler::<JsonRpcMetaData, _>::default();
    jsonrpc_io.extend_with(RpcImpl.to_delegate());
    let metadata = JsonRpcMetaData::from_tx(tx);

    log::info!("JSONRPC server started.");
    #[cfg(not(windows))]
    return mio_loop(listener, jsonrpc_io, metadata);
    #[cfg(windows)]
    return windows_loop(listener, jsonrpc_io, metadata);
}

#[cfg(test)]
mod tests {
    use super::{rpcserver_loop, rpcserver_setup, trimmed};
    use crate::threadmessages::RpcMessageIn;

    use std::{
        io::{Read, Write},
        path::PathBuf,
        sync::mpsc,
        thread,
        time::Duration,
    };

    #[cfg(not(windows))]
    use std::os::unix::net::UnixStream;
    #[cfg(windows)]
    use uds_windows::UnixStream;

    // Redundant with functional tests but useful for testing the Windows loop
    // until the functional tests suite can run on it.
    #[test]
    fn simple_write_recv() {
        let mut path = PathBuf::from(file!()).parent().unwrap().to_path_buf();
        path.push("../../../test_data/revaultd_rpc");

        let (tx, rx) = mpsc::channel();
        let socket = rpcserver_setup(path.clone()).unwrap();
        thread::spawn(move || {
            rpcserver_loop(tx, socket).unwrap_or_else(|e| {
                panic!("Error in JSONRPC server event loop: {}", e.to_string());
            })
        });

        // Take some beathing room
        thread::sleep(Duration::from_secs(2));
        let mut sock = UnixStream::connect(path).unwrap();

        // Write an invalid JSONRPC message
        // For some reasons it takes '{}' as non-empty parameters ON UNIX BUT NOT WINDOWS WTF..
        let invalid_msg =
            String::from(r#"{"jsonrpc": "2.0", "id": 0, "method": "stop", "params": {"a": "b"}}"#);
        let mut response = vec![0; 256];
        sock.write(invalid_msg.as_bytes()).unwrap();
        let read = sock.read(&mut response).unwrap();
        assert_eq!(
            String::from_utf8(trimmed(response, read)).unwrap(),
            String::from(
                r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid parameters: No parameters were expected","data":"Map({\"a\": String(\"b\")})"},"id":0}"#
            )
        );

        // Tell it to stop, should send us a Shutdown message
        let msg = String::from(r#"{"jsonrpc": "2.0", "id": 0, "method": "stop", "params": []}"#);
        sock.write(msg.as_bytes()).unwrap();
        match rx.recv() {
            Ok(RpcMessageIn::Shutdown) => {}
            _ => panic!("Didn't receive shutdown"),
        }
    }
}
