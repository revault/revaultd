mod api;
use crate::threadmessages::ThreadMessage;
use api::{JsonRpcMetaData, RpcApi, RpcImpl};

use std::{
    collections::{HashMap, VecDeque},
    io::{self, Read, Write},
    path::PathBuf,
    sync::{mpsc::Sender, Arc, RwLock},
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
fn read_bytes_from_stream(mut stream: &UnixStream) -> Result<Option<Vec<u8>>, io::Error> {
    let mut buf = vec![0; 512];
    let mut bytes_read = 0;

    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                if bytes_read == 0 {
                    return Ok(None);
                }
                return Ok(Some(trimmed(buf, bytes_read)));
            }
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

fn write_byte_stream(stream: &mut UnixStream, resp: String) -> Result<(), io::Error> {
    match stream.write(resp.as_bytes()) {
        Ok(n) => {
            if n < resp.len() {
                // We didn't write everything!
                Err(io::ErrorKind::WriteZero.into())
            } else {
                Ok(())
            }
        }
        Err(e) => match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::BrokenPipe => Ok(()),
            io::ErrorKind::Interrupted => write_byte_stream(stream, resp),
            _ => Err(e),
        },
    }
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

    // UID per connection
    let mut unique_token = Token(JSONRPC_SERVER.0 + 1);
    let mut connections_map: HashMap<Token, (UnixStream, Arc<RwLock<VecDeque<String>>>)> =
        HashMap::with_capacity(32);

    // Edge case: we might close the socket before writing the response to the
    // 'stop' call that made us shutdown. This tracks that we answer politely.
    let mut stop_token = unique_token;

    poller
        .registry()
        .register(&mut listener, JSONRPC_SERVER, Interest::READABLE)?;

    loop {
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
                if event.is_readable() {
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
                    let (stream, resp_queue) = connections_map
                        .get_mut(&event.token())
                        .expect("We checked it existed just above.");

                    // FIFO
                    while let Some(resp) = resp_queue.write().unwrap().pop_front() {
                        log::trace!("Writing response '{:?}' for {:?}", &resp, event.token());
                        write_byte_stream(stream, resp)?;
                    }
                }

                if event.is_read_closed() {
                    log::trace!("Dropping connection for {:?}", event.token());
                    connections_map.remove(&event.token());

                    if event.token() == stop_token {
                        return Ok(());
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
        if let Some(bytes) = read_bytes_from_stream(&stream)? {
            // Is it actually readable?
            match String::from_utf8(bytes) {
                Ok(string) => {
                    // If it is and wants a response, write it directly
                    if let Some(resp) = jsonrpc_io.handle_request_sync(&string, metadata.clone()) {
                        write_byte_stream(&mut stream, resp)?;
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

#[cfg(test)]
mod tests {
    use super::{jsonrpcapi_loop, trimmed};
    use crate::threadmessages::{RpcMessage, ThreadMessage};

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
        let mut path = PathBuf::from(file!());
        path = path.parent().unwrap().parent().unwrap().to_path_buf();
        path.push("../test_data/revaultd_rpc");

        let (tx, rx) = mpsc::channel();
        let path_ = path.clone();
        thread::spawn(move || {
            jsonrpcapi_loop(tx, path_).unwrap_or_else(|e| {
                panic!("Error in JSONRPC server event loop: {}", e.to_string());
            })
        });

        // Take some beathing room
        thread::sleep(Duration::from_secs(2));
        let mut sock = UnixStream::connect(path).unwrap();

        // Write an invalid JSONRPC message
        // For some reasons it takes '{}' as non-empty parameters..
        let invalid_msg =
            String::from(r#"{"jsonrpc": "2.0", "id": 0, "method": "stop", "params": {}}"#);
        let mut response = vec![0; 256];
        sock.write(invalid_msg.as_bytes()).unwrap();
        let read = sock.read(&mut response).unwrap();
        assert_eq!(
            String::from_utf8(trimmed(response, read)).unwrap(),
            String::from(
                r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid parameters: No parameters were expected","data":"Map({})"},"id":0}"#
            )
        );

        // Tell it to stop, should send us a Shutdown message
        let msg = String::from(r#"{"jsonrpc": "2.0", "id": 0, "method": "stop", "params": []}"#);
        sock.write(msg.as_bytes()).unwrap();
        // FIXME(darosior): i need to debug the fuck out of this but i need to install a VM
        // first...
        #[cfg(not(windows))]
        assert_eq!(rx.recv().unwrap(), ThreadMessage::Rpc(RpcMessage::Shutdown));
    }
}
