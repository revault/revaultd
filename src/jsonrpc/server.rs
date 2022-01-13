//! Here we handle incoming connections and communication on the RPC socket.
//! Actual JSONRPC2 commands are handled in the `api` mod.

use crate::{
    jsonrpc::{
        api::{JsonRpcMetaData, RpcApi, RpcImpl},
        UserRole, RpcUtils
    },
};

use std::{
    collections::{HashMap, VecDeque},
    io::{self, Write},
    path::PathBuf,
    sync::{Arc, RwLock},
    thread,
};

#[cfg(not(windows))]
use mio::{
    net::{UnixListener, UnixStream},
    Events, Interest, Poll, Token,
};
#[cfg(windows)]
use uds_windows::{UnixListener, UnixStream};

use jsonrpc_core::{futures::Future, Call, MethodCall, Response};

// Maximum number of concurrent handlers for incoming RPC commands
const MAX_HANDLER_THREADS: usize = 4;

// Remove trailing newlines from utf-8 byte stream
fn trimmed(mut vec: Vec<u8>, bytes_read: usize) -> Vec<u8> {
    vec.truncate(bytes_read);

    // Until there is some whatever-newline character, pop.
    while let Some(byte) = vec.last() {
        // Of course, we assume utf-8
        if !(&0x0a..=&0x0d).contains(&byte) {
            break;
        }
        vec.pop();
    }

    vec
}

// Returns an error only on a fatal one, and None on recoverable ones.
fn read_bytes_from_stream(stream: &mut dyn io::Read) -> Result<Option<Vec<u8>>, io::Error> {
    let mut buf = vec![0; 512];
    let mut total_read = 0;

    loop {
        match stream.read(&mut buf[total_read..]) {
            Ok(0) => {
                if total_read == 0 {
                    return Ok(None);
                }
                return Ok(Some(trimmed(buf, total_read)));
            }
            Ok(n) => {
                total_read += n;
                // Note that we don't return if it appears that we read till the end
                // here: we always wait for a WouldBlock so that we are sure they are
                // done writing.
                if total_read == buf.len() {
                    buf.resize(total_read * 2, 0);
                } else {
                    // But on windows, we do as we'll never receive a WouldBlock..
                    #[cfg(windows)]
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
                        if total_read == 0 {
                            // We can't read it just yet, but it's fine.
                            return Ok(None);
                        }
                        return Ok(Some(trimmed(buf, total_read)));
                    }
                    io::ErrorKind::Interrupted => {
                        // Interrupted? Let's try again
                        continue;
                    }
                    io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe => {
                        // They're not there anymore, but it's fine.
                        return Ok(None);
                    }
                    // Now that's actually bad
                    _ => return Err(err),
                }
            }
        }
    }
}

// Returns Ok(None) on entirely written data and Ok(Some(remaining_data)) on partially-written
// data.
fn write_byte_stream(stream: &mut UnixStream, resp: Vec<u8>) -> Result<Option<Vec<u8>>, io::Error> {
    let mut written = 0;
    loop {
        match stream.write(&resp[written..]) {
            Ok(n) => {
                written += n;
                log::trace!("Wrote '{}', total '{}'", n, written);

                if written == resp.len() {
                    return Ok(None);
                }
            }
            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => {
                    log::debug!(
                        "Got error '{}' when writing. Wrote '{}' bytes, defering \
                                the rest of the buffer to next write.",
                        e,
                        written
                    );
                    return Ok(Some(resp[written..].to_vec()));
                }
                _ => return Err(e),
            },
        }
    }
}

// Used to check if, when receiving an event for a token, we have an ongoing connection and stream
// for it.
#[cfg(not(windows))]
type ConnectionMap = HashMap<Token, (UnixStream, Arc<RwLock<VecDeque<Vec<u8>>>>)>;

fn handle_single_request(
    jsonrpc_io: Arc<RwLock<jsonrpc_core::MetaIoHandler<JsonRpcMetaData>>>,
    metadata: JsonRpcMetaData,
    resp_queue: Arc<RwLock<VecDeque<Vec<u8>>>>,
    message: MethodCall,
) {
    let res = jsonrpc_io
        .read()
        .unwrap()
        .handle_call(Call::MethodCall(message), metadata)
        .wait()
        .expect("jsonrpc_core says: Handler calls can never fail.")
        .expect("This is a method call, there is always a response.");
    let resp = Response::Single(res);
    let resp_bytes = serde_json::to_vec(&resp).expect("jsonrpc_core says: This should never fail.");

    resp_queue.write().unwrap().push_back(resp_bytes);
}

// Read request from the stream, parse it as JSON and handle the JSONRPC command.
// Returns true if parsed correctly, false otherwise.
// Extend the cache with data read from the stream, and parse it as a set of JSONRPC requests (no
// notification). If there are remaining bytes not interpretable as a valid JSONRPC request, leave
// it in the cache.
// Will return true if we read at least one valid JSONRPC request.
fn read_handle_request(
    cache: &mut Vec<u8>,
    stream: &mut UnixStream,
    resp_queue: &mut Arc<RwLock<VecDeque<Vec<u8>>>>,
    jsonrpc_io: &Arc<RwLock<jsonrpc_core::MetaIoHandler<JsonRpcMetaData>>>,
    metadata: &JsonRpcMetaData,
    handler_threads: &mut VecDeque<thread::JoinHandle<()>>,
) -> Result<(), io::Error> {
    // We use an optional index if there is some left unparsed bytes, because borrow checker :)
    let mut leftover = None;

    if let Some(new) = read_bytes_from_stream(stream)? {
        cache.extend(new);
    } else {
        // Nothing new? We can short-circuit.
        return Ok(());
    }

    let mut de = serde_json::Deserializer::from_slice(cache).into_iter::<MethodCall>();

    while let Some(method_call) = de.next() {
        log::trace!("Got JSONRPC request '{:#?}", method_call);

        match method_call {
            // Get a response and append it to the response queue
            Ok(m) => {
                let t_io_handler = jsonrpc_io.clone();
                let t_meta = metadata.clone();
                let t_queue = resp_queue.clone();

                // We special case the 'stop' command to treat it synchronously, as we could miss
                // the "read closed" event in the main loop and hang up forever otherwise.
                // FIXME: We could not have a handler for it, and just write the raw response by
                // hand.
                if m.method.as_str() == "stop" {
                    handle_single_request(t_io_handler, t_meta, t_queue, m);
                } else {
                    // If there are too many threads spawned, wait for the oldest one to complete.
                    // FIXME: we can be smarter than that..
                    if handler_threads.len() >= MAX_HANDLER_THREADS {
                        handler_threads
                            .pop_front()
                            .expect("Just checked the length")
                            .join()
                            .unwrap();
                    }

                    handler_threads.push_back(thread::spawn(move || {
                        handle_single_request(t_io_handler, t_meta, t_queue, m)
                    }));
                }
            }
            // Parsing error? Assume it's a message we'll be able to read later.
            Err(e) => {
                if e.is_eof() {
                    leftover = Some(de.byte_offset());
                }
                log::trace!(
                    "Non fatal error reading JSON: '{}'. Probably partial read.",
                    e
                );
                break;
            }
        }
    }

    if let Some(leftover) = leftover {
        let s = &cache[leftover..];
        *cache = s.to_vec();
    } else {
        cache.clear();
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

    // UID per connection
    let mut unique_token = Token(JSONRPC_SERVER.0 + 1);
    let mut connections_map: ConnectionMap = HashMap::with_capacity(8);

    // Cache what we read from the socket, in case we read only half a message.
    let mut read_cache_map: HashMap<Token, Vec<u8>> = HashMap::with_capacity(8);
    let jsonrpc_io = Arc::from(RwLock::from(jsonrpc_io));
    // Handle to thread currently handling commands we were sent.
    let mut handler_threads: VecDeque<std::thread::JoinHandle<_>> =
        VecDeque::with_capacity(MAX_HANDLER_THREADS);

    poller
        .registry()
        .register(&mut listener, JSONRPC_SERVER, Interest::READABLE)?;

    loop {
        poller.poll(&mut events, None)?;

        for event in &events {
            // A connection was established; loop to process all the messages
            if event.token() == JSONRPC_SERVER && event.is_readable() {
                while !metadata.is_shutdown() {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let curr_token = Token(unique_token.0);
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
                                    Arc::new(RwLock::new(VecDeque::<Vec<u8>>::with_capacity(32))),
                                ),
                            );

                            read_cache_map.insert(curr_token, Vec::with_capacity(1024));
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
                // Under normal circumstances we are always interested in both
                // Writable (do we got something for them from the resp_queue?)
                // and Readable (do they have something for us?) events
                let (stream, resp_queue) = connections_map
                    .get_mut(&event.token())
                    .expect("We checked it existed just above.");
                poller.registry().reregister(
                    stream,
                    event.token(),
                    Interest::READABLE.add(Interest::WRITABLE),
                )?;

                if event.is_readable() {
                    log::trace!("Readable event for {:?}", event.token());
                    let read_cache = read_cache_map
                        .get_mut(&event.token())
                        .expect("Entry is always set when connection_map's entry is");

                    read_handle_request(
                        read_cache,
                        stream,
                        resp_queue,
                        &jsonrpc_io,
                        &metadata,
                        &mut handler_threads,
                    )?;
                }

                if event.is_writable() {
                    // FIFO
                    loop {
                        // We can't use while let Some(resp) because deadlock
                        let resp = match resp_queue.write().unwrap().pop_front() {
                            Some(resp) => resp,
                            None => break,
                        };

                        log::trace!(
                            "Writing response for {:?} ({} bytes)",
                            event.token(),
                            resp.len()
                        );
                        // If we could not write the data, don't lose track of it! This would only
                        // reasonably happen on `WouldBlock`.
                        match write_byte_stream(stream, resp) {
                            Ok(Some(resp)) => resp_queue.write().unwrap().push_front(resp),
                            Ok(None) => {}
                            Err(e) => {
                                log::error!("Error writing resp for {:?}: '{}'", event.token(), e)
                            }
                        }
                    }
                }

                if event.is_read_closed() || event.is_error() {
                    log::trace!("Dropping connection for {:?}", event.token());
                    connections_map.remove(&event.token());

                    // If this was the last connection alive and we are shutting down,
                    // actually shut down.
                    if metadata.is_shutdown() && connections_map.is_empty() {
                        while let Some(t) = handler_threads.pop_front() {
                            t.join().unwrap();
                        }
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
        while let Some(bytes) = read_bytes_from_stream(&mut stream)? {
            // Is it actually readable?
            match String::from_utf8(bytes) {
                Ok(string) => {
                    // If it is and wants a response, write it directly
                    if let Some(resp) = jsonrpc_io.handle_request_sync(&string, metadata.clone()) {
                        let mut resp = Some(resp.into_bytes());
                        loop {
                            resp = write_byte_stream(&mut stream, resp.unwrap())?;
                            if resp.is_none() {
                                break;
                            }
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
pub fn rpcserver_loop(
    listener: UnixListener,
    user_role: UserRole,
    rpc_utils: RpcUtils,
) -> Result<(), io::Error> {
    let mut jsonrpc_io = jsonrpc_core::MetaIoHandler::<JsonRpcMetaData, _>::default();
    jsonrpc_io.extend_with(RpcImpl.to_delegate());
    let metadata = JsonRpcMetaData::new(user_role, rpc_utils);

    log::info!("JSONRPC server started.");
    #[cfg(not(windows))]
    return mio_loop(listener, jsonrpc_io, metadata);
    #[cfg(windows)]
    return windows_loop(listener, jsonrpc_io, metadata);
}

#[cfg(test)]
mod tests {
    use super::{read_bytes_from_stream, rpcserver_loop, rpcserver_setup, trimmed, UserRole};
    use crate::utils::test_utils::{dummy_rpcutil, test_datadir};

    use std::{
        fs,
        io::{Cursor, Read, Write},
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
        let datadir = test_datadir();
        let rpcutils = dummy_rpcutil(datadir.clone(), UserRole::ManagerStakeholder);
        let revaultd_datadir = rpcutils.revaultd.read().unwrap().data_dir.clone();
        let mut rpc_socket_path = revaultd_datadir.clone();
        rpc_socket_path.push("revaultd_rpc");

        let socket = rpcserver_setup(rpc_socket_path.clone()).unwrap();
        let server_loop_thread = thread::spawn(move || {
            rpcserver_loop(socket, UserRole::Stakeholder, rpcutils).unwrap_or_else(|e| {
                panic!("Error in JSONRPC server event loop: {}", e.to_string());
            })
        });

        fn bind_or_die(path: &std::path::PathBuf, starting_time: std::time::Instant) -> UnixStream {
            match UnixStream::connect(path) {
                Ok(s) => s,
                Err(e) => {
                    if starting_time.elapsed() > Duration::from_secs(5) {
                        panic!("Could not connect to the socket: '{:?}'", e);
                    }
                    bind_or_die(path, starting_time)
                }
            }
        }

        let now = std::time::Instant::now();
        let mut sock = bind_or_die(&rpc_socket_path, now);

        // Write a valid JSONRPC message (but invalid command)
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

        // TODO: support this for Windows..
        #[cfg(not(windows))]
        {
            // Write valid JSONRPC message with a half-written one afterward
            let msg = String::from(
                r#"{"jsonrpc": "2.0", "id": 1, "method": "aaa", "params": []} {"jsonrpc": "2.0", "id": 2, "#,
            );
            let mut response = vec![0; 256];
            sock.write(msg.as_bytes()).unwrap();
            let read = sock.read(&mut response).unwrap();
            assert_eq!(
            response[..read],
            String::from(
                r#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":1}"#
            )
            .as_bytes()[..read]
        );

            // Write the other half of the message
            let msg = String::from(r#" "method": "bbbb", "params": []}"#);
            let mut response = vec![0; 256];
            sock.write(msg.as_bytes()).unwrap();
            let read = sock.read(&mut response).unwrap();
            assert_eq!(
            response[..read],
            String::from(
                r#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":2}"#
            )
            .as_bytes()[..read]
        );
        }

        // Tell it to stop, should send us a Shutdown message
        let msg = String::from(r#"{"jsonrpc": "2.0", "id": 0, "method": "stop", "params": []}"#);
        sock.write(msg.as_bytes()).unwrap();
        sock.flush().unwrap();
        drop(sock);
        server_loop_thread.join().unwrap();

        fs::remove_dir_all(&datadir).unwrap();
    }

    #[test]
    fn test_bytes_reader() {
        let samples = [vec![22; 22], vec![1; 522], vec![189; 28903]];

        // TODO: read_bytes_from_stream() would make a great fuzz target..
        for data in samples.iter() {
            let mut stream = Cursor::new(data.clone());
            let res = read_bytes_from_stream(&mut stream);
            assert_eq!(&res.unwrap().unwrap(), data);
        }
    }
}
