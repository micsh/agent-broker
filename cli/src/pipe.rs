use anyhow::{Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

/// Request forwarded from a pipe client to the active WS session in `listen`.
pub struct PipeReq {
    pub frame: String,
    pub reply_tx: oneshot::Sender<String>,
}

/// Named pipe path for this identity.
/// Derived solely from the identity — no hardcoding.
/// Format: `\\.\pipe\broker-{project}-{name}`
pub fn pipe_name(project: &str, name: &str) -> String {
    // TODO: pipe auth token — currently the pipe name is the only gate
    format!(r"\\.\pipe\broker-{project}-{name}")
}

/// Write a length-prefixed UTF-8 string over an async writer.
/// Wire format: 4-byte little-endian u32 length followed by UTF-8 bytes.
async fn write_lp(w: &mut (impl AsyncWriteExt + Unpin), s: &str) -> Result<()> {
    let b = s.as_bytes();
    w.write_all(&(b.len() as u32).to_le_bytes()).await?;
    w.write_all(b).await?;
    w.flush().await?;
    Ok(())
}

/// Read a length-prefixed UTF-8 string from an async reader (matches `write_lp`).
async fn read_lp(r: &mut (impl AsyncReadExt + Unpin)) -> Result<String> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr).await?;
    let len = u32::from_le_bytes(hdr) as usize;
    if len > 1024 * 1024 {
        bail!("pipe frame too large: {len} bytes");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Run the pipe server accept loop. Accepts one client at a time, reads one
/// LP-framed request, forwards it to `req_tx`, awaits the reply, writes it back.
///
/// A new server instance is pre-created before handling each client so incoming
/// clients do not see "pipe not found" during processing.
/// Exits cleanly when `req_tx` is dropped (WS session ended).
#[cfg(windows)]
pub async fn accept_loop(name: String, req_tx: mpsc::Sender<PipeReq>) {
    use tokio::net::windows::named_pipe::ServerOptions;

    let mut server = match ServerOptions::new().first_pipe_instance(true).create(&name) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[pipe] failed to create server '{name}': {e}");
            return;
        }
    };

    loop {
        // Wait for a client to connect.
        if server.connect().await.is_err() {
            break;
        }

        // Pre-create the next server instance immediately so new clients
        // do not see "pipe not found" while we handle the current one.
        let next = match ServerOptions::new().create(&name) {
            Ok(s) => s,
            Err(_) => break,
        };

        let frame = match read_lp(&mut server).await {
            Ok(f) => f,
            Err(_) => {
                server = next;
                continue;
            }
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        if req_tx.send(PipeReq { frame, reply_tx }).await.is_err() {
            break; // WS session ended — stop accepting
        }

        // Wait for the WS response with a timeout so the pipe client never
        // blocks indefinitely if the broker is slow or the session drops.
        let response = match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            reply_rx,
        ).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(_)) => "HTTP/1.1 503 WS Session Closed\r\n\r\n".to_string(),
            Err(_)      => "HTTP/1.1 504 Upstream Timeout\r\n\r\n".to_string(),
        };
        let _ = write_lp(&mut server, &response).await;

        server = next;
    }
}

/// Try sending `frame` through the named pipe.
/// Returns `None` if the pipe is not available (listen not running) — caller
/// should fall back to a one-shot WS connection.
/// Returns `Some(Ok(response))` on success, `Some(Err(_))` on I/O failure.
#[cfg(windows)]
pub async fn try_send(name: &str, frame: &str) -> Option<Result<String>> {
    use tokio::net::windows::named_pipe::ClientOptions;

    // TODO: pipe auth token — send and verify before forwarding the frame
    let mut client = match ClientOptions::new().open(name) {
        Ok(c) => c,
        Err(_) => return None, // pipe not found → fall back to one-shot WS
    };

    Some(async {
        write_lp(&mut client, frame).await?;
        read_lp(&mut client).await
    }.await)
}
