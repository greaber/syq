//! Local HTTPS fixture with a fresh CA and server key for each test.
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::{pki_types::PrivatePkcs8KeyDer, ServerConfig, ServerConnection, StreamOwned};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

type Requests = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

pub struct Server {
    address: SocketAddr,
    pub ca: String,
    pub requests: Requests,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Server {
    pub fn start(hostname: &str) -> Self {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec![hostname.into()])
            .unwrap()
            .signed_by(&key, &issuer)
            .unwrap();
        let config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![certificate.der().clone()],
                    PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
                )
                .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let received = requests.clone();
        let config = Arc::new(config);
        let worker = thread::spawn(move || {
            let mut object: Option<Vec<u8>> = None;
            for socket in listener.incoming() {
                if stopping.load(Ordering::Relaxed) {
                    break;
                }
                let socket = socket.unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let connection = ServerConnection::new(config.clone()).unwrap();
                let mut tls = StreamOwned::new(connection, socket);
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") && headers.len() < 65536 {
                    let mut byte = [0];
                    if tls.read_exact(&mut byte).is_err() {
                        break;
                    }
                    headers.push(byte[0]);
                }
                if !headers.ends_with(b"\r\n\r\n") {
                    continue;
                }
                let headers = String::from_utf8(headers).unwrap();
                let request = headers.lines().next().unwrap().to_owned();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                assert!(length < 1024 * 1024);
                let mut body = vec![0; length];
                tls.read_exact(&mut body).unwrap();
                received
                    .lock()
                    .unwrap()
                    .push((request.clone(), body.clone()));
                let (status, response) = if request.contains("syq-release-manifest.json") {
                    (200, b"TLS reached the release manifest".to_vec())
                } else if request.starts_with("PUT ") {
                    object = Some(body);
                    (200, Vec::new())
                } else if request.starts_with("HEAD ") {
                    (if object.is_some() { 200 } else { 404 }, Vec::new())
                } else if request.contains("list-type=") {
                    (200, b"<ListBucketResult><Name>bucket</Name><IsTruncated>false</IsTruncated></ListBucketResult>".to_vec())
                } else {
                    (200, object.clone().unwrap_or_default())
                };
                let content_length = if request.starts_with("HEAD ") {
                    object.as_ref().map_or(0, Vec::len)
                } else {
                    response.len()
                };
                write!(tls, "HTTP/1.1 {status} fixture\r\nContent-Length: {content_length}\r\nETag: \"fixture\"\r\nLast-Modified: Wed, 21 Oct 2026 00:00:00 GMT\r\nConnection: close\r\n\r\n").unwrap();
                tls.write_all(&response).unwrap();
                tls.flush().unwrap();
            }
        });
        Self {
            address,
            ca: ca.pem(),
            requests,
            stop,
            worker: Some(worker),
        }
    }

    pub fn url(&self) -> String {
        format!("https://{}", self.address)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.address);
        self.worker.take().unwrap().join().unwrap();
    }
}
