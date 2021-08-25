
use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use error::Result;
use simple_dns::{Name, PacketBuf, PacketHeader, QCLASS, QTYPE, Question};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot;
use tracing::{debug, warn};
use lazy_static::lazy_static;

mod error;

pub use error::MdnsError;

const MULTICAST_PORT: u16 = 5353;
const MULTICAST_ADDR_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MULTICAST_ADDR_IPV6: Ipv6Addr = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0xFB);

lazy_static! {
  pub(crate) static ref MULTICAST_IPV4_SOCKET: SocketAddr =
      SocketAddr::new(IpAddr::V4(MULTICAST_ADDR_IPV4), MULTICAST_PORT);
  pub(crate) static ref MULTICAST_IPV6_SOCKET: SocketAddr =
      SocketAddr::new(IpAddr::V6(MULTICAST_ADDR_IPV6), MULTICAST_PORT);
}

fn create_socket(addr: &SocketAddr) -> std::io::Result<Socket> {
  let domain = if addr.is_ipv4() {
      Domain::IPV4
  } else {
      Domain::IPV6
  };

  let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
  socket.set_read_timeout(Some(Duration::from_millis(100)))?;
  socket.set_reuse_address(true)?;

  #[cfg(not(windows))]
  socket.set_reuse_port(true)?;

  Ok(socket)
}

fn sender_socket(addr: &SocketAddr) -> std::io::Result<std::net::UdpSocket> {
  let sock_addr = if addr.is_ipv4() {
    SockAddr::from(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0))
  } else {
    SockAddr::from(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0))
  };

  let socket = create_socket(addr)?;
  socket.bind(&sock_addr)?;

  Ok(socket.into())
}

/// Continuously reads packets from the given socket and publishes them to the
/// provided channel.
async fn ingest_packets(socket: Arc<UdpSocket>, tx: UnboundedSender<PacketBuf>) {
  let mut buf = [0u8; 4096];

  loop {
    match socket.recv_from(&mut buf[..]).await {
      Ok((count, _)) => {
        if let Ok(header) = PacketHeader::parse(&buf[0..12]) {
          // filter out some obvious noise (e.g. other queries, particularly
          // our own)
          if header.query || header.answers_count == 0 {
            continue;
          }

          let buf = PacketBuf::from(&buf[..count]);
          if let Err(e) = tx.send(buf) {
            warn!("failed to send parsed packet: {}", e);
            break;
          }
        }
      },
      Err(e) => {
        warn!("error receiving packet: {}", e);
        continue;
      }
    }
  }
}

pub struct Query {
  packet_id: u16,
  query_name: String,
  completion: Option<oneshot::Sender<Result<PacketBuf>>>,
  packet: PacketBuf,

  started: Instant,
  timeout: Duration,
}

impl Eq for Query {}

impl PartialEq for Query {
  fn eq(&self, other: &Self) -> bool {
    self.packet_id == other.packet_id && self.query_name == other.query_name
  }
}

impl Ord for Query {
  fn cmp(&self, other: &Self) -> std::cmp::Ordering {
    (self.packet_id, &self.query_name).cmp(&(other.packet_id, &other.query_name))
  }
}

impl PartialOrd for Query {
  fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
    Some(self.cmp(other))
  }
}

impl Hash for Query {
  fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
    self.packet_id.hash(state);
    self.query_name.hash(state);
  }
}

impl fmt::Debug for Query {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Query")
      .field("packet_id", &self.packet_id)
      .field("query_name", &self.query_name)
      .finish()
  }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct QueryKey {
  packet_id: u16,
  query_name: String,
}

impl From<&Query> for QueryKey {
  fn from(q: &Query) -> Self {
    QueryKey {
      packet_id: q.packet_id,
      query_name: q.query_name.clone(),
    }
  }
}

/// An async task to coordinate the sending of queries and processing of
/// responses.
/// Note that this function never terminates; it should be executed in the
/// background using `tokio::spawn`.
async fn process_packets(
  mut query_rx: UnboundedReceiver<Query>,
  mut packet_rx: UnboundedReceiver<PacketBuf>,
  socket: Arc<UdpSocket>,
) {
  let mut queries = HashMap::new();
  let mut cleanup = tokio::time::interval(Duration::from_secs(1));

  loop {
    tokio::select! {
      query = query_rx.recv() => {
        let mut query = match query {
          Some(query) => query,
          None => continue
        };
        match socket.send_to(&query.packet, *MULTICAST_IPV4_SOCKET).await {
          Ok(_) => {
            debug!("inserting query: {:?}", query);
            queries.insert(QueryKey::from(&query), query);
          },
          Err(e) => {
            // we couldn't send the query, send off the completion immediately
            // with an error (ignoring any errors in the send).
            if let Some(completion) = query.completion.take() {
              completion.send(Err(MdnsError::from(e))).ok();
            }
          },
        }
      },

      packet = packet_rx.recv() => {
        let packet = match packet {
          Some(packet) => packet,
          None => continue
        };

        let parsed_packet = match packet.to_packet() {
          Ok(packet) => packet,
          Err(_) => continue,
        };

        for answer in parsed_packet.answers {
          let query_key = QueryKey {
            packet_id: packet.packet_id(),
            query_name: answer.name.to_string(),
          };

          if let Some(mut query) = queries.remove(&query_key) {
            if let Some(completion) = query.completion.take() {
              let cloned = PacketBuf::from(&packet[..]);
              completion.send(Ok(cloned)).ok();
            }
            debug!("completed {:?}", query);
          }
        }
      },

      _ = cleanup.tick() => {
        let mut to_remove = Vec::new();
        for (key, query) in queries.iter_mut() {
          if query.started.elapsed() > query.timeout {
            to_remove.push(key.clone());

            if let Some(completion) = query.completion.take() {
              completion.send(Err(MdnsError::TimedOut(key.clone()))).ok();
            }

            debug!("removing timed out query: {:?}", query);
          }
        }

        for key in to_remove {
          queries.remove(&key);
        }
      }
    };
  }
}

#[derive(Clone)]
pub struct MdnsResolver {
  query_tx: UnboundedSender<Query>
}

impl MdnsResolver {
  /// Attempts to create a new MdnsResolver and begins listening for packets on
  /// the necessary UDP sockets.
  pub async fn new() -> Result<Self> {
    let tx_socket = Arc::new(UdpSocket::from_std(sender_socket(&MULTICAST_IPV4_SOCKET)?)?);
    let tx_socket_clone = Arc::clone(&tx_socket);

    let (query_tx, query_rx) = mpsc::unbounded_channel();
    let (packet_tx, packet_rx) = mpsc::unbounded_channel();

    tokio::spawn(async move {
      ingest_packets(tx_socket_clone, packet_tx).await
    });

    tokio::spawn(async move {
      process_packets(query_rx, packet_rx, tx_socket).await;
    });

    Ok(MdnsResolver {
      query_tx,
    })
  }

  /// Submit a query with the given timeout.
  /// Note that timeouts are processed at 1s intervals.
  pub async fn query_timeout(&self, q: impl AsRef<str>, timeout: Duration) -> Result<PacketBuf> {
    let packet_id = rand::random();
    let mut packet = PacketBuf::new(PacketHeader::new_query(packet_id, false), true);
    let service_name = Name::new(q.as_ref())?;
    packet.add_question(&Question::new(
      service_name.clone(),
      QTYPE::A,
      QCLASS::IN,
      true
    ))?;

    let (tx, rx) = oneshot::channel();
    self.query_tx.send(Query {
      packet_id,
      query_name: q.as_ref().to_string(),
      completion: Some(tx),
      packet,

      started: Instant::now(),
      timeout,
    })?;

    rx.await?
  }
}
