use std::{env, process};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use color_eyre::Result;
use mdns_resolver::MdnsResolver;
use tracing::error;

#[cfg(feature = "bins")]
fn install_tracing() {
  use tracing_error::ErrorLayer;
  use tracing_subscriber::prelude::*;
  use tracing_subscriber::{fmt, EnvFilter};

  let fmt_layer = fmt::layer().with_target(true).with_writer(std::io::stderr);

  let filter_layer = EnvFilter::try_from_default_env()
    .or_else(|_| EnvFilter::try_new("info"))
    .unwrap();

  tracing_subscriber::registry()
    .with(filter_layer)
    .with(fmt_layer)
    .with(ErrorLayer::default())
    .init();
}

#[tokio::main]
async fn main() -> Result<()> {
  install_tracing();

  let resolver = MdnsResolver::new().await?;
  let query = match env::args().skip(1).next() {
    Some(query) => query,
    None => {
      error!("usage: {} hostname", env::args().next().unwrap_or("mdns-query".into()));
      process::exit(1);
    }
  };

  let res = match resolver.query_timeout(query, Duration::from_millis(1000)).await {
    Ok(result) => result,
    Err(e) => {
      error!("could not resolve query: {}", e);
      process::exit(1);
    }
  };

  let packet = res.to_packet()?;
  for answer in packet.answers {
    let addr = match answer.rdata {
      simple_dns::rdata::RData::A(rec) => IpAddr::V4(Ipv4Addr::from(rec.address)),
      simple_dns::rdata::RData::AAAA(rec) => IpAddr::V6(Ipv6Addr::from(rec.address)),
      _ => continue,
    };
    println!("{} = {}", answer.name, addr);
  }

  Ok(())
}
