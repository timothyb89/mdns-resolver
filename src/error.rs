use thiserror::Error;

use crate::{Query, QueryKey};

#[derive(Error, Debug)]
pub enum MdnsError {
  #[error("io error: {}", .0)]
  IOError(#[from] std::io::Error),

  #[error("dns error: {}", .0)]
  DNSError(#[from] simple_dns::SimpleDnsError),

  #[error("error sending query: {}", .0)]
  QuerySendError(#[from] tokio::sync::mpsc::error::SendError<Query>),

  #[error("oneshot error: {}", .0)]
  OneshotError(#[from] tokio::sync::oneshot::error::RecvError),

  #[error("query timed out: {:?}", .0)]
  TimedOut(QueryKey)
}

pub type Result<T> = std::result::Result<T, MdnsError>;
