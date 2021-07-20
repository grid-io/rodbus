use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use rodbus::*;
use rodbus::client::*;
use rodbus::error::Error;
use rodbus::server::*;
use rodbus::types::*;

struct Handler {
    coils: [bool; 100],
}
impl RequestHandler for Handler {
    fn read_coil(&self, address: u16) -> Result<bool, ExceptionCode> {
        match self.coils.get(address as usize) {
            Some(x) => Ok(*x),
            None => Err(ExceptionCode::IllegalDataAddress),
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    let args: Vec<String> = std::env::args().collect();

    if args.len() != 3 {
        panic!("You must provide only the <num sessions> and <num requests> parameters");
    }

    let num_sessions = usize::from_str(&args[1])?;
    let num_requests = usize::from_str(&args[2])?;

    println!(
        "creating {} parallel connections and making {} requests per connection",
        num_sessions, num_requests
    );

    let addr = SocketAddr::from_str("127.0.0.1:40000")?;

    let handler = Handler {
        coils: [false; 100],
    }
    .wrap();

    let _handle = spawn_tcp_server_task(
        num_sessions,
        addr,
        ServerHandlerMap::single(UnitId::new(1), handler),
        DecodeLevel::new(
            PduDecodeLevel::DataValues,
            AduDecodeLevel::Nothing,
            PhysDecodeLevel::Nothing,
        ),
    )
    .await?;

    // now spawn a bunch of clients
    let mut channels: Vec<(Channel, RequestParam)> = Vec::new();
    for _ in 0..num_sessions {
        let channel = spawn_tcp_client_task(
            addr,
            10,
            default_reconnect_strategy(),
            DecodeLevel::new(
                PduDecodeLevel::Nothing,
                AduDecodeLevel::Nothing,
                PhysDecodeLevel::Nothing,
            ),
        );
        let params = RequestParam::new(UnitId::new(1), Duration::from_secs(1));

        channels.push((channel, params));
    }

    let mut query_tasks: Vec<tokio::task::JoinHandle<Result<(), Error>>> = Vec::new();

    let start = std::time::Instant::now();

    // spawn tasks that make a query 1000 times
    for (mut channel, params) in channels {
        let handle: tokio::task::JoinHandle<Result<(), Error>> = tokio::spawn(async move {
            for _ in 0..num_requests {
                if let Err(err) = channel
                    .read_coils(params, AddressRange::try_from(0, 100).unwrap())
                    .await
                {
                    println!("failure: {}", err);
                    return Err(err);
                }
            }
            Ok(())
        });
        query_tasks.push(handle);
    }

    for handle in query_tasks {
        handle.await.unwrap().unwrap();
    }

    let elapsed = std::time::Instant::now() - start;

    let num_total_requests = num_sessions * num_requests;
    let seconds = elapsed.as_secs_f64();
    let requests_per_sec: f64 = (num_total_requests as f64) / seconds;

    println!(
        "performed {} requests in {} seconds - ({:.1} requests/sec)",
        num_total_requests, seconds, requests_per_sec
    );

    Ok(())
}
