use std::net::{SocketAddr, ToSocketAddrs};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Sender, Receiver};
use tokio::sync::oneshot;
use tokio::runtime::Runtime;
use std::rc::Rc;

#[derive(Debug)]
pub struct Reply {
    pub result : usize,
}

impl Reply {
   fn new(result : usize) -> Self {
       Reply { result }
   }
}

pub struct Request {
    id: u16,
    argument : usize,
    reply_to : tokio::sync::oneshot::Sender<Reply>
}

#[derive(Debug)]
pub enum Error {
    Tx,
    Rx
}

impl std::convert::From<tokio::sync::oneshot::error::RecvError> for Error {
    fn from(_: tokio::sync::oneshot::error::RecvError) -> Self {
        Error::Rx
    }
}

impl std::convert::From<tokio::sync::mpsc::error::SendError> for Error {
    fn from(_: tokio::sync::mpsc::error::SendError) -> Self {
        Error::Tx
    }
}

pub struct Session {
    id: u16,
    channel_tx: Sender<Request>,
}

impl Session {
    fn new(id: u16, channel_tx: Sender<Request>) -> Self {
        Session { id, channel_tx }
    }

    pub async fn send(&mut self, arg: usize) -> Result<Reply, Error> {
        let (tx, rx) = oneshot::channel::<Reply>();
        self.channel_tx.send(Request{id: self.id, argument: arg, reply_to: tx}).await?;
        rx.await.map_err(|_| { Error::Rx } )
    }
}

pub struct Channel {
    addr: SocketAddr,
    tx: Sender<Request>,
}

impl Channel {
    fn new(addr: SocketAddr, runtime: &Runtime) -> Self {
        let (tx, rx) = mpsc::channel(100);
        runtime.spawn(Self::run(rx));
        Channel { addr, tx  }
    }

    pub fn create_session(&self, id: u16) -> Session {
        Session::new(id, self.tx.clone())
    }

    async fn run(mut rx: Receiver<Request>)  {
        while let Some(request) =  rx.recv().await {
            if let Err(_e) = request.reply_to.send(Reply::new( request.argument * request.argument)) {
                // TODO
            }
        }
    }
}

pub struct ModbusManager {
    rt: Rc<Runtime>,
}

impl ModbusManager {
    pub fn new(rt: Rc<Runtime>) -> Self {
        ModbusManager { rt }
    }

    pub fn create_channel(&self, addr: SocketAddr) -> Channel {
        Channel::new(addr, &self.rt)
    }
}

fn main() {
    let rt = Rc::new(Runtime::new().expect("unable to create runtime."));
    let manager = ModbusManager::new(rt.clone());
    let channel = manager.create_channel("127.0.0.1:8080".to_socket_addrs().expect("Invalid socket address").next().unwrap());
    let mut session = channel.create_session(0x76);


    rt.block_on(async move {
        let result = session.send(5).await;
        println!("Result: {:?}", result);
    });

}
