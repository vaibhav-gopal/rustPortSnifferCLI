use std::{
    io::{self, Write},
    net::{IpAddr, Ipv4Addr},
    sync::mpsc::{channel, Sender},
};
use bpaf::Bpaf;
use tokio::{
    task,
    net::TcpStream,
};
// Tokio is a runtime library that implements a task / call queue to run mutliple computations quickly and concurrently --> don't know whether it uses async/await or threads to acheive this or both
// Bpaf is a terminal tool, that lets us add menus, colors etc. --> the macro attribute lets us define menu options right in the implementation

const MAX: u16 = 65535;

const IPFALLBACK: IpAddr = IpAddr::V4(Ipv4Addr::new(127,0,0,1));

#[derive(Debug, Clone, Bpaf)]
#[bpaf(options)]
pub struct Arguments {
    #[bpaf(long, short, fallback(IPFALLBACK))]
    /// The address that you want to port sniff. Must be a valid IPV4 address. Falls back to current device
    pub address: IpAddr,
    #[bpaf(long("start"), short('s'), fallback(1u16), guard(start_port_guard, "must be greater than 0"))]
    /// The start port for the sniffer. (must be greater than 0)
    pub start_port: u16,
    #[bpaf(long("end"), short('e'), fallback(MAX), guard(end_port_guard, "must be less than or equal to 65535"))]
    /// The end port for the sniffer. (must be less than or equal to 65535)
    pub end_port: u16,
}

// Bpaf uses these functions when taking in inputs to the start/end port field in the Arguments struct --> acts as a guard or input verifier
fn start_port_guard(input: &u16) -> bool {
    *input > 0
}
fn end_port_guard(input: &u16) -> bool {
    *input <= MAX
}

async fn scan(tx: Sender<u16>, port: u16, addr: IpAddr) {
    match TcpStream::connect(format!("{}:{}",addr, port)).await {
        Ok(_) => {
            print!(".");
            io::stdout().flush().unwrap();
            tx.send(port).unwrap();
        }
        Err(_) => (),
    }
}

#[tokio::main]
async fn main() {
    //bpaf creates a function with the same name as the struct to implement the command line menu
    let opts: Arguments = arguments().run();

    let (tx, rx) = channel();
    for i in opts.start_port..=opts.end_port {
        let tx = tx.clone();
        task::spawn(async move {
            scan(tx,i, opts.address).await;
        });
    }

    let mut out = vec![];
    drop(tx);
    for p in rx {
        out.push(p);
    }
    println!("");
    out.sort();
    for v in out {
        println!("{} is open", v);
    }
}
