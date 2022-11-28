use log::{error, info};
use pnet::packet::icmp::{checksum, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::{MutablePacket, Packet};
use pnet_transport::icmp_packet_iter;
use pnet_transport::TransportProtocol::Ipv4;
use pnet_transport::{transport_channel, TransportChannelType::Layer4};
use std::process::exit;
use std::{io, process::Command};
use tun_tap::{Iface, Mode};

pub struct Server {
    running: bool,
    iface: Iface,
}

fn cmd(cmd: &str, args: &[&str]) {
    let ecode = Command::new("ip")
        .args(args)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    assert!(ecode.success(), "Failed to execute {}", cmd);
}

impl Server {
    pub fn new(ifname: &str, subnet: &str) -> io::Result<Self> {
        let iface = Iface::new(ifname, Mode::Tun)?;

        info!("Tunnel Device created: {:?}", iface.name());

        cmd("ip", &["addr", "add", "dev", iface.name(), subnet]);
        cmd("ip", &["link", "set", "up", "dev", iface.name()]);

        Ok(Server {
            running: false,
            iface,
        })
    }

    pub fn start(&mut self) {
        self.running = true;

        let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));

        let (mut tx, mut rx) = match transport_channel(4096, protocol) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => {
                error!(
                    "An error occurred when creating the transport channel: {}",
                    e
                );
                exit(1)
            }
        };

        let mut iter = icmp_packet_iter(&mut rx);

        while self.running {
            match iter.next() {
                Ok((packet, addr)) => {
                    if packet.get_icmp_type() != IcmpTypes::EchoRequest {
                        continue;
                    }

                    let mut vec: Vec<u8> = vec![0; packet.packet().len()];
                    match MutableIcmpPacket::new(&mut vec[..]) {
                        Some(mut echo_reply) => {
                            echo_reply.clone_from(&packet);

                            echo_reply.set_icmp_type(IcmpTypes::EchoReply);
                            echo_reply.set_checksum(checksum(&echo_reply.to_immutable()));

                            match tx.send_to(echo_reply, addr) {
                                Ok(n) => assert_eq!(n, packet.packet().len()),
                                Err(e) => error!("failed to send packet: {}", e),
                            }
                        }
                        None => {}
                    };
                }
                Err(e) => {
                    // If an error occurs, we can handle it here
                    error!("An error occurred while reading: {}", e);
                }
            }
        }
    }
}
