use log::{error, info};
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::util::checksum;
use pnet_transport::icmp_packet_iter;
use pnet_transport::TransportProtocol::Ipv4;
use pnet_transport::{transport_channel, TransportChannelType::Layer4};
use std::thread::sleep;
use std::time::Duration;
use std::{io, net::IpAddr, process::exit, str::FromStr};
use tun_tap::{Iface, Mode};

pub struct Client {
    iface: Iface,
    server: IpAddr,
}

impl Client {
    pub fn new(ifname: &str, server: &str) -> io::Result<Self> {
        let iface = Iface::new(ifname, Mode::Tun)?;

        info!("Tunnel Device created: {:?}", iface.name());

        match IpAddr::from_str(server) {
            Ok(addr) => Ok(Client {
                iface,
                server: addr,
            }),
            Err(e) => {
                error!("Could not parse addr: {}", e);
                exit(1)
            }
        }
    }

    pub fn start(&mut self) {
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

        let mut seq_num = 1u16;
        let ident = 10u16;

        let mut iter = icmp_packet_iter(&mut rx);

        loop {
            let mut send_buf = [0u8; 8];
            match MutableEchoRequestPacket::new(&mut send_buf[..]) {
                Some(mut echo_request) => {
                    echo_request.set_icmp_type(IcmpTypes::EchoRequest);
                    echo_request.set_sequence_number(seq_num);
                    echo_request.set_identifier(ident);

                    echo_request.set_checksum(checksum(echo_request.packet(), 1));

                    match tx.send_to(echo_request, self.server) {
                        Ok(n) => assert_eq!(n, send_buf.len()),
                        Err(e) => error!("failed to send packet: {}", e),
                    }
                }
                None => {}
            }

            loop {
                match iter.next() {
                    Ok((packet, addr)) => {
                        if packet.get_icmp_type() != IcmpTypes::EchoReply {
                            continue;
                        }

                        match EchoReplyPacket::new(packet.packet()) {
                            Some(echo_reply) => {
                                if echo_reply.get_identifier() != ident
                                    || echo_reply.get_sequence_number() != seq_num
                                {
                                    continue;
                                }

                                info!("{} bytes from {}", packet.packet().len(), addr);
                                break;
                            }
                            None => {}
                        }
                    }
                    Err(e) => {
                        // If an error occurs, we can handle it here
                        error!("An error occurred while reading: {}", e);
                    }
                }
            }

            sleep(Duration::from_millis(1000));

            seq_num += 1;
        }
    }
}
