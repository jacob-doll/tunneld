use log::{error, info, warn};
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::util::checksum;
use pnet_transport::icmp_packet_iter;
use pnet_transport::TransportProtocol::Ipv4;
use pnet_transport::{transport_channel, TransportChannelType::Layer4};
use std::error::Error;
use std::net::Ipv4Addr;
use std::thread::sleep;
use std::time::Duration;
use std::{net::IpAddr, process::exit, str::FromStr};
use tun_tap::{Iface, Mode};

use crate::common::cmd;

pub struct Client {
    iface: Iface,
    server: IpAddr,
    tun_ip: Ipv4Addr,
    command: u8,
}

impl Client {
    pub fn new(ifname: &str, server: &str) -> Result<Self, Box<dyn Error>> {
        let iface = Iface::new(ifname, Mode::Tun)?;

        info!("Tunnel Device created: {:?}", iface.name());

        let addr = IpAddr::from_str(server)?;
        Ok(Client {
            iface,
            server: addr,
            tun_ip: Ipv4Addr::new(0, 0, 0, 0),
            command: 0,
        })
    }

    fn process_reply(&mut self, echo_reply: &EchoReplyPacket) {
        let payload = &echo_reply.packet()[8..];
        let tun_command = payload[4];

        match tun_command {
            1 => {
                self.tun_ip = Ipv4Addr::new(payload[5], payload[6], payload[7], payload[8]);
                let cidr = payload[9];

                let subnet = format!("{}/{}", self.tun_ip, cidr);
                info!("Got ip: {} from server", subnet);

                cmd(
                    "ip",
                    &["addr", "add", "dev", self.iface.name(), subnet.as_str()],
                );
                cmd("ip", &["link", "set", "up", "dev", self.iface.name()]);

                self.command = 2;
            }
            _ => warn!("Unkown tunnel command: {}", tun_command),
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
            let mut send_buf = [0u8; 1024];
            let mut payload = vec![0u8; send_buf.len() - 8];
            let mut echo_request = MutableEchoRequestPacket::new(&mut send_buf[..]).unwrap();

            echo_request.set_icmp_type(IcmpTypes::EchoRequest);
            echo_request.set_sequence_number(seq_num);
            echo_request.set_identifier(ident);

            // payload handling
            payload[0..4].copy_from_slice(&['t' as u8, 'u' as u8, 'n' as u8, 'd' as u8]);

            payload[4] = self.command;

            echo_request.set_payload(&payload);
            echo_request.set_checksum(checksum(echo_request.packet(), 1));

            match tx.send_to(echo_request, self.server) {
                Ok(n) => assert_eq!(n, send_buf.len()),
                Err(e) => error!("failed to send packet: {}", e),
            }

            loop {
                match iter.next() {
                    Ok((packet, _)) => {
                        let echo_reply = EchoReplyPacket::new(packet.packet()).unwrap();

                        if echo_reply.get_icmp_type() != IcmpTypes::EchoReply
                            || echo_reply.get_identifier() != ident
                            || echo_reply.get_sequence_number() != seq_num
                        {
                            continue;
                        }

                        self.process_reply(&echo_reply);
                        break;
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
