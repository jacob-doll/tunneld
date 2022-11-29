use log::{error, info, warn};
use pnet::packet::icmp::echo_reply::MutableEchoReplyPacket;
use pnet::packet::icmp::echo_request::EchoRequestPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::util::checksum;
use pnet_transport::icmp_packet_iter;
use pnet_transport::TransportProtocol::Ipv4;
use pnet_transport::{transport_channel, TransportChannelType::Layer4};
use regex::Regex;
use std::error::Error;
use std::net::Ipv4Addr;
use std::process::exit;
use std::result::Result;
use std::str::FromStr;
use std::u8;
use std::vec::Vec;
use tun_tap::{Iface, Mode};

use crate::common::cmd;

struct IpAllocation {
    ip: Ipv4Addr,
    allocated: bool,
}

struct IpPool {
    pool: Vec<IpAllocation>,
    cidr: u8,
}

impl IpPool {
    pub fn new(network: Ipv4Addr, cidr: u8) -> Result<Self, Box<dyn Error>> {
        let num_hosts = (2 << (31 - cidr)) - 1;

        let mut pool: Vec<IpAllocation> = Vec::new();

        let first_ip: u32 = network.into();
        let last_ip = first_ip + num_hosts;

        for ip in (first_ip + 2)..last_ip {
            pool.push(IpAllocation {
                ip: Ipv4Addr::from(ip),
                allocated: false,
            });
        }

        Ok(IpPool { pool, cidr })
    }

    pub fn alloc_ip(&mut self) -> Option<Ipv4Addr> {
        for alloc in &mut self.pool {
            if !alloc.allocated {
                alloc.allocated = true;
                return Some(alloc.ip);
            }
        }
        None
    }

    // fn release_ip(&mut self, addr: Ipv4Addr) {
    //     for alloc in &mut self.pool {
    //         if alloc.ip == addr {
    //             alloc.allocated = false;
    //             return;
    //         }
    //     }
    //     warn!("IP: {} not in pool range", addr);
    // }
}

pub struct Server {
    iface: Iface,
    pool: IpPool,
    tun_ip: Ipv4Addr,
}

impl Server {
    pub fn new(ifname: &str, subnet: &str) -> Result<Self, Box<dyn Error>> {
        let iface = Iface::new(ifname, Mode::Tun)?;

        info!("Tunnel Device created: {:?}", iface.name());

        let re = Regex::new(
            r"^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(/)([0-9]|[1-2][0-9]|3[0-2])$",
        )
        .unwrap();

        let cap = match re.captures(subnet) {
            Some(caps) => caps,
            None => return Err("Invalid subnet")?,
        };

        let network = Ipv4Addr::from_str(&cap[1])?;
        let cidr = &cap[3].to_string().parse::<u8>()?;

        let tun_ip_u32: u32 = network.into();
        let tun_ip = Ipv4Addr::from(tun_ip_u32 + 1);

        cmd(
            "ip",
            &[
                "addr",
                "add",
                "dev",
                iface.name(),
                format!("{}/{}", tun_ip, cidr).as_str(),
            ],
        );
        cmd("ip", &["link", "set", "up", "dev", iface.name()]);

        let pool = IpPool::new(network, cidr.clone())?;

        Ok(Server {
            iface,
            pool,
            tun_ip,
        })
    }

    fn proccess_packet(
        &mut self,
        echo_request: &EchoRequestPacket,
        echo_reply: &mut MutableEchoReplyPacket,
    ) {
        let mut payload = vec![0u8; echo_reply.packet().len() - 8];
        let tun_command = echo_request.packet()[12];

        payload[0..4].copy_from_slice(&echo_request.packet()[8..12]);

        match tun_command {
            0 => {
                info!("Handling new client request");
                payload[4] = 1u8;
                let ip = self.pool.alloc_ip().unwrap().octets();
                payload[5..9].clone_from_slice(&ip);
                payload[9] = self.pool.cidr;
            }
            _ => warn!("Unkown tunnel command: {}", tun_command),
        }

        echo_reply.set_payload(&payload);
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

        let mut iter = icmp_packet_iter(&mut rx);

        loop {
            // Receive packet
            match iter.next() {
                Ok((packet, addr)) => {
                    let echo_request = EchoRequestPacket::new(packet.packet()).unwrap();

                    if echo_request.get_icmp_type() != IcmpTypes::EchoRequest {
                        continue;
                    }

                    let mut out: Vec<u8> = vec![0; echo_request.packet().len()];

                    let mut echo_reply = MutableEchoReplyPacket::new(&mut out[..]).unwrap();
                    echo_reply.set_icmp_type(IcmpTypes::EchoReply);
                    echo_reply.set_identifier(echo_request.get_identifier());
                    echo_reply.set_sequence_number(echo_request.get_sequence_number());

                    let sig = &echo_request.payload()[0..4];

                    if sig != ['t' as u8, 'u' as u8, 'n' as u8, 'd' as u8] {
                        echo_reply.set_payload(echo_request.payload());
                    } else {
                        self.proccess_packet(&echo_request, &mut echo_reply)
                    }

                    echo_reply.set_checksum(checksum(echo_reply.packet(), 1));

                    match tx.send_to(echo_reply, addr) {
                        Ok(n) => assert_eq!(n, packet.packet().len()),
                        Err(e) => error!("failed to send packet: {}", e),
                    }
                }
                Err(e) => {
                    // If an error occurs, we can handle it here
                    error!("An error occurred while reading: {}", e);
                }
            }
        }
    }
}
