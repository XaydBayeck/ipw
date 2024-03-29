use std::{collections::HashMap, fs, io::Read, mem, os::fd::AsRawFd, path::Path};

use libc::posix_spawn_file_actions_addchdir_np;
use socket2::{Domain, SockAddr, Socket, Type};

use crate::{
    head::{EtherHdr, EtherKind, Header, IPHdr, Protocol},
    socket::PackSocket,
};

#[derive(Debug)]
pub struct App<const S: usize> {
    socket: PackSocket<S>,
    addr: SockAddr,
    arp: PackSocket<64>,
    macs: Vec<(String, [u8; 6])>,
    log: bool,
}

impl<const S: usize> App<S> {
    pub fn new() -> std::io::Result<Self> {
        let socket = PackSocket::<S>::new(libc::ETH_P_IP)?;
        let addr = unsafe {
            // Initialise a `SocketAddr` byte calling `getsockname(2)`.
            let mut addr_storage: libc::sockaddr_storage = mem::zeroed();
            let mut len = mem::size_of_val(&addr_storage) as libc::socklen_t;

            // The `getsockname(2)` system call will intiliase `storage` for
            // us, setting `len` to the correct length.
            let res = libc::getsockname(
                socket.socket.as_raw_fd(),
                (&mut addr_storage as *mut libc::sockaddr_storage).cast(),
                &mut len,
            );
            if res == -1 {
                return Err(std::io::Error::last_os_error());
            }
            SockAddr::new(addr_storage, 20)
        };

        Ok(App {
            socket,
            addr,
            arp: PackSocket::new(libc::ETH_P_ALL)?,
            macs: get_macs()
                .into_iter()
                .map(|(ifc, mac)| {
                    let mac = mac
                        .trim()
                        .split(':')
                        .map(|num| {
                            u8::from_str_radix(num, 16)
                                .expect("MAC address must be write like `ff:ff:ff:ff:ff:ff`")
                        })
                        .collect::<Vec<u8>>()
                        .try_into()
                        .unwrap();
                    (ifc, mac)
                })
                .collect(),
            log: false,
        })
    }

    pub fn get_mac(&mut self, dhost: [u8; 4]) -> std::io::Result<[u8; 6]> {
        let shost = Socket::new(Domain::IPV4, Type::DGRAM, None)?
            .local_addr()?
            .as_socket_ipv4()
            .unwrap()
            .ip()
            .octets();
        let smac = self.macs[0].1;
        // 设置目标 IP 地址和硬件地址
        let dest_hw = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]; // Broadcast MAC address

        // 构建 ARP 请求报文
        let mut arp_packet = [0u8; 42];

        let ethdr = EtherHdr {
            dhost: dest_hw,
            shost: smac,
            etype: EtherKind::ARP,
        }
        .to_bytes();

        arp_packet[0..14].copy_from_slice(&ethdr);
        arp_packet[14] = 0x00;
        arp_packet[15] = 0x01; // 硬件类型 (Ethernet)
        arp_packet[16] = 0x08;
        arp_packet[17] = 0x00; // 协议类型 (IPv4)
        arp_packet[18] = 0x06; // 硬件地址长度
        arp_packet[19] = 0x04; // 协议地址长度
        arp_packet[20..22].copy_from_slice(&[0x00, 0x01]); // 操作类型 (ARP Request)
        arp_packet[22..28].copy_from_slice(&smac); // 发送方硬件地址
        arp_packet[28..32].copy_from_slice(&[10, 38, 255, 149]); // 发送方协议地址
        arp_packet[32..38].copy_from_slice(&dest_hw); // 目标硬件地址
        arp_packet[38..42].copy_from_slice(&dhost); // 目标协议地址

        let dst_addr = unsafe {
            // Initialise a `SocketAddr` byte calling `getsockname(2)`.
            let mut addr_storage: libc::sockaddr_storage = mem::zeroed();
            let mut len = mem::size_of_val(&addr_storage) as libc::socklen_t;

            // The `getsockname(2)` system call will intiliase `storage` for
            // us, setting `len` to the correct length.
            let res = libc::getsockname(
                self.arp.socket.as_raw_fd(),
                (&mut addr_storage as *mut libc::sockaddr_storage).cast(),
                &mut len,
            );
            if res == -1 {
                return Err(std::io::Error::last_os_error());
            }
            SockAddr::new(addr_storage, 20)
        };

        // let arp_packet = [255, 255, 255, 255, 255, 255, 152, 141, 70, 92, 99, 59, 8, 6, 0, 1, 8, 0, 6, 4, 0, 1, 152, 141, 70, 92, 99, 59, 10, 38, 255, 149, 255, 255, 255, 255, 255, 255, 13, 107, 21, 200];

        println!("{:?}", dst_addr.domain());

        // 绑定到指定 IP 地址和接口
        // self.arp.bind(&dst_addr)?;
        // println!("connect success!");
        // self.arp.bind(&SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0).into())?;
        self.arp.send_to(&arp_packet, &dst_addr)?;
        println!("send success!");

        let (data, addr) = dbg!(self.arp.recive()?);

        if data.len() > 42 && &data[20..22] == [0x00, 0x02] {
            Ok(data[22..28].try_into().unwrap())
        } else {
            Err(std::io::Error::from_raw_os_error(22))
        }
    }

    pub fn send_file(
        &self,
        ident: u16,
        dhost: [u8; 6],
        dstip: [u8; 4],
        protocol: Protocol,
        file: &Path,
        radix: u32,
    ) -> std::io::Result<usize> {
        let content = fs::read_to_string(file)?;
        self.send(ident, dhost, dstip, protocol, &content, radix)
    }

    pub fn send(
        &self,
        ident: u16,
        dhost: [u8; 6],
        dstip: [u8; 4],
        protocol: Protocol,
        buf: &str,
        radix: u32,
    ) -> std::io::Result<usize> {
        let smac = self.macs[0].1;

        let content = buf
            .chars()
            .map(|c| u8::from_str_radix(&c.to_string(), radix).expect("content must be bytes!!!"))
            .collect::<Vec<_>>();

        let ehdr = EtherHdr {
            dhost,
            shost: smac,
            etype: EtherKind::IP,
        };

        let ippacket = IPHdr::new(ident)
            .destination(dstip)
            .protocol(protocol)
            .checksum();

        let mut output = (ehdr, ippacket).to_bytes();
        output.extend(content);

        self.socket.send_to(&output, &self.addr)
    }

    pub fn analyz(&mut self) -> std::io::Result<()> {
        let mut table = HashMap::new();
        loop {
            let (data, addr) = self.socket.recive()?;
            let ((_, iphdr), buf) = <(EtherHdr, IPHdr)>::from_bytes(&data);
            let num = table.get(&iphdr.protocol).unwrap_or(&0);
            table.insert(iphdr.protocol, num + 1);
            println!("============IP报文数据分析============");
            for (protocol, num) in &table {
                print!("  协议：{protocol:?}=>{num},");
            }
            println!("\n=======================================");
        }
    }

    pub fn filter(
        &mut self,
        src_mac: Option<[u8; 6]>,
        dst_mac: Option<[u8; 6]>,
        shost: Option<[u8; 4]>,
        dhost: Option<[u8; 4]>,
        log: bool,
    ) -> std::io::Result<()> {
        loop {
            let (data, addr) = self.socket.recive()?;
            let ((ethdr, iphdr), buf) = <(EtherHdr, IPHdr)>::from_bytes(&data);
            let smac_flag = src_mac.is_some_and(|mac| ethdr.shost == mac) || src_mac.is_none();
            let dmac_flag = dst_mac.is_some_and(|mac| ethdr.dhost == mac) || dst_mac.is_none();
            let sip_flag = shost.is_some_and(|ip| iphdr.source == ip) || shost.is_none();
            let dip_flag = dhost.is_some_and(|ip| iphdr.destinaiton == ip) || dhost.is_none();

            if smac_flag && dmac_flag && sip_flag && dip_flag {
                println!("============IP报文数据分析============");
                println!(
                    "IP版本：{}, 首部长：{} byte, TOS：{}",
                    iphdr.version, iphdr.ihl, iphdr.tos
                );
                println!("数据长度: {}, 报文ID：{}", iphdr.totlen, iphdr.ident);
                println!("允许分片：{}, 已分片：{}", iphdr.flag.df, iphdr.flag.mf);
                println!("片偏移：{} byte", iphdr.offset);
                println!("生存期：{} 跳", iphdr.ttl);
                println!("协议：{:?}", iphdr.protocol);
                println!("校验和：{}", iphdr.chksum);
                println!(
                    "源: {}, 目的IP：{}",
                    iphdr.source.map(|n| n.to_string()).join("."),
                    iphdr.destinaiton.map(|n| n.to_string()).join("."),
                );
                if !iphdr.opt_section.is_empty() {
                    println!("额外报首部信息：{:?}", iphdr.opt_section);
                }
                println!("数据：\n{:?}", buf);
                println!("=======================================");
            }
        }
    }
}

fn get_macs() -> Vec<(String, String)> {
    let net = Path::new("/sys/class/net");
    let entry =
        std::fs::read_dir(net).expect(&format!("No such directory {}", net.to_str().unwrap()));

    entry
        .filter_map(|p| p.ok())
        .map(|p| p.path().file_name().expect("No such file!").to_os_string())
        .filter_map(|s| s.into_string().ok())
        .map(|ifc| {
            let iface = net.join(&ifc).join("address");
            let mut f = std::fs::File::open(iface).expect("Error");
            let mut macaddr = String::new();
            f.read_to_string(&mut macaddr).expect("Error");
            (ifc, macaddr)
        })
        .collect::<Vec<_>>()
}
