use super::Header;
use Protocol::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IPFlag {
    /// 是否允许分片。取值为 0 时，表示允许分片
    pub df: bool,
    /// 是否还有分片正在传输，设置为 0 时，表示没有更多分片需要发送，或数据报没有分片
    pub mf: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    Other(u8),
}

impl Default for Protocol {
    fn default() -> Self {
        ICMP
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IPHdr {
    /// 占 4 位，表示 IP 协议的版本。通信双方使用的 IP 协议版本必须一致。
    /// 目前广泛使用的IP协议版本号为 4，即 IPv4。
    pub version: u8,
    /// 占 4 位，可表示的最大十进制数值是 15。
    pub ihl: u8,
    /// 占 8 位，用来获得更好的服务。只有在使用区分服务时，这个字段才起作用。
    pub tos: u8,
    /// 首部和数据之和，单位为字节。总长度字段为 16 位，因此数据报的最大长度为 2^16-1=65535 字节。
    pub totlen: u16,
    /// 用来标识数据报，占 16 位。IP 协议在存储器中维持一个计数器。
    pub ident: u16,
    /// 占 3 位。第一位未使用，其值为 0。
    pub flag: IPFlag,
    /// 占 13 位。当报文被分片后，该字段标记该分片在原报文中的相对位置。 片偏移以 8 个字节为偏移单位。
    /// 所以，除了最后一个分片，其他分片的偏移值都是 8 字节（64 位）的整数倍。
    pub offset: u16,
    /// 表示数据报在网络中的寿命，占 8 位。该字段由发出数据报的源主机设置。
    /// 其目的是防止无法交付的数据报无限制地在网络中传输，从而消耗网络资源。
    pub ttl: u8,
    /// 表示该数据报文所携带的数据所使用的协议类型，占 8 位。
    /// 例如，TCP 的协议号为 6，UDP 的协议号为 17，ICMP 的协议号为 1。
    pub protocol: Protocol,
    /// 用于校验数据报的首部，占 16 位。
    pub chksum: u16,
    /// 表示数据报的源 IP 地址，占 32 位。
    pub source: [u8; 4],
    /// 表示数据报的目的 IP 地址，占 32 位。该字段用于校验发送是否正确。
    pub destinaiton: [u8; 4],
    /// 该字段用于一些可选的报头设置，主要用于测试、调试和安全的目的。
    /// 这些选项包括严格源路由（数据报必须经过指定的路由）、网际时间戳（经过每个路由器时的时间戳记录）和安全限制。
    pub opt_section: Vec<u8>,
}

impl Header for IPHdr {
    fn from_bytes(bytes: &[u8]) -> (Self, &[u8]) {
        let (hbytes, bytes) = bytes.split_at(20);

        let version = hbytes[0] >> 4;
        let ihl = (hbytes[0] & 0x0f) * 4;
        let tos = hbytes[1];
        let totlen = u16::from_be_bytes(hbytes[2..4].try_into().unwrap());
        let ident = u16::from_be_bytes(hbytes[4..6].try_into().unwrap());
        let flag = IPFlag {
            df: (hbytes[6] & 0b0100_0000) > 0,
            mf: (hbytes[6] & 0b0010_0000) > 0,
        };
        let offset = (((hbytes[6] & 0b0001_1111) as u16) << 8) | (hbytes[7] as u16);
        let ttl = hbytes[8];
        let protocol = match hbytes[9] {
            1 => ICMP,
            6 => TCP,
            17 => UDP,
            p => Other(p),
        };
        let checksum = u16::from_be_bytes(hbytes[10..12].try_into().unwrap());
        let source = hbytes[12..16].try_into().unwrap();
        let destinaiton = hbytes[16..20].try_into().unwrap();

        let opt_len = (ihl - 20) as usize;
        let opt_section = if opt_len > 0 {
            hbytes[20..opt_len].into_iter().cloned().collect()
        } else {
            Vec::new()
        };

        (
            IPHdr {
                version,
                ihl,
                tos,
                totlen,
                ident,
                flag,
                offset,
                ttl,
                protocol,
                chksum: checksum,
                source,
                destinaiton,
                opt_section,
            },
            bytes,
        )
    }
    fn to_bytes(self) -> Vec<u8> {
        let mut bytes = vec![];
        let ver_ihl = (self.version << 4) | (self.ihl / 4);
        bytes.push(ver_ihl);
        bytes.push(self.tos);
        bytes.extend_from_slice(&self.totlen.to_be_bytes());
        bytes.extend_from_slice(&self.ident.to_be_bytes());
        let mut offset = self.offset.to_be_bytes();
        if self.flag.df {
            offset[0] |= 0b0100_0000;
        }
        if self.flag.mf {
            offset[0] |= 0b0010_0000;
        }
        bytes.extend_from_slice(&offset);
        bytes.push(self.ttl);
        bytes.push(match self.protocol {
            ICMP => 1,
            TCP => 6,
            UDP => 17,
            Other(p) => p,
        });
        bytes.extend_from_slice(&self.chksum.to_be_bytes());
        bytes.extend_from_slice(&self.source);
        bytes.extend_from_slice(&self.destinaiton);
        bytes.extend_from_slice(&self.opt_section);
        bytes
    }
}

impl IPHdr {
    pub fn new(ident: u16) -> Self {
        Self {
            version: 4,
            ihl: 20,
            ident,
            flag: IPFlag {
                df: true,
                mf: false,
            },
            ttl: 64,
            totlen: 20,
            source: [0, 0, 0, 0],
            ..Default::default()
        }
    }

    pub fn ttl(self, ttl: u8) -> Self {
        Self { ttl, ..self }
    }

    pub fn protocol(self, protocol: Protocol) -> Self {
        Self { protocol, ..self }
    }

    pub fn destination(self, addr: [u8; 4]) -> Self {
        Self {
            destinaiton: addr,
            ..self
        }
    }

    pub fn get_chksum(&self) -> u16 {
        self.chksum
    }

    pub fn checksum(mut self) -> Self {
        self.chksum = 0;
        let bytes = self.clone().to_bytes();

        let mut sum: u32 = bytes
            .chunks(2)
            .map(|bs| (bs[0] as u32) << 8 | bs[1] as u32)
            .sum();

        while sum >> 16 != 0 {
            sum = (sum >> 16) + (sum & 0xffff);
        }

        self.chksum = !sum as u16;

        self
    }

    pub fn append_opt(self, mut opt_section: Vec<u8>) -> Self {
        let mut len = opt_section.len();
        let rem = len % 4;
        if rem > 0 {
            len += 4;
            opt_section.extend(vec![0u8; rem]);
        }
        Self {
            ihl: self.ihl + (len as u8) / 4,
            totlen: self.totlen + (len as u16),
            opt_section,
            ..self
        }
    }
}
