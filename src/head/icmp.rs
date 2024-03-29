use super::Header;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ping {
    pub ident: u16,
    pub seqnum: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ICMP {
    pub typ: u8,
    pub code: u8,
    pub chksum: u16,
    pub msg: Option<Ping>,
}

impl ICMP {
    pub fn new(typ: u8, code: u8) -> Self {
        Self {
            typ,
            code,
            chksum: 0,
            msg: None,
        }
    }

    pub fn with_ident(self, ident: u16) -> Self {
        let seqnum = self.msg.map(|msg| msg.seqnum).unwrap_or(0);
        Self {
            msg: Some(Ping {
                ident,
                seqnum,
            }),
            ..self
        }
    }
    
    pub fn with_seqnum(self, seqnum: u16) -> Self {
        let ident = self.msg.map(|msg| msg.ident).unwrap_or(0);
        Self {
            msg: Some(Ping {
                ident,
                seqnum,
            }),
            ..self
        }
    }

    pub fn checksum(mut self, data:&[u8]) -> Self {
        self.chksum = 0;
        let mut bytes = self.clone().to_bytes();
        bytes.extend_from_slice(data);

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


    pub fn typ_dsc(&self) -> String {
        match (self.typ, self.code) {
            (0, 0) => "回显应答（ping应答）",
            (8, 0) => "请求回显（ping请求）",
            (9, 0) => "路由器通告",
            (10, 0) => "路由器请求",
            (13, 0) => "时间戳请求（目前已不使用）",
            (14, 0) => "时间戳应答（目前已不使用）",
            (15, 0) => "信息请求（目前已不使用）",
            (16, 0) => "信息应答（目前已不使用）",
            (17, 0) => "地址掩码请求",
            (18, 0) => "地址掩码应答",
            (3, 0) => "网络不可达",
            (3, 1) => "主机不可达",
            (3, 2) => "协议不可达",
            (3, 3) => "端口不可达",
            (3, 6) => "目的网络不认识",
            (3, 7) => "目的主机不认识",
            (3, 9) => "目的网络被强制禁止",
            (3, 10) => "目的主机被强制隔离",
            (3, 11) => "由于TOS,网络不可达",
            (3, 12) => "由于TOS,主机不可达",
            (3, 13) => "由于过滤，通信被强制禁止",
            (4, 0) => "源端被关闭",
            (5, 0) => "对网络重定向",
            (5, 1) => "对主机重定向",
            (5, 2) => "对服务类型和网络重定向",
            (5, 3) => "对服务类型和主机重定向",
            (11, 0) => "传输期间生存时间为0",
            (11, 1) => "在数据报组装期间生存时间为0",
            (12, 0) => "坏的IP首部",
            (12, 1) => "缺少必须的选项",
            _ => "未定义",
        }
        .to_string()
    }
}

impl Header for ICMP {
    fn from_bytes(bytes: &[u8]) -> (Self, &[u8]) {
        let (hdr, bytes) = bytes.split_at(4);
        let typ = hdr[0];
        let code = hdr[1];
        let chksum = u16::from_be_bytes(hdr[2..4].try_into().unwrap());
        let (msg, rest) = if matches!(typ, 0 | 8 | 9 | 10 | 13 | 14 | 15 | 16 | 17 | 18) {
            let (dada, rest) = bytes.split_at(4);
            let ident = u16::from_be_bytes(dada[0..2].try_into().unwrap());
            let seqnum = u16::from_be_bytes(dada[2..4].try_into().unwrap());
            (Some(Ping { ident, seqnum }), rest)
        } else {
            (None, bytes)
        };

        (
            ICMP {
                typ,
                code,
                chksum,
                msg,
            },
            rest,
        )
    }

    fn to_bytes(self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.push(self.typ);
        bytes.push(self.code);
        bytes.extend(self.chksum.to_be_bytes());
        if let Some(msg) = self.msg {
            bytes.extend(msg.ident.to_be_bytes());
            bytes.extend(msg.seqnum.to_be_bytes());
        }
        bytes
    }
}
