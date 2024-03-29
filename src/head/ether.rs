use std::fmt::Display;

use super::Header;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EtherKind {
    IP,
    ARP,
    Other(u16),
}

impl EtherKind {
    pub fn new(org: u16) -> Self {
        match org {
            0x0800 => EtherKind::IP,
            0x0806 => EtherKind::ARP,
            org => EtherKind::Other(org),
        }
    }
}

impl Header for EtherKind {
    fn from_bytes(bytes: &[u8]) -> (Self, &[u8]) {
        let (b, rest) = bytes.split_at(2);
        let org = ((b[0] as u16) << 8) + (b[1] as u16);
        (Self::new(org), rest)
    }
    fn to_bytes(self) -> Vec<u8> {
        match self {
            EtherKind::IP => [0x08, 0x00],
            EtherKind::ARP => [0x08, 0x06],
            EtherKind::Other(org) => org.to_le_bytes(),
        }
        .to_vec()
    }
}

pub struct EtherHdr {
    pub dhost: [u8; 6],
    pub shost: [u8; 6],
    pub etype: EtherKind,
}

impl Header for EtherHdr {
    fn from_bytes(bytes: &[u8]) -> (Self, &[u8]) {
        let (dhost, bytes) = bytes.split_at(6);
        let (shost, bytes) = bytes.split_at(6);
        let (etype, rest) = EtherKind::from_bytes(bytes);

        let dhost = dhost.try_into().unwrap();
        let shost = shost.try_into().unwrap();

        (
            Self {
                dhost,
                shost,
                etype,
            },
            rest,
        )
    }
    fn to_bytes(self) -> Vec<u8> {
        let etype = self.etype.to_bytes();
        let mut bytes = [self.dhost, self.shost].concat().to_vec();
        bytes.extend(etype);
        bytes
    }
}

impl Display for EtherHdr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dhost = self
            .dhost
            .iter()
            .map(|&c| format!("{:02x}", c))
            .collect::<Vec<String>>()
            .join(":");
        let shost = self
            .shost
            .iter()
            .map(|&c| format!("{:02x}", c))
            .collect::<Vec<String>>()
            .join(":");
        write!(f, "type: {:?} => MAC:{} >> {}", self.etype, shost, dhost)
    }
}
