mod ether;
mod ip;
mod icmp;

pub use ether::*;
pub use ip::*;
pub use icmp::*;

pub trait Header: Sized {
    fn from_bytes(bytes: &[u8]) -> (Self, &[u8]);
    fn to_bytes(self) -> Vec<u8>;
}

impl<H0: Header, H1: Header> Header for (H0, H1)
{
    fn from_bytes(bytes: &[u8]) -> (Self, &[u8]) {
        let (h0, bytes) = H0::from_bytes(bytes);
        let (h1, rest) = H1::from_bytes(bytes);
        ((h0, h1), rest)
    }
    fn to_bytes(self) -> Vec<u8> {
        let (h0, h1) = self;
        let (mut h0, h1) = (h0.to_bytes(), h1.to_bytes());
        h0.extend(h1);
        h0
    }
}
