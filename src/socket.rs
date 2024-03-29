use std::{
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

#[derive(Debug)]
pub struct PackSocket<const SIZE: usize> {
    pub socket: Socket,
    buf: [MaybeUninit<u8>; SIZE],
}

impl<const SIZE: usize> PackSocket<SIZE> {
    pub fn new(protocol: libc::c_int) -> std::io::Result<Self> {
        Ok(PackSocket {
            socket: Socket::new(
                Domain::PACKET,
                Type::RAW,
                Some(Protocol::from((protocol as i16).to_be() as i32)),
            )?,
            buf: [MaybeUninit::uninit(); SIZE],
        })
    }

    pub fn recive(&mut self) -> std::io::Result<(Vec<u8>, SockAddr)> {
        let (len, addr) = self.socket.recv_from(&mut self.buf)?;
        Ok((
            (0..len)
                .map(|idx| unsafe { self.buf[idx].assume_init() })
                .collect(),
            addr,
        ))
    }
}

impl<const S: usize> Deref for PackSocket<S> {
    type Target = Socket;
    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl<const S: usize> DerefMut for PackSocket<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.socket
    }
}
