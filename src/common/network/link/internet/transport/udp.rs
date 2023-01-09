use serde::Serialize;
use crate::common::network::packet::PacketReader;
use crate::network::ReadError;

#[derive(Serialize)]
pub struct UDPHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16
}

impl UDPHeader {
    const SIZE: usize = 8;

    pub fn new<'a, 'b: 'a>(packet_reader: &'a mut PacketReader<'b>) -> Result<UDPHeader, ReadError> {
        let bytes = packet_reader.read(Self::SIZE)?;

        Ok(UDPHeader {
            src_port: u16::from_be_bytes(bytes[..2].try_into()?),
            dst_port: u16::from_be_bytes(bytes[2..4].try_into()?),
            length: u16::from_be_bytes(bytes[4..6].try_into()?),
            checksum: u16::from_be_bytes(bytes[6..8].try_into()?)
        })
    }
}