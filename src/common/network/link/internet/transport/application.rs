use serde::Serialize;
use crate::common::network::packet::PacketReader;
use crate::network::ReadError;

#[derive(Serialize)]
pub enum ApplicationHeader {
    Default
}

impl ApplicationHeader {
    pub fn new<'a, 'b: 'a>(_packet_reader: &'a mut PacketReader<'b>) -> Result<ApplicationHeader, ReadError> {
        Ok(ApplicationHeader::Default)
    }
}