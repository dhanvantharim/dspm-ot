use nom::{number::complete::{le_u16, le_u8}, IResult};

#[derive(Debug, Clone)]
pub struct Dnp3Frame {
    pub src: u16,
    pub dst: u16,
    pub function_code: u8,
}

pub fn parse(input: &[u8]) -> Option<Dnp3Frame> {
    parse_frame(input).ok().map(|(_, f)| f)
}

fn parse_frame(input: &[u8]) -> IResult<&[u8], Dnp3Frame> {
    // DNP3 data link layer: 0x0564 start bytes, length, control, dst, src
    let (input, _start) = nom::bytes::complete::tag(&[0x05u8, 0x64])(input)?;
    let (input, _length) = le_u8(input)?;
    let (input, _control) = le_u8(input)?;
    let (input, dst) = le_u16(input)?;
    let (input, src) = le_u16(input)?;
    // Transport and application layer — skip CRC (2 bytes), read function code
    let (input, _crc) = le_u16(input)?;
    let (input, _transport) = le_u8(input)?;
    let (input, function_code) = le_u8(input)?;
    Ok((input, Dnp3Frame { src, dst, function_code }))
}
