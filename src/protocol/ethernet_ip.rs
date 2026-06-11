use nom::{number::complete::{le_u16, le_u32}, IResult};

#[derive(Debug, Clone)]
pub struct EipFrame {
    pub command: u16,
    pub session_handle: u32,
    pub status: u32,
}

pub fn parse(input: &[u8]) -> Option<EipFrame> {
    parse_encap_header(input).ok().map(|(_, f)| f)
}

fn parse_encap_header(input: &[u8]) -> IResult<&[u8], EipFrame> {
    let (input, command) = le_u16(input)?;
    let (input, _length) = le_u16(input)?;
    let (input, session_handle) = le_u32(input)?;
    let (input, status) = le_u32(input)?;
    Ok((input, EipFrame { command, session_handle, status }))
}
