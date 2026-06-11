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

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn parse_encapsulation_header() {
        let raw = [
            0x65, 0x00, // Register Session
            0x04, 0x00, // length
            0x01, 0x00, 0x00, 0x00, // session handle
            0x00, 0x00, 0x00, 0x00, // status
        ];
        let frame = parse(&raw).expect("valid eip header");
        assert_eq!(frame.command, 0x0065);
        assert_eq!(frame.session_handle, 1);
        assert_eq!(frame.status, 0);
    }

    #[test]
    fn parse_rejects_short_input() {
        assert!(parse(&[0x65, 0x00]).is_none());
    }
}
