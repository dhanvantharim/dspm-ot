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

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn parse_valid_dnp3_frame() {
        let raw = [
            0x05, 0x64, 0x0C, 0xC4, // start + length + control
            0x01, 0x00, // dst
            0x02, 0x00, // src
            0x00, 0x00, // crc
            0xC0, // transport
            0x01, // function code
        ];
        let frame = parse(&raw).expect("valid dnp3 frame");
        assert_eq!(frame.dst, 1);
        assert_eq!(frame.src, 2);
        assert_eq!(frame.function_code, 1);
    }

    #[test]
    fn parse_rejects_invalid_start_bytes() {
        assert!(parse(&[0x00, 0x64]).is_none());
    }
}
