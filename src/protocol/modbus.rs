use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u8},
    IResult,
};

#[derive(Debug, Clone)]
pub struct ModbusFrame {
    pub transaction_id: u16,
    pub unit_id: u8,
    pub function_code: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionCode {
    ReadCoils = 1,
    ReadDiscreteInputs = 2,
    ReadHoldingRegisters = 3,
    ReadInputRegisters = 4,
    WriteSingleCoil = 5,
    WriteSingleRegister = 6,
    WriteMultipleCoils = 15,
    WriteMultipleRegisters = 16,
    ReadDeviceIdentification = 43,
    Unknown,
}

impl From<u8> for FunctionCode {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::ReadCoils,
            2 => Self::ReadDiscreteInputs,
            3 => Self::ReadHoldingRegisters,
            4 => Self::ReadInputRegisters,
            5 => Self::WriteSingleCoil,
            6 => Self::WriteSingleRegister,
            15 => Self::WriteMultipleCoils,
            16 => Self::WriteMultipleRegisters,
            43 => Self::ReadDeviceIdentification,
            _ => Self::Unknown,
        }
    }
}

impl FunctionCode {
    pub fn is_write(&self) -> bool {
        matches!(
            self,
            Self::WriteSingleCoil
                | Self::WriteSingleRegister
                | Self::WriteMultipleCoils
                | Self::WriteMultipleRegisters
        )
    }
}

pub fn parse(input: &[u8]) -> Option<ModbusFrame> {
    parse_mbap(input).ok().map(|(_, frame)| frame)
}

fn parse_mbap(input: &[u8]) -> IResult<&[u8], ModbusFrame> {
    let (input, transaction_id) = be_u16(input)?;
    let (input, _protocol_id) = be_u16(input)?;
    let (input, length) = be_u16(input)?;
    let (input, unit_id) = be_u8(input)?;
    let (input, function_code) = be_u8(input)?;
    let data_len = length.saturating_sub(2) as usize;
    let (input, data_bytes) = take(data_len)(input)?;

    Ok((
        input,
        ModbusFrame {
            transaction_id,
            unit_id,
            function_code,
            data: data_bytes.to_vec(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::{FunctionCode, parse};

    #[test]
    fn parse_valid_mbap_frame() {
        // transaction=1, proto=0, length=3, unit=1, fc=3 (read holding), data=0x00
        let raw = [0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x03, 0x00];
        let frame = parse(&raw).expect("valid modbus frame");
        assert_eq!(frame.transaction_id, 1);
        assert_eq!(frame.unit_id, 1);
        assert_eq!(frame.function_code, 3);
        assert_eq!(frame.data, vec![0x00]);
    }

    #[test]
    fn parse_rejects_truncated_frame() {
        assert!(parse(&[0x00, 0x01, 0x00, 0x00]).is_none());
    }

    #[test]
    fn function_code_write_detection() {
        assert!(FunctionCode::from(5).is_write());
        assert!(FunctionCode::from(16).is_write());
        assert!(!FunctionCode::from(3).is_write());
        assert_eq!(FunctionCode::from(99), FunctionCode::Unknown);
    }
}
