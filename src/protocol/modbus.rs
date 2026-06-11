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
