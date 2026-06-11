pub mod modbus;
pub mod ethernet_ip;
pub mod dnp3;

#[derive(Debug, Clone)]
pub enum OtProtocol {
    Modbus(modbus::ModbusFrame),
    EthernetIp(ethernet_ip::EipFrame),
    Dnp3(dnp3::Dnp3Frame),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolKind {
    Modbus,
    EthernetIp,
    Dnp3,
}

impl ProtocolKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Modbus => "modbus",
            Self::EthernetIp => "ethernet_ip",
            Self::Dnp3 => "dnp3",
        }
    }

    pub fn from_port(port: u16) -> Option<Self> {
        match port {
            502 => Some(Self::Modbus),
            44818 => Some(Self::EthernetIp),
            2222 => Some(Self::EthernetIp),
            20000 => Some(Self::Dnp3),
            _ => None,
        }
    }
}
