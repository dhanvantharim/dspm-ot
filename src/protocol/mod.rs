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

#[cfg(test)]
mod tests {
    use super::ProtocolKind;

    #[test]
    fn from_port_maps_ot_ports() {
        assert_eq!(ProtocolKind::from_port(502), Some(ProtocolKind::Modbus));
        assert_eq!(ProtocolKind::from_port(44818), Some(ProtocolKind::EthernetIp));
        assert_eq!(ProtocolKind::from_port(2222), Some(ProtocolKind::EthernetIp));
        assert_eq!(ProtocolKind::from_port(20000), Some(ProtocolKind::Dnp3));
        assert_eq!(ProtocolKind::from_port(80), None);
    }

    #[test]
    fn as_str_returns_stable_names() {
        assert_eq!(ProtocolKind::Modbus.as_str(), "modbus");
        assert_eq!(ProtocolKind::EthernetIp.as_str(), "ethernet_ip");
        assert_eq!(ProtocolKind::Dnp3.as_str(), "dnp3");
    }
}
