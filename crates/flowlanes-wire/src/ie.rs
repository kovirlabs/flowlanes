//! The information elements flowlanes knows by name.
//!
//! IDs, names and abstract data types are from the IANA "IP Flow Information
//! Export (IPFIX) Entities" registry (ipfix-information-elements.csv,
//! fetched 2026-11-22). NetFlow v9 field types 1-127 use the same numbers
//! (RFC 3954 §8, RFC 7012). An element not listed here, and every
//! enterprise-specific element, is kept as its ID and raw bytes (R4).

/// Abstract data types used by the listed elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IeType {
    Unsigned,
    Ipv4,
    Ipv6,
    Mac,
    Str,
    Octets,
    DateTimeSeconds,
    DateTimeMillis,
}

/// (id, name, type)
pub const KNOWN: &[(u16, &str, IeType)] = &[
    (1, "octetDeltaCount", IeType::Unsigned),
    (2, "packetDeltaCount", IeType::Unsigned),
    (4, "protocolIdentifier", IeType::Unsigned),
    (5, "ipClassOfService", IeType::Unsigned),
    (6, "tcpControlBits", IeType::Unsigned),
    (7, "sourceTransportPort", IeType::Unsigned),
    (8, "sourceIPv4Address", IeType::Ipv4),
    (9, "sourceIPv4PrefixLength", IeType::Unsigned),
    (10, "ingressInterface", IeType::Unsigned),
    (11, "destinationTransportPort", IeType::Unsigned),
    (12, "destinationIPv4Address", IeType::Ipv4),
    (13, "destinationIPv4PrefixLength", IeType::Unsigned),
    (14, "egressInterface", IeType::Unsigned),
    (15, "ipNextHopIPv4Address", IeType::Ipv4),
    (16, "bgpSourceAsNumber", IeType::Unsigned),
    (17, "bgpDestinationAsNumber", IeType::Unsigned),
    (21, "flowEndSysUpTime", IeType::Unsigned),
    (22, "flowStartSysUpTime", IeType::Unsigned),
    (27, "sourceIPv6Address", IeType::Ipv6),
    (28, "destinationIPv6Address", IeType::Ipv6),
    (29, "sourceIPv6PrefixLength", IeType::Unsigned),
    (30, "destinationIPv6PrefixLength", IeType::Unsigned),
    (32, "icmpTypeCodeIPv4", IeType::Unsigned),
    (34, "samplingInterval", IeType::Unsigned),
    (35, "samplingAlgorithm", IeType::Unsigned),
    (56, "sourceMacAddress", IeType::Mac),
    (58, "vlanId", IeType::Unsigned),
    (60, "ipVersion", IeType::Unsigned),
    (61, "flowDirection", IeType::Unsigned),
    (62, "ipNextHopIPv6Address", IeType::Ipv6),
    (80, "destinationMacAddress", IeType::Mac),
    (95, "applicationId", IeType::Octets),
    (96, "applicationName", IeType::Str),
    (130, "exporterIPv4Address", IeType::Ipv4),
    (136, "flowEndReason", IeType::Unsigned),
    (144, "exportingProcessId", IeType::Unsigned),
    (145, "templateId", IeType::Unsigned),
    (148, "flowId", IeType::Unsigned),
    (149, "observationDomainId", IeType::Unsigned),
    (150, "flowStartSeconds", IeType::DateTimeSeconds),
    (151, "flowEndSeconds", IeType::DateTimeSeconds),
    (152, "flowStartMilliseconds", IeType::DateTimeMillis),
    (153, "flowEndMilliseconds", IeType::DateTimeMillis),
    (160, "systemInitTimeMilliseconds", IeType::DateTimeMillis),
    (176, "icmpTypeIPv4", IeType::Unsigned),
    (177, "icmpCodeIPv4", IeType::Unsigned),
    (210, "paddingOctets", IeType::Octets),
    (225, "postNATSourceIPv4Address", IeType::Ipv4),
    (226, "postNATDestinationIPv4Address", IeType::Ipv4),
    (227, "postNAPTSourceTransportPort", IeType::Unsigned),
    (228, "postNAPTDestinationTransportPort", IeType::Unsigned),
    (230, "natEvent", IeType::Unsigned),
];

/// Name and type of an IANA element, if flowlanes knows it.
pub fn lookup(id: u16) -> Option<(&'static str, IeType)> {
    KNOWN
        .iter()
        .find(|(i, _, _)| *i == id)
        .map(|&(_, n, t)| (n, t))
}

/// The IANA ID of a known name.
pub fn id_of(name: &str) -> Option<u16> {
    KNOWN
        .iter()
        .find(|(_, n, _)| *n == name)
        .map(|&(i, _, _)| i)
}
