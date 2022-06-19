package capsule

type ProtocolNumber uint8

// Protocol Numbers, defined by IANA at https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
const (
	ProtocolTCP ProtocolNumber = 6
	ProtocolUDP ProtocolNumber = 17
)
