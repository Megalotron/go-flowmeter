package capsule

// A Packet act as an encapsulation of a PCAP *packet.
// It is used to fill up a Flow.
type Packet struct {
	// 1. Identification
	// -----
	// Used to identify the current Packet in the Flow.
	id uint64
	// Used to identify the packet's protocol based on the IANA list.
	protocol ProtocolNumber

	// 2. Content
	// -----
	// These two fields represents the source and destination ports of the current packet.
	srcPort uint16
	dstPort uint16
	// Similarly, these two fields represents the source and destination addresses for the
	// current packet.
	srcAddress string
	dstAddress string
	// This flag is used as an indication of whether this packet is a TCP termination-call.
	flagFIN bool

	// 3. Metadata
	// -----
	// Used to indicate when the packet was captured.
	timestamp uint64
	// Used to attach this packet to a specific Flow.
	flowID string
}

// ID returns the packet's unique identifier.
func (p *Packet) ID() uint64 {
	return p.id
}

// Protocol returns the IANA protocol identifier for this packet.
func (p *Packet) Protocol() ProtocolNumber {
	return p.protocol
}

// SrcPort returns the packet's source port.
func (p *Packet) SrcPort() uint16 {
	return p.srcPort
}

// DstPort returns the packet's destination port.
func (p *Packet) DstPort() uint16 {
	return p.dstPort
}

// SrcAddress returns the packet's source address.
func (p *Packet) SrcAddress() string {
	return p.srcAddress
}

// DstAddress returns the packet's destination address.
func (p *Packet) DstAddress() string {
	return p.dstAddress
}

// FlagFIN returns true if the packet is used as a TCP termination call.
// It returns false otherwise.
func (p *Packet) FlagFIN() bool {
	return p.flagFIN
}

// Timestamp returns the UNIX timestamp when the packet was captured.
func (p *Packet) Timestamp() uint64 {
	return p.timestamp
}

// FlowID returns the identifier of the Flow which contains this packet.
func (p *Packet) FlowID() string {
	return p.flowID
}

// nolint:lll
// NewPacket creates a new PCAP packet encapsulation from the given information.
func NewPacket(id uint64, protocol ProtocolNumber, srcPort uint16, dstPort uint16, srcAddress string, dstAddress string, timestamp uint64) *Packet {
	return &Packet{
		id:         id,
		protocol:   protocol,
		srcPort:    srcPort,
		dstPort:    dstPort,
		srcAddress: srcAddress,
		dstAddress: dstAddress,
		timestamp:  timestamp,
	}
}
