package capsule

// A Packet act as an encapsulation of a PCAP packet.
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
