package capsule

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// FileReader is used to read a PCAP file and extract each packet.
type FileReader struct {
	handler *pcap.Handle
	source  *gopacket.PacketSource
}

// NewFileReader creates an instance of FileReader to extract data from file referenced by its filename.
func NewFileReader(filename string) (*FileReader, error) {
	handler, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, err
	}

	source := gopacket.NewPacketSource(handler, handler.LinkType())

	return &FileReader{
		handler: handler,
		source:  source,
	}, nil
}

// GetNextPacket retrieves the next packet from the PCAP source.
func (r *FileReader) GetNextPacket() (gopacket.Packet, error) {
	packet, err := r.source.NextPacket()
	if err != nil {
		return nil, err
	}

	return packet, nil
}

// Close closes the PCAP file handler.
func (r *FileReader) Close() {
	r.handler.Close()
}
