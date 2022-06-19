package capsule

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewPacketFromPcapFile(t *testing.T) {
	testCases := []struct {
		name     string
		filename string
		err      error
		id       uint64
		srcIP    string
		dstIP    string
		srcPort  uint16
		dstPort  uint16
		protocol ProtocolNumber
	}{
		{
			name:     "Valid Local Ethernet Connection",
			filename: "../tests/test_ethernet.pcap",
			err:      nil,
			id:       0,
			srcIP:    "10.1.1.2",
			dstIP:    "10.1.1.1",
			srcPort:  44644,
			dstPort:  80,
			protocol: ProtocolTCP,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			var encapsulation Packet

			reader, err := NewFileReader(tt.filename)
			assert.NoError(t, err)

			packet, err := reader.GetNextPacket()
			assert.NoError(t, err)

			err = encapsulation.FromPCAP(packet, 0)
			assert.Equal(t, tt.err, err)

			if tt.err == nil {
				assert.Equal(t, tt.id, encapsulation.id)
				assert.Equal(t, tt.srcIP, encapsulation.srcIP)
				assert.Equal(t, tt.dstIP, encapsulation.dstIP)
				assert.Equal(t, tt.srcPort, encapsulation.srcPort)
				assert.Equal(t, tt.dstPort, encapsulation.dstPort)
				assert.Equal(t, tt.protocol, encapsulation.protocol)
			}

			reader.Close()
		})
	}
}
