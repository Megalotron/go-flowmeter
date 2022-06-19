package capsule

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestReadValidFile(t *testing.T) {
	filename := "../tests/test_ethernet.pcap"

	reader, err := NewFileReader(filename)
	assert.NoError(t, err)

	// Got those by running : tcpdump -qns 0 -X -r tests/test_ethernet.pcap
	expectedSize := 10
	i := 0

	for {
		packet, err := reader.GetNextPacket()
		if packet == nil || err != nil {
			break
		}

		i++
	}
	assert.Equal(t, expectedSize, i)

	reader.Close()
}
