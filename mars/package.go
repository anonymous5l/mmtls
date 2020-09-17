package mars

import (
	"encoding/binary"
	"encoding/hex"
	"math/big"
)

var (
	magicHandshake = []byte{0x16, 0xf1, 0x03}
	magicAbort     = []byte{0x15, 0xf1, 0x03}
	magicSystem    = []byte{0x19, 0xf1, 0x03}
)

func magicCompare(magic, compare []byte) bool {
	return magic[0] == compare[0] && magic[1] == compare[1] && magic[2] == compare[2]
}

type mmtlsPackage struct {
	magic  []byte
	length uint16
	data   []byte
}

func buildPackage(magic, data []byte) *mmtlsPackage {
	return &mmtlsPackage{
		magic:  magic,
		data:   data,
		length: uint16(len(data)),
	}
}

func (this *mmtlsPackage) reset(data []byte) {
	this.data = data
	this.length = uint16(len(data))
}

func (this mmtlsPackage) serialized() []byte {
	buf := make([]byte, this.length+5)
	copy(buf[:3], this.magic[:3])
	binary.BigEndian.PutUint16(buf[3:], this.length)
	copy(buf[5:], this.data)
	return buf
}

func deserializeHeader(data []byte) *mmtlsPackage {
	if len(data) >= 5 {
		pkt := &mmtlsPackage{
			magic: make([]byte, 3),
		}
		copy(pkt.magic, data[:3])
		pkt.length = binary.BigEndian.Uint16(data[3:])
		return pkt
	}
	return nil
}

func toBigIntFromHex(s string) *big.Int {
	b := big.NewInt(0)
	d, _ := hex.DecodeString(s)
	b.SetBytes(d)
	return b
}
