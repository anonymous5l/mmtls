package mars

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
)

func pskExtension(t sessionTicket) []byte {
	t.TicketAgeAdd = nil
	buf := &bytes.Buffer{}
	buf.Write([]byte{0x00, 0x0f, 0x01}) // id
	stBuf := t.serialized()
	_ = binary.Write(buf, binary.BigEndian, uint32(len(stBuf)))
	buf.Write(stBuf)
	return buf.Bytes()
}

func serializedEcdsaPublicKey(index uint32, key ecdsa.PublicKey) []byte {
	kb := elliptic.Marshal(curve, key.X, key.Y)
	buf := make([]byte, 10)
	binary.BigEndian.PutUint32(buf, uint32(len(kb)+6))
	binary.BigEndian.PutUint32(buf[4:], index)
	binary.BigEndian.PutUint16(buf[8:], uint16(len(kb)))
	buf = append(buf, kb...)
	return buf
}

func ecdsaExtension(pk []ecdsa.PublicKey) []byte {
	buf := &bytes.Buffer{}
	buf.Write([]byte{0x00, 0x10, 0x02}) // id
	for i, v := range pk {
		buf.Write(serializedEcdsaPublicKey(uint32(i+1), v))
	}
	return buf.Bytes()
}
