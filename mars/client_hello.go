package mars

import (
	"bytes"
	"encoding/binary"
)

type clientHello struct {
	CipherSuite []uint16
	Random      []byte
	Timestamp   uint32
	Extension   [][]byte
	Count       byte
}

func (this clientHello) serialized() []byte {
	buf := &bytes.Buffer{}
	buf.Write([]byte{0x01, 0x03, 0xf1}) // id
	buf.WriteByte(byte(len(this.CipherSuite)))
	for _, v := range this.CipherSuite {
		_ = binary.Write(buf, binary.BigEndian, v)
	}
	buf.Write(this.Random)
	_ = binary.Write(buf, binary.BigEndian, this.Timestamp)
	extensionBuf := &bytes.Buffer{}
	for _, v := range this.Extension {
		writeU32LenData(extensionBuf, v)
	}

	_ = binary.Write(buf, binary.BigEndian, uint32(extensionBuf.Len()+1))
	buf.WriteByte(this.Count)
	buf.Write(extensionBuf.Bytes())
	return buf.Bytes()
}

func (this *MMTLSClient) clientHello(hello *clientHello) error {
	// for now only support new handshake
	buf := &bytes.Buffer{}
	buf.Write(hello.serialized())

	internal := buf.Bytes()
	pkt := make([]byte, 4)
	binary.BigEndian.PutUint32(pkt, uint32(len(internal)))
	pkt = append(pkt, internal...)

	this.handshakeHasher.Write(pkt)
	this.handshakeClientSeqNum++

	pkt = buildPackage(magicHandshake, pkt).serialized()

	header, err := this.buildRequestHeader(int64(len(pkt)))
	if err != nil {
		return err
	}

	pkt = append(header, pkt...)

	_, err = this.conn.Write(pkt)

	return err
}
