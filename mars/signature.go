package mars

import (
	"bytes"
	"encoding/binary"
	"io"
)

type signature struct {
	Type           byte
	EcdsaSignature []byte
}

func (this *MMTLSClient) readSignature(trafficKey *trafficKeyPair) (*signature, error) {
	pkt, err := this.readPackage(this.handshakeReader)
	if err != nil {
		return nil, err
	}

	// compare traffic key is valid
	verifyPkt, err := this.readGCMPackage(pkt, trafficKey)
	if err != nil {
		return nil, err
	}

	s := &signature{}

	r := bytes.NewReader(verifyPkt.data)

	// package length
	if _, err := r.Seek(4, io.SeekCurrent); err != nil {
		return nil, err
	}

	// static 0x0f
	s.Type, _ = r.ReadByte()

	var l uint16

	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return nil, err
	}

	s.EcdsaSignature = make([]byte, l)
	if _, err := r.Read(s.EcdsaSignature); err != nil {
		return nil, err
	}

	this.handshakeServerSeqNum++
	return s, nil
}

func (this signature) serialized() []byte {
	buf := &bytes.Buffer{}
	buf.Write([]byte{0, 0, 0, 0})
	buf.WriteByte(this.Type)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(this.EcdsaSignature)))
	buf.Write(this.EcdsaSignature)
	rBuf := buf.Bytes()
	binary.BigEndian.PutUint32(rBuf, uint32(buf.Len()-4))
	return rBuf
}

type serverFinish struct {
	Reversed byte
	Data     []byte
}

func (this *MMTLSClient) readServerFinish(trafficKey *trafficKeyPair) (*serverFinish, error) {
	pkt, err := this.readPackage(this.handshakeReader)
	if err != nil {
		return nil, err
	}

	// compare traffic key is valid
	pkt, err = this.readGCMPackage(pkt, trafficKey)
	if err != nil {
		return nil, err
	}

	sf := &serverFinish{}

	r := bytes.NewReader(pkt.data)

	// package length
	if _, err := r.Seek(4, io.SeekCurrent); err != nil {
		return nil, err
	}

	// static reversed
	sf.Reversed, _ = r.ReadByte()

	var l uint16

	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return nil, err
	}

	sf.Data = make([]byte, l)
	if _, err := r.Read(sf.Data); err != nil {
		return nil, err
	}

	this.handshakeServerSeqNum++
	return sf, nil
}
