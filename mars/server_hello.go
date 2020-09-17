package mars

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
)

type serverHello struct {
	CipherSuite uint16
	PublicKey   *ecdsa.PublicKey
}

func (this *MMTLSClient) readServerHello() (*serverHello, error) {
	resp, err := http.ReadResponse(bufio.NewReader(this.conn), nil)
	if err != nil {
		return nil, err
	}

	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	this.handshakeReader = bytes.NewReader(buf)

	pkt, err := this.readPackage(this.handshakeReader)
	if err != nil {
		return nil, err
	}

	if !magicCompare(pkt.magic, magicHandshake) {
		return nil, errors.New("magic not compare")
	}

	this.handshakeHasher.Write(pkt.data)
	this.handshakeServerSeqNum++

	hello := &serverHello{}

	r := bytes.NewReader(pkt.data)

	var l uint32
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return nil, err
	}

	if uint32(pkt.length-4) < l {
		return nil, errors.New("data corrupted")
	}

	// skip 3 reversed
	if _, err := r.Seek(3, io.SeekCurrent); err != nil {
		return nil, err
	}

	if err := binary.Read(r, binary.BigEndian, &hello.CipherSuite); err != nil {
		return nil, err
	}

	// skip server random
	if _, err := r.Seek(32, io.SeekCurrent); err != nil {
		return nil, err
	}

	// skip array pkt len
	if _, err := r.Seek(4, io.SeekCurrent); err != nil {
		return nil, err
	}

	// skip pkt len
	_, _ = r.ReadByte()

	// skip pkt len
	if _, err := r.Seek(4, io.SeekCurrent); err != nil {
		return nil, err
	}

	// skip pkt type
	if _, err := r.Seek(2, io.SeekCurrent); err != nil {
		return nil, err
	}

	// skip array index
	if _, err := r.Seek(4, io.SeekCurrent); err != nil {
		return nil, err
	}

	var pkLen uint16
	if err := binary.Read(r, binary.BigEndian, &pkLen); err != nil {
		return nil, err
	}

	ecPoint := make([]byte, pkLen)
	if _, err := r.Read(ecPoint); err != nil {
		return nil, err
	}

	x, y := elliptic.Unmarshal(curve, ecPoint)

	hello.PublicKey = &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	return hello, nil
}
