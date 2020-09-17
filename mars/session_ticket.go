package mars

import (
	"bytes"
	"encoding/binary"
	"time"
)

type sessionTicket struct {
	Type           byte // reversed unknown
	TicketLifeTime uint32
	TicketAgeAdd   []byte
	Reversed       uint32 // always 0x3a
	Nonce          []byte // 12 bytes nonce
	Ticket         []byte
}

func (this sessionTicket) serialized() []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(this.Type)
	_ = binary.Write(buf, binary.BigEndian, this.TicketLifeTime)
	writeU16LenData(buf, this.TicketAgeAdd)
	_ = binary.Write(buf, binary.BigEndian, this.Reversed)
	writeU16LenData(buf, this.Nonce)
	writeU16LenData(buf, this.Ticket)
	return buf.Bytes()
}

func deserializedSessionTicket(data []byte) sessionTicket {
	ticket := sessionTicket{}
	r := bytes.NewReader(data)
	ticket.Type, _ = r.ReadByte()
	_ = binary.Read(r, binary.BigEndian, &ticket.TicketLifeTime)
	ticket.TicketAgeAdd = readU16LenData(r)
	_ = binary.Read(r, binary.BigEndian, &ticket.Reversed)
	ticket.Nonce = readU16LenData(r)
	ticket.Ticket = readU16LenData(r)
	return ticket
}

type newSessionTicket struct {
	Reversed byte
	Len      byte
	Tickets  []sessionTicket
}

func (this *MMTLSClient) readNewSessionTicket(keyPair *trafficKeyPair) (*newSessionTicket, error) {
	pkt, err := this.readPackage(this.handshakeReader)
	if err != nil {
		return nil, err
	}

	pkt, err = this.readGCMPackage(pkt, keyPair)
	if err != nil {
		return nil, err
	}

	this.handshakeHasher.Write(pkt.data)

	exc := &newSessionTicket{}

	r := bytes.NewReader(pkt.data)

	var l uint32
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return nil, err
	}
	exc.Reversed, _ = r.ReadByte()

	exc.Len, _ = r.ReadByte()
	for i := byte(0); i < exc.Len; i++ {
		if err := binary.Read(r, binary.BigEndian, &l); err != nil {
			return nil, err
		}
		st := make([]byte, l)
		if _, err := r.Read(st); err != nil {
			return nil, err
		}
		exc.Tickets = append(exc.Tickets, deserializedSessionTicket(st))
	}

	this.handshakeServerSeqNum++
	return exc, nil
}

func (this *newSessionTicket) serialized() []byte {
	dataBuf := &bytes.Buffer{}
	dataBuf.Write([]byte{0, 0, 0, 0})
	dataBuf.WriteByte(0x04)
	dataBuf.WriteByte(0x02)
	for _, v := range this.Tickets {
		writeU32LenData(dataBuf, v.serialized())
	}
	buf := dataBuf.Bytes()
	binary.BigEndian.PutUint32(buf, uint32(len(buf)-4))
	return buf
}

func (this *newSessionTicket) export() []byte {
	earlyDataBuf := &bytes.Buffer{}
	writeU32LenData(earlyDataBuf, this.Tickets[0].serialized())
	return earlyDataBuf.Bytes()
}

func (this *newSessionTicket) exportWithPskRefresh(pskRefresh []byte) []byte {
	inner := &bytes.Buffer{}
	st := this.Tickets[1]
	stData := st.serialized()
	writeU32LenData(inner, stData)
	_ = binary.Write(inner, binary.BigEndian, uint64(time.Now().Unix()+int64(st.TicketLifeTime)))
	inner.Write(pskRefresh)
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, uint32(inner.Len()))
	data = append(data, inner.Bytes()...)
	return data
}
