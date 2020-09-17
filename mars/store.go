package mars

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type Session struct {
	tk             *newSessionTicket
	PskAccess      []byte
	applicationKey *trafficKeyPair
	earlyKey       *trafficKeyPair
}

func LoadSession(buf []byte) (*Session, error) {
	ss := &Session{}
	tk := &newSessionTicket{}
	ss.tk = tk

	r := bytes.NewReader(buf)
	var l uint32
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return nil, err
	}

	if l > uint32(r.Len()) {
		return nil, errors.New("data corrupted")
	}

	tk.Reversed, _ = r.ReadByte()
	tk.Len, _ = r.ReadByte()
	for i := byte(0); i < tk.Len; i++ {
		st := deserializedSessionTicket(readU32LenData(r))
		tk.Tickets = append(tk.Tickets, st)
	}

	return ss, nil
}

func (this Session) SaveSession() []byte {
	return this.tk.serialized()
}
