package mars

import (
	"encoding/binary"
	"io"
)

func writeU32LenData(w io.Writer, d []byte) {
	_ = binary.Write(w, binary.BigEndian, uint32(len(d)))
	if len(d) > 0 {
		_, _ = w.Write(d)
	}
}

func writeU16LenData(w io.Writer, d []byte) {
	_ = binary.Write(w, binary.BigEndian, uint16(len(d)))
	if len(d) > 0 {
		_, _ = w.Write(d)
	}
}

func readU16LenData(r io.Reader) []byte {
	var u16l uint16
	_ = binary.Read(r, binary.BigEndian, &u16l)
	if u16l > 0 {
		b := make([]byte, u16l)
		_, _ = r.Read(b)
		return b
	}
	return nil
}

func readU32LenData(r io.Reader) []byte {
	var u32l uint32
	_ = binary.Read(r, binary.BigEndian, &u32l)
	if u32l > 0 {
		b := make([]byte, u32l)
		_, _ = r.Read(b)
		return b
	}
	return nil
}
