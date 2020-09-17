package mars

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/hkdf"
)

var (
	curve = elliptic.P256()
)

type MMTLSClient struct {
	conn                                         net.Conn
	status                                       int32
	publicEcdh, verifyEcdh                       *ecdsa.PrivateKey
	serverEcdh                                   *ecdsa.PublicKey
	handshakeHasher                              hash.Hash
	handshakeReader                              io.Reader
	handshakeServerSeqNum, handshakeClientSeqNum byte

	Session *Session
}

type trafficKeyPair struct {
	ClientKey   []byte
	ServerKey   []byte
	ClientNonce []byte
	ServerNonce []byte
}

func NewMMTLSClient() *MMTLSClient {
	cli := &MMTLSClient{}
	cli.handshakeHasher = sha256.New()

	cli.serverEcdh = &ecdsa.PublicKey{
		Curve: curve,
		X:     toBigIntFromHex("f2e3a105249f5628ca8a7f9264eff421752b99ff25f6c6bb560a8e207fc03b75"),
		Y:     toBigIntFromHex("dbd4c1785e6db96c149be739c7b249d0b0d3d2c9edef568f343548b68041f0f2"),
	}
	return cli
}

func (this *MMTLSClient) handshakeComplete() bool {
	return atomic.LoadInt32(&this.status) == 1
}

func (this *MMTLSClient) generalKeyPair() error {
	if this.publicEcdh == nil {
		public, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return err
		}
		this.publicEcdh = public
	}

	if this.verifyEcdh == nil {
		verify, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return err
		}
		this.verifyEcdh = verify
	}

	return nil
}

func (this *MMTLSClient) readRandom(s int) []byte {
	b := make([]byte, s)
	if n, err := rand.Read(b); err != nil {
		return nil
	} else if n != s {
		return nil
	}
	return b
}

func (this *MMTLSClient) readPackage(r io.Reader) (*mmtlsPackage, error) {
	header := make([]byte, 5)

	n, err := r.Read(header)
	if err != nil {
		return nil, err
	} else if n != len(header) {
		return nil, errors.New("data length")
	}

	pkt := deserializeHeader(header)
	pkt.data = make([]byte, pkt.length)

	offset := 0

	for uint16(offset) < pkt.length {
		n, err := r.Read(pkt.data[offset:])
		if err != nil {
			return nil, err
		}
		offset += n
	}

	return pkt, nil
}

func (this *MMTLSClient) sendPackage(pkt *mmtlsPackage) error {
	if _, err := this.conn.Write(pkt.serialized()); err != nil {
		return err
	}
	return nil
}

func (this *MMTLSClient) computeShareKey(x, y, z *big.Int) []byte {
	r, _ := curve.ScalarMult(x, y, z.Bytes())
	s := sha256.Sum256(r.Bytes())
	return s[:]
}

func (this *MMTLSClient) earlyDataKey(pskAccess []byte, st *newSessionTicket) (*trafficKeyPair, error) {
	earlyDataHash := sha256.New()
	earlyDataHash.Write(st.export())

	trafficKey := make([]byte, 28)
	if _, err := hkdf.Expand(sha256.New, pskAccess,
		this.buildHkdfInfo("early data key expansion", earlyDataHash)).
		Read(trafficKey); err != nil {
		return nil, err
	}
	// early data key expansion
	pair := &trafficKeyPair{}
	pair.ClientKey = trafficKey[:16]
	pair.ClientNonce = trafficKey[16:]
	return pair, nil
}

func (this *MMTLSClient) trafficKey(shareKey, info []byte) (*trafficKeyPair, error) {
	trafficKey := make([]byte, 56)
	if _, err := hkdf.Expand(sha256.New, shareKey, info).Read(trafficKey); err != nil {
		return nil, err
	}
	pair := &trafficKeyPair{}
	pair.ClientKey = trafficKey[:16]
	pair.ServerKey = trafficKey[16:32]
	pair.ClientNonce = trafficKey[32:44]
	pair.ServerNonce = trafficKey[44:]
	return pair, nil
}

func (this *MMTLSClient) readGCMPackage(pkt *mmtlsPackage, keys *trafficKeyPair) (*mmtlsPackage, error) {
	c, err := aes.NewCipher(keys.ServerKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	copy(nonce, keys.ServerNonce)
	nonce[11] = nonce[11] ^ this.handshakeServerSeqNum
	auddit := make([]byte, 13)
	binary.BigEndian.PutUint64(auddit, uint64(this.handshakeServerSeqNum))
	copy(auddit[8:], pkt.magic)
	binary.BigEndian.PutUint16(auddit[11:], pkt.length)

	dst, err := aead.Open(nil, nonce, pkt.data, auddit)
	if err != nil {
		return nil, err
	}

	pkt.reset(dst)

	return pkt, nil
}

func (this *MMTLSClient) sendGCMPackage(pkt *mmtlsPackage, keys *trafficKeyPair) error {
	c, err := aes.NewCipher(keys.ClientKey)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(c)
	if err != nil {
		return err
	}

	nonce := make([]byte, 12)
	copy(nonce, keys.ClientNonce)
	nonce[11] = nonce[11] ^ this.handshakeClientSeqNum

	auddit := make([]byte, 13)
	binary.BigEndian.PutUint64(auddit, uint64(this.handshakeClientSeqNum))
	copy(auddit[8:], pkt.magic)
	binary.BigEndian.PutUint16(auddit[11:], pkt.length)

	pkt.reset(aead.Seal(nil, nonce, pkt.data, auddit))

	return this.sendPackage(pkt)
}

func (this *MMTLSClient) verifyEcdsa(data []byte) bool {
	dataHash := sha256.Sum256(this.handshakeHasher.Sum(nil))
	return ecdsa.VerifyASN1(this.serverEcdh, dataHash[:], data)
}

func (this *MMTLSClient) buildHkdfInfo(prefix string, hash hash.Hash) []byte {
	info := []byte(prefix)
	if hash != nil {
		info = append(info, hash.Sum(nil)...)
	}
	return info
}

func (this *MMTLSClient) hmac(k, d []byte) []byte {
	hm := hmac.New(sha256.New, k)
	hm.Write(d)
	return hm.Sum(nil)
}

func (this *MMTLSClient) clientFinal(comKey []byte, keyPair *trafficKeyPair) error {
	cliKey := make([]byte, 32)
	if _, err := hkdf.Expand(sha256.New, comKey,
		this.buildHkdfInfo("client finished",
			nil)).Read(cliKey); err != nil {
		return err
	}
	cliKey = this.hmac(cliKey, this.handshakeHasher.Sum(nil))

	buf := &bytes.Buffer{}
	if err := binary.Write(buf, binary.BigEndian, uint32(3+len(cliKey))); err != nil {
		return err
	}
	buf.WriteByte(0x14)
	if err := binary.Write(buf, binary.BigEndian, uint16(len(cliKey))); err != nil {
		return err
	}
	buf.Write(cliKey)

	pkt := buildPackage(magicHandshake, buf.Bytes())

	if err := this.sendGCMPackage(pkt, keyPair); err != nil {
		return err
	}

	this.handshakeClientSeqNum++
	return nil
}

func (this *MMTLSClient) reset() {
	this.handshakeHasher.Reset()
	this.handshakeClientSeqNum = 0
	this.handshakeServerSeqNum = 0
}

func (this *MMTLSClient) buildRequestHeader(cl int64) ([]byte, error) {
	request := &http.Request{
		Method:     http.MethodPost,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Close:      true,
		Header:     map[string][]string{},
	}

	randName := make([]byte, 4)
	if _, err := rand.Read(randName); err != nil {
		return nil, err
	}

	request.Header.Set("Accept", "*/*")
	request.Header.Set("Cache-Control", "no-cache")
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Content-Length", fmt.Sprintf("%d", cl))
	request.Header.Set("Upgrade", "mmtls")
	request.Header.Set("User-Agent", "MicroMessenger Client")
	request.URL, _ = url.Parse(fmt.Sprintf("https://dns.weixin.qq.com/mmtls/%x", randName))

	b, err := httputil.DumpRequest(request, false)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (this *MMTLSClient) Handshake() error {
	if this.conn == nil {
		conn, err := net.Dial("tcp", "dns.weixin.qq.com:443")
		if err != nil {
			return err
		}
		this.conn = conn
	}
	if !this.handshakeComplete() {
		this.reset()

		if err := this.generalKeyPair(); err != nil {
			return err
		}

		ch := &clientHello{}
		ch.Timestamp = uint32(time.Now().Unix())
		ch.Random = this.readRandom(32)
		// 1-RTT ECDHE, 1-RTT PSK, 0-RTT PSK

		if this.Session != nil {
			// INAN 0x00 0xA8 TLS_PSK_WITH_AES_128_GCM_SHA256
			ch.CipherSuite = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0xa8}
			ch.Count = 2
			ch.Extension = append(ch.Extension, pskExtension(this.Session.tk.Tickets[1]))
		} else {
			ch.Count = 1
			ch.CipherSuite = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
		}
		ch.Extension = append(ch.Extension, append(ecdsaExtension([]ecdsa.PublicKey{
			this.publicEcdh.PublicKey,
			this.verifyEcdh.PublicKey,
		}), 0x00, 0x00, 0x00, 0x01))

		if err := this.clientHello(ch); err != nil {
			return err
		}

		serverHello, err := this.readServerHello()
		if err != nil {
			return err
		}

		// DH compute key
		comKey := this.computeShareKey(serverHello.PublicKey.X, serverHello.PublicKey.Y, this.publicEcdh.D)

		// traffic keys
		trafficKey, err := this.trafficKey(comKey,
			this.buildHkdfInfo("handshake key expansion", this.handshakeHasher))

		if err != nil {
			return err
		}

		// compare traffic key is valid
		signature, err := this.readSignature(trafficKey)
		if err != nil {
			return err
		}

		if !this.verifyEcdsa(signature.EcdsaSignature) {
			return errors.New("verify signature failed")
		}

		sData := signature.serialized()
		this.handshakeHasher.Write(sData)

		// for not don't process
		// example: for next usage save information to local storage
		ex, err := this.readNewSessionTicket(trafficKey)
		if err != nil {
			return err
		}

		pskAccess := make([]byte, 32)
		if _, err := hkdf.Expand(sha256.New, comKey,
			this.buildHkdfInfo("PSK_ACCESS",
				this.handshakeHasher)).Read(pskAccess); err != nil {
			return err
		}

		// for next psk key update time one mouth
		pskRefresh := make([]byte, 32)
		if _, err := hkdf.Expand(sha256.New, comKey,
			this.buildHkdfInfo("PSK_REFRESH",
				this.handshakeHasher)).Read(pskRefresh); err != nil {
			return err
		}

		sf, err := this.readServerFinish(trafficKey)
		if err != nil {
			return err
		}

		sfKey := make([]byte, 32)
		if _, err := hkdf.Expand(sha256.New, comKey,
			this.buildHkdfInfo("server finished",
				nil)).Read(sfKey); err != nil {
			return err
		}

		securityParam := this.hmac(sfKey, this.handshakeHasher.Sum(nil))

		if bytes.Compare(sf.Data, securityParam) != 0 {
			return errors.New("security key not compare")
		}

		// local store cache
		//ex.exportWithPskRefresh(pskRefresh)

		if err := this.clientFinal(comKey, trafficKey); err != nil {
			return err
		}

		expandedSecret := make([]byte, 32)
		if _, err := hkdf.Expand(sha256.New, comKey,
			this.buildHkdfInfo("expanded secret",
				this.handshakeHasher)).Read(expandedSecret); err != nil {
			return err
		}

		keyExchange, err := this.trafficKey(expandedSecret,
			this.buildHkdfInfo("application data key expansion",
				this.handshakeHasher))
		if err != nil {
			return err
		}

		earlyPair, err := this.earlyDataKey(pskAccess, ex)
		if err != nil {
			return err
		}

		// set psk session
		if this.Session == nil {
			this.Session = &Session{
				tk:             ex,
				PskAccess:      pskAccess,
				earlyKey:       earlyPair,
				applicationKey: keyExchange,
			}
		}

		// fully complete handshake
		atomic.StoreInt32(&this.status, 1)
	}

	return nil
}
