package core

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io/ioutil"
)

const (
	TypeData      = 0x01
	TypeNack      = 0x02
	TypeSync      = 0x03
	TypeKeyReq    = 0x04
	TypeKeyShare  = 0x08
	TypeMemberInfo = 0x09
	TypeDictReset = 0x06
	TypeAck       = 0x07

	// DictWindow bounds the per-sender compression window so both sides build
	// identical dictionaries deterministically and clients can prune history.
	DictWindow = 200
	// DictFpLen is the length of the dictionary fingerprint in the Data header.
	DictFpLen = 4
)

type DataDart struct {
	Type     uint8
	ConvId   uint16
	SenderId uint16
	Seq      uint32
	Payload  string
}

// DecryptedData is the first stage of decoding a Data dart: the payload is
// decrypted and the senderId recovered, but the payload is not yet inflated
// (inflation needs the per-sender dictionary, which requires knowing senderId).
type DecryptedData struct {
	Type       uint8
	ConvId     uint16
	SenderId   uint16
	Seq        uint32
	Compressed []byte
	DictFp     []byte
	Epoch      uint16
	Idx        uint32
}

type NackDart struct {
	Type       uint8
	ConvId     uint16
	SenderId   uint16 // the member who detected the gap (the signer)
	TargetId   uint16 // the member whose stream has the gap
	MissingSeq []uint32
}

type SyncDart struct {
	Type       uint8
	ConvId     uint16
	SenderId   uint16
	HighestSeq uint32
}

type KeyReqDart struct {
	Type         uint8
	ConvId       uint16
	SenderId     uint16
	ReqNonce     []byte
	ClientPubKey []byte
}

// KeyShareDart is a member-to-member group-key delivery relayed opaquely by
// the server. The group key is ECDH-encrypted to the target member.
type KeyShareDart struct {
	Type         uint8
	ConvId       uint16
	SenderId     uint16
	TargetId     uint16
	Epoch        uint16
	Nonce        []byte
	EncryptedKey []byte // GCM ciphertext+tag of the 32-byte group key
}

type Member struct {
	SenderId uint16
	PubKey   []byte
}

// MemberInfo is the server-authenticated membership roster.
type MemberInfo struct {
	Type         uint8
	ConvId       uint16
	SenderId     uint16
	ServerPubKey []byte
	Creator      bool
	Members      []Member
}

type DictResetDart struct {
	Type     uint8
	ConvId   uint16
	SenderId uint16
	TargetId uint16
}

type AckDart struct {
	Type     uint8
	ConvId   uint16
	SenderId uint16
	TargetId uint16
	Seq      uint32
}

type Codec struct {
	ConvKeys      map[uint16][]byte            // current group key per conv (set on adopt)
	RoomKeys      map[uint16]map[uint16][]byte // epoch -> key (for decrypting old epochs)
	CurrentEpochs map[uint16]uint16
}

func NewCodec() *Codec {
	return &Codec{
		ConvKeys:      make(map[uint16][]byte),
		RoomKeys:      make(map[uint16]map[uint16][]byte),
		CurrentEpochs: make(map[uint16]uint16),
	}
}

func writeUint24(b []byte, v uint32) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

// DictFingerprint is the first 4 bytes of SHA-256(dict). Both the sender and
// every receiver compute it over their own (windowed) dictionary; a mismatch
// means lost history.
func DictFingerprint(dict []byte) []byte {
	sum := sha256.Sum256(dict)
	return sum[:DictFpLen]
}

func readUint24(b []byte) uint32 {
	return uint32(b[2]) | uint32(b[1])<<8 | uint32(b[0])<<16
}

func (c *Codec) getConvKey(convId uint16) ([]byte, error) {
	if key, ok := c.ConvKeys[convId]; ok {
		return key, nil
	}
	return nil, errors.New("no conversation key established")
}

func (c *Codec) EncodeData(dart *DataDart, dict []byte, messageKey []byte, idx uint32, nonce []byte) ([]byte, error) {
	epoch := c.CurrentEpochs[dart.ConvId]
	if epoch == 0 {
		epoch = 1
	}

	var compressed bytes.Buffer
	fw, _ := flate.NewWriterDict(&compressed, flate.DefaultCompression, dict)
	fw.Write([]byte(dart.Payload))
	fw.Close()

	// 7-byte cleartext header + 24-byte cleartext extension (all AAD):
	//   senderId(2) | nonce(12) | epoch(2) | dictFp(4) | idx(4).
	// The payload is the deflated message; the key is the sender's per-message
	// ratchet key (see chain.go).
	if nonce == nil {
		nonce = make([]byte, 12)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}
	dictFp := DictFingerprint(dict)

	prefix := make([]byte, 7+24)
	prefix[0] = dart.Type
	binary.BigEndian.PutUint16(prefix[1:3], dart.ConvId)
	writeUint24(prefix[3:6], dart.Seq)
	prefix[6] = 24
	binary.BigEndian.PutUint16(prefix[7:9], dart.SenderId)
	copy(prefix[9:21], nonce)
	binary.BigEndian.PutUint16(prefix[21:23], epoch)
	copy(prefix[23:27], dictFp)
	binary.BigEndian.PutUint32(prefix[27:31], idx)

	block, err := aes.NewCipher(messageKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, compressed.Bytes(), prefix)

	res := make([]byte, len(prefix)+len(ciphertext))
	copy(res, prefix)
	copy(res[len(prefix):], ciphertext)
	return res, nil
}

func (c *Codec) DecryptData(buf []byte, messageKey []byte) (*DecryptedData, error) {
	if len(buf) < 7 {
		return nil, errors.New("buffer too short")
	}
	typ := buf[0]
	convId := binary.BigEndian.Uint16(buf[1:3])
	seq := readUint24(buf[3:6])
	extLen := int(buf[6])

	if len(buf) < 7+extLen+16 {
		return nil, errors.New("invalid payload length")
	}
	prefix := buf[:7+extLen]
	senderId := binary.BigEndian.Uint16(prefix[7:9])
	nonce := prefix[9:21]
	epoch := binary.BigEndian.Uint16(prefix[21:23])
	dictFp := prefix[23:27]
	idx := binary.BigEndian.Uint32(prefix[27:31])
	encryptedWithTag := buf[7+extLen:]

	block, err := aes.NewCipher(messageKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, encryptedWithTag, prefix)
	if err != nil {
		return nil, err
	}

	return &DecryptedData{
		Type:       typ,
		ConvId:     convId,
		SenderId:   senderId,
		Seq:        seq,
		Compressed: plaintext,
		DictFp:     dictFp,
		Epoch:      epoch,
		Idx:        idx,
	}, nil
}

func InflateData(compressed []byte, dict []byte) ([]byte, error) {
	fr := flate.NewReaderDict(bytes.NewReader(compressed), dict)
	defer fr.Close()
	return ioutil.ReadAll(fr)
}
