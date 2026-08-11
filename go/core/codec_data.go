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
	"fmt"
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
}

type NackDart struct {
	Type       uint8
	ConvId     uint16
	SenderId   uint16
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

func (c *Codec) EncodeData(dart *DataDart, dict []byte) ([]byte, error) {
	epoch := c.CurrentEpochs[dart.ConvId]
	if epoch == 0 {
		epoch = 1
	}
	convKey := c.RoomKeys[dart.ConvId][epoch]
	if convKey == nil {
		return nil, errors.New("no group key established")
	}

	var compressed bytes.Buffer
	fw, _ := flate.NewWriterDict(&compressed, flate.DefaultCompression, dict)
	fw.Write([]byte(dart.Payload))
	fw.Close()

	// 7-byte cleartext header: type(1) | convId(2) | seq(3) | extLen(1).
	// The 18-byte extension carries nonce(12) + epoch(2) + dict fingerprint(4).
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	dictFp := DictFingerprint(dict)
	epochBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(epochBuf, epoch)

	header := make([]byte, 7)
	header[0] = dart.Type
	binary.BigEndian.PutUint16(header[1:3], dart.ConvId)
	writeUint24(header[3:6], dart.Seq)
	header[6] = 12 + 2 + DictFpLen // ext len = nonce + epoch + dict fingerprint

	aad := make([]byte, 0, len(header)+len(nonce)+len(epochBuf)+len(dictFp))
	aad = append(aad, header...)
	aad = append(aad, nonce...)
	aad = append(aad, epochBuf...)
	aad = append(aad, dictFp...)

	plaintext := make([]byte, 0, 2+compressed.Len())
	plaintext = append(plaintext, byte(dart.SenderId>>8), byte(dart.SenderId))
	plaintext = append(plaintext, compressed.Bytes()...)

	block, err := aes.NewCipher(convKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, aad)

	res := make([]byte, len(aad)+len(ciphertext))
	copy(res, aad)
	copy(res[len(aad):], ciphertext)
	return res, nil
}

func (c *Codec) DecryptData(buf []byte) (*DecryptedData, error) {
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
	aad := buf[:7+extLen]
	nonce := buf[7 : 7+12]
	epoch := binary.BigEndian.Uint16(buf[7+12 : 7+14])
	dictFp := buf[7+14 : 7+extLen]
	encryptedWithTag := buf[7+extLen:]

	convKey := c.RoomKeys[convId][epoch]
	if convKey == nil {
		return nil, fmt.Errorf("no group key for conv %d epoch %d", convId, epoch)
	}

	block, err := aes.NewCipher(convKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, encryptedWithTag, aad)
	if err != nil {
		return nil, err
	}
	if len(plaintext) < 2 {
		return nil, errors.New("invalid plaintext length")
	}

	senderId := binary.BigEndian.Uint16(plaintext[0:2])

	return &DecryptedData{
		Type:       typ,
		ConvId:     convId,
		SenderId:   senderId,
		Seq:        seq,
		Compressed: plaintext[2:],
		DictFp:     dictFp,
		Epoch:      epoch,
	}, nil
}

func InflateData(compressed []byte, dict []byte) ([]byte, error) {
	fr := flate.NewReaderDict(bytes.NewReader(compressed), dict)
	defer fr.Close()
	return ioutil.ReadAll(fr)
}
