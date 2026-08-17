package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

func nackPrefixLen(missingCount int) int {
	return 21 + missingCount*3
}

// ParseNack reads the cleartext gap list. A blind relay uses this to repair
// from cache without holding the group key.
func ParseNack(buf []byte) (*NackDart, error) {
	if len(buf) < 21 {
		return nil, errors.New("buffer too short")
	}
	count := int(binary.BigEndian.Uint16(buf[19:21]))
	headerLen := nackPrefixLen(count)
	if len(buf) < headerLen {
		return nil, errors.New("buffer too short")
	}
	seqs := make([]uint32, 0, count)
	for i := 0; i < count; i++ {
		off := 21 + i*3
		seqs = append(seqs, readUint24(buf[off:off+3]))
	}
	return &NackDart{
		Type:       buf[0],
		ConvId:     binary.BigEndian.Uint16(buf[1:3]),
		SenderId:   binary.BigEndian.Uint16(buf[3:5]),
		TargetId:   binary.BigEndian.Uint16(buf[5:7]),
		MissingSeq: seqs,
	}, nil
}

func (c *Codec) EncodeNack(nack *NackDart, nonce []byte) ([]byte, error) {
	convKey, err := c.getConvKey(nack.ConvId)
	if err != nil {
		return nil, err
	}

	// Cleartext prefix: type(1) | convId(2) | senderId(2) | targetId(2)
	// | nonce(12) | count(2) | seqs(3*count). GCM authenticates empty
	// plaintext; the whole prefix is AAD so a blind server can still read
	// the gap list.
	if nonce == nil {
		nonce = make([]byte, 12)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}

	headerLen := nackPrefixLen(len(nack.MissingSeq))
	header := make([]byte, headerLen)
	header[0] = nack.Type
	binary.BigEndian.PutUint16(header[1:3], nack.ConvId)
	binary.BigEndian.PutUint16(header[3:5], nack.SenderId)
	binary.BigEndian.PutUint16(header[5:7], nack.TargetId)
	copy(header[7:19], nonce)
	binary.BigEndian.PutUint16(header[19:21], uint16(len(nack.MissingSeq)))
	for i, seq := range nack.MissingSeq {
		writeUint24(header[21+i*3:24+i*3], seq)
	}

	block, err := aes.NewCipher(convKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, nil, header)
	res := make([]byte, len(header)+len(ciphertext))
	copy(res, header)
	copy(res[len(header):], ciphertext)
	return res, nil
}

func (c *Codec) DecodeNack(buf []byte) (*NackDart, error) {
	nack, err := ParseNack(buf)
	if err != nil {
		return nil, err
	}
	headerLen := nackPrefixLen(len(nack.MissingSeq))
	if len(buf) < headerLen+16 {
		return nil, errors.New("buffer too short")
	}
	header := buf[:headerLen]
	nonce := header[7:19]
	tag := buf[headerLen:]

	convKey, err := c.getConvKey(nack.ConvId)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(convKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if _, err := aesgcm.Open(nil, nonce, tag, header); err != nil {
		return nil, err
	}
	return nack, nil
}

func (c *Codec) EncodeSync(sync *SyncDart, nonce []byte) ([]byte, error) {
	convKey, err := c.getConvKey(sync.ConvId)
	if err != nil {
		return nil, err
	}

	// 17-byte cleartext header: type(1) | convId(2) | senderId(2) | nonce(12).
	if nonce == nil {
		nonce = make([]byte, 12)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}

	header := make([]byte, 17)
	header[0] = sync.Type
	binary.BigEndian.PutUint16(header[1:3], sync.ConvId)
	binary.BigEndian.PutUint16(header[3:5], sync.SenderId)
	copy(header[5:], nonce)

	payload := make([]byte, 3)
	writeUint24(payload[0:3], sync.HighestSeq)

	block, err := aes.NewCipher(convKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, payload, header)
	res := make([]byte, len(header)+len(ciphertext))
	copy(res, header)
	copy(res[len(header):], ciphertext)
	return res, nil
}

func (c *Codec) DecodeSync(buf []byte) (*SyncDart, error) {
	if len(buf) < 17 {
		return nil, errors.New("buffer too short")
	}
	typ := buf[0]
	convId := binary.BigEndian.Uint16(buf[1:3])
	senderId := binary.BigEndian.Uint16(buf[3:5])
	header := buf[:17]
	nonce := buf[5:17]
	encrypted := buf[17:]

	convKey, err := c.getConvKey(convId)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(convKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	payload, err := aesgcm.Open(nil, nonce, encrypted, header)
	if err != nil {
		return nil, err
	}
	if len(payload) < 3 {
		return nil, errors.New("invalid sync payload")
	}

	return &SyncDart{
		Type:       typ,
		ConvId:     convId,
		SenderId:   senderId,
		HighestSeq: readUint24(payload[0:3]),
	}, nil
}
