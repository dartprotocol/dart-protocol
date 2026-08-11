package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

func (c *Codec) EncodeNack(nack *NackDart, nonce []byte) ([]byte, error) {
	convKey, err := c.getConvKey(nack.ConvId)
	if err != nil {
		return nil, err
	}

	// 19-byte cleartext header: type(1) | convId(2) | senderId(2) | targetId(2)
	// | nonce(12). senderId is the member who detected the gap (the signer);
	// targetId is the member whose stream has the gap.
	if nonce == nil {
		nonce = make([]byte, 12)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}

	header := make([]byte, 19)
	header[0] = nack.Type
	binary.BigEndian.PutUint16(header[1:3], nack.ConvId)
	binary.BigEndian.PutUint16(header[3:5], nack.SenderId)
	binary.BigEndian.PutUint16(header[5:7], nack.TargetId)
	copy(header[7:], nonce)

	payload := make([]byte, 2+len(nack.MissingSeq)*3)
	binary.BigEndian.PutUint16(payload[0:2], uint16(len(nack.MissingSeq)))
	offset := 2
	for _, seq := range nack.MissingSeq {
		writeUint24(payload[offset:offset+3], seq)
		offset += 3
	}

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

func (c *Codec) DecodeNack(buf []byte) (*NackDart, error) {
	if len(buf) < 19 {
		return nil, errors.New("buffer too short")
	}
	typ := buf[0]
	convId := binary.BigEndian.Uint16(buf[1:3])
	senderId := binary.BigEndian.Uint16(buf[3:5])
	targetId := binary.BigEndian.Uint16(buf[5:7])
	header := buf[:19]
	nonce := buf[7:19]
	encrypted := buf[19:]

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

	if len(payload) < 2 {
		return nil, errors.New("invalid nack payload")
	}
	count := binary.BigEndian.Uint16(payload[0:2])
	var seqs []uint32
	offset := 2
	for i := 0; i < int(count); i++ {
		if len(payload) < offset+3 {
			break
		}
		seqs = append(seqs, readUint24(payload[offset:offset+3]))
		offset += 3
	}

	return &NackDart{
		Type:       typ,
		ConvId:     convId,
		SenderId:   senderId,
		TargetId:   targetId,
		MissingSeq: seqs,
	}, nil
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
