package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// TypeChainShare is the member->member per-sender ratchet-chain delivery frame.
const TypeChainShare uint8 = 0x0A

// ChainState is a sender's per-message ratchet chain. Key is the chain key for
// the NEXT message (at Index); each message consumes it and advances the chain.
type ChainState struct {
	Key   []byte
	Index uint32
}

// ChainShareDart carries a sender's current chain state to a target member,
// ECDH-encrypted like a KeyShare.
type ChainShareDart struct {
	Type       uint8
	ConvId     uint16
	SenderId   uint16
	TargetId   uint16
	Epoch      uint16
	Nonce      []byte
	ChainKey   []byte
	ChainIndex uint32
}

// ChainMessageKey derives the per-message key for a chain key at an index.
func ChainMessageKey(chainKey []byte, index uint32) []byte {
	mac := hmac.New(sha256.New, chainKey)
	mac.Write([]byte("DartMsgKey"))
	idxBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(idxBuf, index)
	mac.Write(idxBuf)
	return mac.Sum(nil)
}

// ChainNextKey is the chain key that follows chainKey after one message.
func ChainNextKey(chainKey []byte) []byte {
	mac := hmac.New(sha256.New, chainKey)
	mac.Write([]byte("DartChainKey"))
	return mac.Sum(nil)
}

// AdvanceChain advances a chain state to targetIndex (skipping lost messages)
// and consumes the message key at targetIndex. Returns the message key and the
// advanced state (whose Index is targetIndex + 1).
func AdvanceChain(state ChainState, targetIndex uint32) ([]byte, ChainState) {
	key := append([]byte(nil), state.Key...)
	index := state.Index
	for index < targetIndex {
		key = ChainNextKey(key)
		index++
	}
	messageKey := ChainMessageKey(key, index)
	return messageKey, ChainState{Key: ChainNextKey(key), Index: index + 1}
}

func (c *Codec) EncodeChainShare(share *ChainShareDart, transportKey []byte) ([]byte, error) {
	header := make([]byte, 21)
	header[0] = share.Type
	binary.BigEndian.PutUint16(header[1:3], share.ConvId)
	binary.BigEndian.PutUint16(header[3:5], share.SenderId)
	binary.BigEndian.PutUint16(header[5:7], share.TargetId)
	binary.BigEndian.PutUint16(header[7:9], share.Epoch)
	copy(header[9:], share.Nonce)

	payload := make([]byte, 36)
	copy(payload[0:32], share.ChainKey)
	binary.BigEndian.PutUint32(payload[32:36], share.ChainIndex)

	block, err := aes.NewCipher(transportKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	encrypted := aesgcm.Seal(nil, share.Nonce, payload, header)
	res := make([]byte, len(header)+len(encrypted))
	copy(res, header)
	copy(res[len(header):], encrypted)
	return res, nil
}

func (c *Codec) DecodeChainShare(buf []byte, transportKey []byte) (*ChainShareDart, error) {
	if len(buf) < 21+36+16 {
		return nil, errors.New("buffer too short")
	}
	typ := buf[0]
	convId := binary.BigEndian.Uint16(buf[1:3])
	senderId := binary.BigEndian.Uint16(buf[3:5])
	targetId := binary.BigEndian.Uint16(buf[5:7])
	epoch := binary.BigEndian.Uint16(buf[7:9])
	header := buf[:21]
	nonce := buf[9:21]
	encryptedWithTag := buf[21:]

	block, err := aes.NewCipher(transportKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	payload, err := aesgcm.Open(nil, nonce, encryptedWithTag, header)
	if err != nil {
		return nil, err
	}
	if len(payload) < 36 {
		return nil, errors.New("invalid chain share payload")
	}

	return &ChainShareDart{
		Type:       typ,
		ConvId:     convId,
		SenderId:   senderId,
		TargetId:   targetId,
		Epoch:      epoch,
		Nonce:      append([]byte(nil), nonce...),
		ChainKey:   append([]byte(nil), payload[0:32]...),
		ChainIndex: binary.BigEndian.Uint32(payload[32:36]),
	}, nil
}
