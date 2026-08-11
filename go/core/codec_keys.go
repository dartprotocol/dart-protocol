package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

// ServerFingerprint is the SHA-256 hex fingerprint of the server's static ECDH
// public key. Clients pin this value to authenticate the server (SSH-style
// host-key verification), so an active MITM can't substitute its own key.
func ServerFingerprint(serverPubKey []byte) string {
	sum := sha256.Sum256(serverPubKey)
	return hex.EncodeToString(sum[:])
}

func (c *Codec) EncodeKeyReq(req *KeyReqDart) ([]byte, error) {
	header := make([]byte, 5)
	header[0] = req.Type
	binary.BigEndian.PutUint16(header[1:3], req.ConvId)
	binary.BigEndian.PutUint16(header[3:5], req.SenderId)
	res := append(header, req.ReqNonce...)
	res = append(res, req.ClientPubKey...)
	return res, nil
}

func (c *Codec) DecodeKeyReq(buf []byte) (*KeyReqDart, error) {
	if len(buf) < 21 {
		return nil, errors.New("buffer too short")
	}
	return &KeyReqDart{
		Type:         buf[0],
		ConvId:       binary.BigEndian.Uint16(buf[1:3]),
		SenderId:     binary.BigEndian.Uint16(buf[3:5]),
		ReqNonce:     buf[5:21],
		ClientPubKey: buf[21:],
	}, nil
}

// KeyShareAAD binds a group-key share to the target member.
func KeyShareAAD(share *KeyShareDart) []byte {
	aad := make([]byte, 21)
	aad[0] = share.Type
	binary.BigEndian.PutUint16(aad[1:3], share.ConvId)
	binary.BigEndian.PutUint16(aad[3:5], share.SenderId)
	binary.BigEndian.PutUint16(aad[5:7], share.TargetId)
	binary.BigEndian.PutUint16(aad[7:9], share.Epoch)
	copy(aad[9:], share.Nonce)
	return aad
}

func (c *Codec) EncodeKeyShare(share *KeyShareDart, transportKey []byte) ([]byte, error) {
	header := KeyShareAAD(share)
	block, err := aes.NewCipher(transportKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, share.Nonce, share.EncryptedKey, header)
	res := make([]byte, len(header)+len(ciphertext))
	copy(res, header)
	copy(res[len(header):], ciphertext)
	return res, nil
}

func (c *Codec) DecodeKeyShare(buf []byte, transportKey []byte) (uint16, []byte, error) {
	if len(buf) < 21+48 {
		return 0, nil, errors.New("buffer too short")
	}
	epoch := binary.BigEndian.Uint16(buf[7:9])
	header := buf[:21]
	nonce := buf[9:21]
	encryptedWithTag := buf[21:]

	block, err := aes.NewCipher(transportKey)
	if err != nil {
		return 0, nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, nil, err
	}
	groupKey, err := aesgcm.Open(nil, nonce, encryptedWithTag, header)
	if err != nil {
		return 0, nil, err
	}
	return epoch, groupKey, nil
}

// MemberInfoServerKey returns the server public key embedded in a MEMBER_INFO
// packet, so a client can verify the pin before deriving the transport key.
func MemberInfoServerKey(buf []byte) ([]byte, error) {
	if len(buf) < 70 {
		return nil, errors.New("buffer too short")
	}
	return buf[5:70], nil
}

func (c *Codec) EncodeMemberInfo(info *MemberInfo, transportKey []byte, nonce []byte) ([]byte, error) {
	header := make([]byte, 5)
	header[0] = info.Type
	binary.BigEndian.PutUint16(header[1:3], info.ConvId)
	binary.BigEndian.PutUint16(header[3:5], info.SenderId)

	if nonce == nil {
		nonce = make([]byte, 12)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}

	creatorFlag := byte(0)
	if info.Creator {
		creatorFlag = 1
	}
	payload := make([]byte, 3+len(info.Members)*67)
	payload[0] = creatorFlag
	binary.BigEndian.PutUint16(payload[1:3], uint16(len(info.Members)))
	offset := 3
	for _, m := range info.Members {
		binary.BigEndian.PutUint16(payload[offset:offset+2], m.SenderId)
		copy(payload[offset+2:offset+67], m.PubKey)
		offset += 67
	}

	aad := make([]byte, 0, len(header)+65+len(nonce))
	aad = append(aad, header...)
	aad = append(aad, info.ServerPubKey...)
	aad = append(aad, nonce...)

	block, err := aes.NewCipher(transportKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, payload, aad)

	res := make([]byte, 0, len(aad)+len(ciphertext))
	res = append(res, aad...)
	res = append(res, ciphertext...)
	return res, nil
}

func (c *Codec) DecodeMemberInfo(buf []byte, transportKey []byte) (*MemberInfo, error) {
	if len(buf) < 5+65+12+16 {
		return nil, errors.New("buffer too short")
	}
	typ := buf[0]
	convId := binary.BigEndian.Uint16(buf[1:3])
	senderId := binary.BigEndian.Uint16(buf[3:5])
	serverPubKey := buf[5:70]
	nonce := buf[70:82]
	encrypted := buf[82:]
	header := buf[:5]

	aad := make([]byte, 0, len(header)+65+len(nonce))
	aad = append(aad, header...)
	aad = append(aad, serverPubKey...)
	aad = append(aad, nonce...)

	block, err := aes.NewCipher(transportKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	payload, err := aesgcm.Open(nil, nonce, encrypted, aad)
	if err != nil {
		return nil, err
	}

	creator := payload[0] == 1
	count := int(binary.BigEndian.Uint16(payload[1:3]))
	members := make([]Member, 0, count)
	offset := 3
	for i := 0; i < count; i++ {
		if len(payload) < offset+67 {
			break
		}
		m := Member{
			SenderId: binary.BigEndian.Uint16(payload[offset : offset+2]),
			PubKey:   append([]byte(nil), payload[offset+2:offset+67]...),
		}
		members = append(members, m)
		offset += 67
	}

	return &MemberInfo{
		Type:         typ,
		ConvId:       convId,
		SenderId:     senderId,
		ServerPubKey: append([]byte(nil), serverPubKey...),
		Creator:      creator,
		Members:      members,
	}, nil
}

func (c *Codec) EncodeDictReset(reset *DictResetDart, nonce []byte) ([]byte, error) {
	convKey, err := c.getConvKey(reset.ConvId)
	if err != nil {
		return nil, err
	}

	// 19-byte cleartext header: type(1) | convId(2) | senderId(2) | targetId(2)
	// | nonce(12). The whole header is the AEAD AAD, so an outsider can't forge a reset.
	if nonce == nil {
		nonce = make([]byte, 12)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}

	header := make([]byte, 19)
	header[0] = reset.Type
	binary.BigEndian.PutUint16(header[1:3], reset.ConvId)
	binary.BigEndian.PutUint16(header[3:5], reset.SenderId)
	binary.BigEndian.PutUint16(header[5:7], reset.TargetId)
	copy(header[7:], nonce)

	block, err := aes.NewCipher(convKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	tag := aesgcm.Seal(nil, nonce, nil, header)
	res := make([]byte, len(header)+len(tag))
	copy(res, header)
	copy(res[len(header):], tag)
	return res, nil
}

func (c *Codec) DecodeDictReset(buf []byte) (*DictResetDart, error) {
	if len(buf) < 19 {
		return nil, errors.New("buffer too short")
	}
	typ := buf[0]
	convId := binary.BigEndian.Uint16(buf[1:3])
	senderId := binary.BigEndian.Uint16(buf[3:5])
	targetId := binary.BigEndian.Uint16(buf[5:7])
	header := buf[:19]
	nonce := buf[7:19]
	tag := buf[19:]

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

	if _, err := aesgcm.Open(nil, nonce, tag, header); err != nil {
		return nil, err
	}

	return &DictResetDart{
		Type:     typ,
		ConvId:   convId,
		SenderId: senderId,
		TargetId: targetId,
	}, nil
}

func (c *Codec) EncodeAck(ack *AckDart, nonce []byte) ([]byte, error) {
	convKey, err := c.getConvKey(ack.ConvId)
	if err != nil {
		return nil, err
	}

	// 22-byte cleartext header: type(1) | convId(2) | senderId(2) | targetId(2)
	// | seq(3) | nonce(12). The whole header is the AEAD AAD, so an outsider
	// can't forge a delivery confirmation.
	if nonce == nil {
		nonce = make([]byte, 12)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}

	header := make([]byte, 22)
	header[0] = ack.Type
	binary.BigEndian.PutUint16(header[1:3], ack.ConvId)
	binary.BigEndian.PutUint16(header[3:5], ack.SenderId)
	binary.BigEndian.PutUint16(header[5:7], ack.TargetId)
	writeUint24(header[7:10], ack.Seq)
	copy(header[10:], nonce)

	block, err := aes.NewCipher(convKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	tag := aesgcm.Seal(nil, nonce, nil, header)
	res := make([]byte, len(header)+len(tag))
	copy(res, header)
	copy(res[len(header):], tag)
	return res, nil
}

func (c *Codec) DecodeAck(buf []byte) (*AckDart, error) {
	if len(buf) < 22 {
		return nil, errors.New("buffer too short")
	}
	typ := buf[0]
	convId := binary.BigEndian.Uint16(buf[1:3])
	senderId := binary.BigEndian.Uint16(buf[3:5])
	targetId := binary.BigEndian.Uint16(buf[5:7])
	seq := readUint24(buf[7:10])
	header := buf[:22]
	nonce := buf[10:22]
	tag := buf[22:]

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

	if _, err := aesgcm.Open(nil, nonce, tag, header); err != nil {
		return nil, err
	}

	return &AckDart{
		Type:     typ,
		ConvId:   convId,
		SenderId: senderId,
		TargetId: targetId,
		Seq:      seq,
	}, nil
}
