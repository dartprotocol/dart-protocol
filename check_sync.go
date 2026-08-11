package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

func writeUint24(b []byte, v uint32) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

func main() {
	convKey := bytes.Repeat([]byte{0x11}, 32)
	nonce := bytes.Repeat([]byte{0x33}, 12)

	// New 17-byte header: type(1) | convId(2) | senderId(2) | nonce(12).
	header := make([]byte, 17)
	header[0] = 0x03
	binary.BigEndian.PutUint16(header[1:3], 1)
	binary.BigEndian.PutUint16(header[3:5], 2)
	copy(header[5:], nonce)

	payload := make([]byte, 3)
	writeUint24(payload, 3)

	block, _ := aes.NewCipher(convKey)
	aesgcm, _ := cipher.NewGCM(block)

	ciphertext := aesgcm.Seal(nil, nonce, payload, header)
	res := append(header, ciphertext...)

	fmt.Printf("Go Sync: %x\n", res)
}
