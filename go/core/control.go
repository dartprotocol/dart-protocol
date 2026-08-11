package core

import (
	"crypto/hmac"
	"crypto/sha256"
)

// CtrlMacLen is the length of the per-sender HMAC appended to control frames.
const CtrlMacLen = 32

// PairwiseKey derives the per-sender MAC key shared between a private key and
// a peer's public key: SHA-256(ECDH(priv, peerPub)). Both sides compute the
// same value from their own private key, so a third member cannot derive it
// and cannot forge the other member's control frames.
func PairwiseKey(priv *ECDH, peerPubKey []byte) ([]byte, error) {
	secret, err := priv.ComputeSecret(peerPubKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(secret)
	return sum[:], nil
}

// SignControlFrame appends HMAC-SHA256(key, frame) to a control frame.
func SignControlFrame(frame, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(frame)
	out := make([]byte, len(frame)+CtrlMacLen)
	copy(out, frame)
	copy(out[len(frame):], mac.Sum(nil))
	return out
}

// VerifyControlFrame verifies and strips the trailing HMAC. Returns the
// stripped frame and true on success.
func VerifyControlFrame(frame, key []byte) ([]byte, bool) {
	if len(frame) < CtrlMacLen {
		return nil, false
	}
	payload := frame[:len(frame)-CtrlMacLen]
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), frame[len(frame)-CtrlMacLen:]) {
		return nil, false
	}
	return payload, true
}

// StripControlFrame removes the trailing HMAC without verifying. Used by the
// relay server (which cannot derive member-to-member keys) and by members
// trusting server-verified SYNC / Dict-Reset frames.
func StripControlFrame(frame []byte) ([]byte, bool) {
	if len(frame) < CtrlMacLen {
		return nil, false
	}
	return frame[:len(frame)-CtrlMacLen], true
}
