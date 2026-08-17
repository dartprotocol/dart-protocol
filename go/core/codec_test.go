package core

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Fixed inputs matching the TS golden-vector generator (src/test vectors):
// nonce = 00..0b, reqNonce = 00..0f, group key 0x11*, message key 0x22*,
// transport key 0x33*, member pubkeys 0x04||0x01* / 0x04||0x02*.
var (
	testGroupKey    = bytes.Repeat([]byte{0x11}, 32)
	testMsgKey      = bytes.Repeat([]byte{0x22}, 32)
	testTransportKey = bytes.Repeat([]byte{0x33}, 32)
	testNonce       = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b}
	testReqNonce    = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	testPubA        = append([]byte{0x04}, bytes.Repeat([]byte{0x01}, 64)...)
	testPubB        = append([]byte{0x04}, bytes.Repeat([]byte{0x02}, 64)...)
	testServerPub   = append([]byte{0x04}, bytes.Repeat([]byte{0x03}, 64)...)
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func assertHex(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	w := mustHex(t, want)
	if !bytes.Equal(got, w) {
		t.Errorf("%s mismatch:\n got %x\nwant %s", name, got, want)
	}
}

func newTestCodec() *Codec {
	c := NewCodec()
	c.RoomKeys[1] = map[uint16][]byte{1: testGroupKey}
	c.ConvKeys[1] = testGroupKey
	c.CurrentEpochs[1] = 1
	return c
}

// --- Round-trips (encode with a fixed nonce, decode, compare) ---

func TestDataRoundTrip(t *testing.T) {
	c := newTestCodec()
	dart := &DataDart{Type: TypeData, ConvId: 1, SenderId: 7, Seq: 9, Payload: "hello dart"}
	buf, err := c.EncodeData(dart, nil, testMsgKey, 3, 1, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := c.DecryptData(buf, testMsgKey)
	if err != nil {
		t.Fatal(err)
	}
	if dec.ConvId != 1 || dec.SenderId != 7 || dec.Seq != 9 || dec.Idx != 3 || dec.Epoch != 1 {
		t.Errorf("decoded fields wrong: %+v", dec)
	}
	payload, err := InflateData(dec.Compressed, nil)
	if err != nil || string(payload) != "hello dart" {
		t.Errorf("payload = %q err = %v", payload, err)
	}
}

func TestDataExplicitEpochSurvivesCurrentEpochChange(t *testing.T) {
	c := newTestCodec()
	c.CurrentEpochs[1] = 2
	dart := &DataDart{Type: TypeData, ConvId: 1, SenderId: 7, Seq: 9, Payload: "old epoch"}
	buf, err := c.EncodeData(dart, nil, testMsgKey, 3, 1, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := c.DecryptData(buf, testMsgKey)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Epoch != 1 {
		t.Fatalf("explicit epoch was replaced by current epoch: got %d", dec.Epoch)
	}
}

func TestParseNackWithoutKey(t *testing.T) {
	c := newTestCodec()
	nack := &NackDart{Type: TypeNack, ConvId: 1, SenderId: 7, TargetId: 9, MissingSeq: []uint32{1, 2, 3}}
	buf, err := c.EncodeNack(nack, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	// A codec with no group key must still be able to read the gap list.
	blind, err := ParseNack(buf)
	if err != nil {
		t.Fatal(err)
	}
	if blind.SenderId != 7 || blind.TargetId != 9 || len(blind.MissingSeq) != 3 || blind.MissingSeq[2] != 3 {
		t.Errorf("parseNack wrong: %+v", blind)
	}
}

func TestNackRoundTrip(t *testing.T) {
	c := newTestCodec()
	nack := &NackDart{Type: TypeNack, ConvId: 1, SenderId: 7, TargetId: 9, MissingSeq: []uint32{1, 2, 3}}
	buf, err := c.EncodeNack(nack, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := c.DecodeNack(buf)
	if err != nil {
		t.Fatal(err)
	}
	if dec.SenderId != 7 || dec.TargetId != 9 || len(dec.MissingSeq) != 3 || dec.MissingSeq[2] != 3 {
		t.Errorf("decoded nack wrong: %+v", dec)
	}
}

func TestSyncRoundTrip(t *testing.T) {
	c := newTestCodec()
	sync := &SyncDart{Type: TypeSync, ConvId: 1, SenderId: 7, HighestSeq: 99}
	buf, err := c.EncodeSync(sync, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := c.DecodeSync(buf)
	if err != nil {
		t.Fatal(err)
	}
	if dec.SenderId != 7 || dec.HighestSeq != 99 {
		t.Errorf("decoded sync wrong: %+v", dec)
	}
}

func TestAckRoundTrip(t *testing.T) {
	c := newTestCodec()
	ack := &AckDart{Type: TypeAck, ConvId: 1, SenderId: 7, TargetId: 9, Seq: 12}
	buf, err := c.EncodeAck(ack, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := c.DecodeAck(buf)
	if err != nil {
		t.Fatal(err)
	}
	if dec.SenderId != 7 || dec.TargetId != 9 || dec.Seq != 12 {
		t.Errorf("decoded ack wrong: %+v", dec)
	}
}

func TestDictResetRoundTrip(t *testing.T) {
	c := newTestCodec()
	reset := &DictResetDart{Type: TypeDictReset, ConvId: 1, SenderId: 7, TargetId: 9}
	buf, err := c.EncodeDictReset(reset, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := c.DecodeDictReset(buf)
	if err != nil {
		t.Fatal(err)
	}
	if dec.SenderId != 7 || dec.TargetId != 9 {
		t.Errorf("decoded reset wrong: %+v", dec)
	}
}

func TestKeyReqRoundTrip(t *testing.T) {
	c := NewCodec()
	req := &KeyReqDart{Type: TypeKeyReq, ConvId: 1, SenderId: 7, ReqNonce: testReqNonce, ClientPubKey: testPubA}
	buf, err := c.EncodeKeyReq(req)
	dec, err := c.DecodeKeyReq(buf)
	if err != nil {
		t.Fatal(err)
	}
	if dec.SenderId != 7 || !bytes.Equal(dec.ReqNonce, testReqNonce) || !bytes.Equal(dec.ClientPubKey, testPubA) {
		t.Errorf("decoded keyreq wrong: %+v", dec)
	}
}

func TestKeyShareRoundTrip(t *testing.T) {
	c := NewCodec()
	share := &KeyShareDart{Type: TypeKeyShare, ConvId: 1, SenderId: 7, TargetId: 9, Epoch: 2, Nonce: testNonce, EncryptedKey: bytes.Repeat([]byte{0xBB}, 32)}
	buf, err := c.EncodeKeyShare(share, testTransportKey)
	if err != nil {
		t.Fatal(err)
	}
	epoch, key, err := c.DecodeKeyShare(buf, testTransportKey)
	if err != nil {
		t.Fatal(err)
	}
	if epoch != 2 || !bytes.Equal(key, bytes.Repeat([]byte{0xBB}, 32)) {
		t.Errorf("decoded keyshare wrong: epoch=%d key=%x", epoch, key)
	}
}

func TestChainShareRoundTrip(t *testing.T) {
	c := NewCodec()
	share := &ChainShareDart{Type: TypeChainShare, ConvId: 1, SenderId: 7, TargetId: 9, Epoch: 2, Nonce: testNonce, ChainKey: bytes.Repeat([]byte{0xCC}, 32), ChainIndex: 5}
	buf, err := c.EncodeChainShare(share, testTransportKey)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := c.DecodeChainShare(buf, testTransportKey)
	if err != nil {
		t.Fatal(err)
	}
	if dec.SenderId != 7 || dec.TargetId != 9 || dec.Epoch != 2 || dec.ChainIndex != 5 || !bytes.Equal(dec.ChainKey, bytes.Repeat([]byte{0xCC}, 32)) {
		t.Errorf("decoded chain share wrong: %+v", dec)
	}
}

func TestMemberInfoRoundTrip(t *testing.T) {
	c := NewCodec()
	info := &MemberInfo{
		Type: TypeMemberInfo, ConvId: 1, SenderId: 7, ServerPubKey: testServerPub, Creator: true,
		Members: []Member{{SenderId: 7, PubKey: testPubA}, {SenderId: 9, PubKey: testPubB}},
	}
	buf, err := c.EncodeMemberInfo(info, testTransportKey, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := c.DecodeMemberInfo(buf, testTransportKey)
	if err != nil {
		t.Fatal(err)
	}
	if dec.ConvId != 1 || dec.Creator != true || len(dec.Members) != 2 || dec.Members[1].SenderId != 9 {
		t.Errorf("decoded member info wrong: %+v", dec)
	}
	if fp := ServerFingerprint(testServerPub); len(fp) != 64 {
		t.Errorf("bad fingerprint %q", fp)
	}
}

// --- Cross-language golden wire vectors (generated by the TS reference) ---

func TestGoldenData(t *testing.T) {
	c := newTestCodec()
	// Decode compat: bytes produced by the TS reference decrypt + inflate to the
	// right payload. (The raw-deflate ENCODING differs per implementation, but
	// decompression is implementation-independent, so interop holds.)
	buf := mustHex(t, "010001000009180007000102030405060708090a0b0001e3b0c442000000038d885ad6727ac08d141c148997d24140046f48e9cd6bee431f1c2400")
	dec, err := c.DecryptData(buf, testMsgKey)
	if err != nil {
		t.Fatal(err)
	}
	if dec.ConvId != 1 || dec.SenderId != 7 || dec.Seq != 9 || dec.Idx != 3 || dec.Epoch != 1 {
		t.Errorf("decoded fields wrong: %+v", dec)
	}
	payload, err := InflateData(dec.Compressed, nil)
	if err != nil || string(payload) != "hello dart" {
		t.Errorf("golden data payload = %q err = %v", payload, err)
	}
}

func TestGoldenNack(t *testing.T) {
	c := newTestCodec()
	nack := &NackDart{Type: TypeNack, ConvId: 1, SenderId: 7, TargetId: 9, MissingSeq: []uint32{1, 2, 3}}
	buf, err := c.EncodeNack(nack, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "nack", buf, "02000100070009000102030405060708090a0b00030000010000020000036e3fdcea13a7d1a81d67e2a9149581c4")
	dec, err := c.DecodeNack(buf)
	if err != nil || dec.SenderId != 7 || len(dec.MissingSeq) != 3 {
		t.Errorf("golden nack decode wrong: %+v err=%v", dec, err)
	}
}

func TestGoldenSync(t *testing.T) {
	c := newTestCodec()
	sync := &SyncDart{Type: TypeSync, ConvId: 1, SenderId: 7, HighestSeq: 99}
	buf, err := c.EncodeSync(sync, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "sync", buf, "0300010007000102030405060708090a0b13e3d5bb7fdb1913e44d8c593cb1542f296d51")
	dec, err := c.DecodeSync(buf)
	if err != nil || dec.HighestSeq != 99 {
		t.Errorf("golden sync decode wrong: %+v err=%v", dec, err)
	}
}

func TestGoldenAck(t *testing.T) {
	c := newTestCodec()
	ack := &AckDart{Type: TypeAck, ConvId: 1, SenderId: 7, TargetId: 9, Seq: 12}
	buf, err := c.EncodeAck(ack, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "ack", buf, "0700010007000900000c000102030405060708090a0b0fb7689169b3345bda3ae1045175b099")
}

func TestGoldenDictReset(t *testing.T) {
	c := newTestCodec()
	reset := &DictResetDart{Type: TypeDictReset, ConvId: 1, SenderId: 7, TargetId: 9}
	buf, err := c.EncodeDictReset(reset, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "dictReset", buf, "06000100070009000102030405060708090a0bdb933a8972efd7d1cacd06a9bf4bc2d8")
}

func TestGoldenKeyReq(t *testing.T) {
	req := &KeyReqDart{Type: TypeKeyReq, ConvId: 1, SenderId: 7, ReqNonce: testReqNonce, ClientPubKey: testPubA}
	buf, _ := NewCodec().EncodeKeyReq(req)
	assertHex(t, "keyReq", buf, "0400010007000102030405060708090a0b0c0d0e0f0401010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101")
}

func TestGoldenKeyShare(t *testing.T) {
	c := NewCodec()
	share := &KeyShareDart{Type: TypeKeyShare, ConvId: 1, SenderId: 7, TargetId: 9, Epoch: 2, Nonce: testNonce, EncryptedKey: bytes.Repeat([]byte{0xBB}, 32)}
	buf, err := c.EncodeKeyShare(share, testTransportKey)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "keyShare", buf, "080001000700090002000102030405060708090a0ba31cb58150dbb540a0b545dfffd009276cf071ff3e94649889b646f34315fb543dbfbdd04e3baad9e9c1810dda634d79")
}

func TestGoldenChainShare(t *testing.T) {
	c := NewCodec()
	share := &ChainShareDart{Type: TypeChainShare, ConvId: 1, SenderId: 7, TargetId: 9, Epoch: 2, Nonce: testNonce, ChainKey: bytes.Repeat([]byte{0xCC}, 32), ChainIndex: 5}
	buf, err := c.EncodeChainShare(share, testTransportKey)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "chainShare", buf, "0a0001000700090002000102030405060708090a0bd46bc2f627acc237d7c232a888a77e501b87068849e313effec1318434628c23e2b4c62dab2e8efe054b548df0acafe21afb1498")
}

func TestGoldenMemberInfo(t *testing.T) {
	c := NewCodec()
	info := &MemberInfo{
		Type: TypeMemberInfo, ConvId: 1, SenderId: 7, ServerPubKey: testServerPub, Creator: true,
		Members: []Member{{SenderId: 7, PubKey: testPubA}, {SenderId: 9, PubKey: testPubB}},
	}
	buf, err := c.EncodeMemberInfo(info, testTransportKey, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "memberInfo", buf, "09000100070403030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303000102030405060708090a0b19a70c3aec640ffa1a0fff65456ab39dd64acb45842ede22330cfc49f9af41eee3b5c729051ea802c02ae8667a8c11890320ab4b93afb203a980e77d49e2448ad66521f98c5011290b33bd659c289254ac2d969150609df3e08f699eba5b9b82cc1eafbf1836fc188a521e967fe33cf64bf96a1fbc554a1949ebb842c194a331bcbf673bf6349e1ad08a6f949d74a5dedb3598f1352d2d2fc4")
}

// --- Deterministic ratchet-chain vectors (cross-language) ---

func TestChainGoldenVectors(t *testing.T) {
	seed := bytes.Repeat([]byte{0x44}, 32)
	assertHex(t, "chainMsgKey0", ChainMessageKey(seed, 0), "e4b4d1bdd01191ce786b8f5efe2202757d94378135ad772bb9e01ed22d8ce688")
	assertHex(t, "chainNext0", ChainNextKey(seed), "4f174eacd84d526c6e0ebd801d14be1a17b4b87d740f1d9518349204546d5e38")
	assertHex(t, "chainMsgKey1", ChainMessageKey(ChainNextKey(seed), 1), "44714fbdde4e6e726f97c386f8eb631ff12959963e732f878122ef5d6d1d8dac")
	msgKey, _ := AdvanceChain(ChainState{Key: seed, Index: 0}, 2)
	assertHex(t, "advance", msgKey, "1ded480040e14f6fba5be12a1666a3542dec36f01629c21411b9d5f80bce05a0")
}

func TestChainProperties(t *testing.T) {
	seed := bytes.Repeat([]byte{0x44}, 32)
	m0, s1 := AdvanceChain(ChainState{Key: seed, Index: 0}, 0)
	m1, s2 := AdvanceChain(s1, 1)
	m2, _ := AdvanceChain(s2, 2)
	// Distinct per-message keys.
	if bytes.Equal(m0, m1) || bytes.Equal(m1, m2) || bytes.Equal(m0, m2) {
		t.Error("message keys are not distinct")
	}
	// One-way: the ratcheted chain key differs from the seed.
	if bytes.Equal(s2.Key, seed) {
		t.Error("chain did not ratchet")
	}
	// Gap tolerance: skipping to index 3 gives the same key as processing in order.
	skipped, _ := AdvanceChain(s1, 3)
	sequential, _ := AdvanceChain(s2, 3)
	if !bytes.Equal(skipped, sequential) {
		t.Error("gap derivation not consistent")
	}
}
