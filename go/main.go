package main

import (
	"bufio"
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"dartgo/core"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Cached per-message key + chain index for a sent message (retransmission).
type messageKeyEntry struct {
	key []byte
	idx uint32
}

type NativeDartClient struct {
	conn       *net.UDPConn
	senderId   uint16
	roomId     uint16
	codec      *core.Codec
	ecdh       *core.ECDH
	serverAddr *net.UDPAddr

	serverFingerprint string

	// Server public key per conversation (from MEMBER_INFO), used to key the
	// server-verified SYNC / Dict-Reset frames.
	serverPubKeys map[uint16][]byte

	// Per-sender ratchet chains: convId -> epoch -> senderId -> chain state.
	senderChains    map[uint16]map[uint16]map[uint16]core.ChainState
	chainSharedWith map[uint16]map[uint16]bool
	messageKeys     map[uint32]messageKeyEntry
	chainSeeds      map[uint16]map[uint16]core.ChainState // convId -> epoch -> index-0 chain state

	tcpConn     net.Conn
	useFallback bool

	// E2EE group-key management
	roster     map[uint16]map[uint16][]byte // convId -> senderId -> pubkey
	sharedWith map[uint16]map[uint16]bool   // convId -> members we shared the current key with
	isCreator  map[uint16]bool
	rekeyTimer *time.Timer

	nextSeq         uint32
	highestSentSeq  uint32
	highestReceived map[uint16]uint32
	sentMessages    map[uint32]*core.DataDart
	
	// senderId -> seq -> dart
	receivedMessages map[uint16]map[uint32]*core.DataDart

	syncTimers []*time.Timer
	ackedSeq   map[uint16]uint32
	ackTimers  map[uint16]*time.Timer

	outOfOrderBuffer map[uint16]map[uint32][]byte
	nackTimestamps   map[uint16]map[uint32]time.Time

	pendingQueue []string
	lastSendTime time.Time

	mu sync.Mutex
}

func NewNativeDartClient(serverIP string, port int) (*NativeDartClient, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", serverIP, port))
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}

	ecdh, err := core.NewECDH()
	if err != nil {
		return nil, err
	}

	rand.Seed(time.Now().UnixNano())
	
	return &NativeDartClient{
		conn:             conn,
		senderId:         uint16(rand.Intn(65535)),
		codec:            core.NewCodec(),
		ecdh:             ecdh,
		serverAddr:       addr,
		nextSeq:          1,
		highestReceived:  make(map[uint16]uint32),
		sentMessages:     make(map[uint32]*core.DataDart),
		receivedMessages: make(map[uint16]map[uint32]*core.DataDart),
		ackTimers:        make(map[uint16]*time.Timer),
		outOfOrderBuffer: make(map[uint16]map[uint32][]byte),
		nackTimestamps:   make(map[uint16]map[uint32]time.Time),
		serverFingerprint: strings.ToLower(strings.TrimSpace(os.Getenv("DART_SERVER_FINGERPRINT"))),
		roster:           make(map[uint16]map[uint16][]byte),
		sharedWith:       make(map[uint16]map[uint16]bool),
		isCreator:        make(map[uint16]bool),
		serverPubKeys:    make(map[uint16][]byte),
		senderChains:    make(map[uint16]map[uint16]map[uint16]core.ChainState),
		chainSharedWith: make(map[uint16]map[uint16]bool),
		messageKeys:     make(map[uint32]messageKeyEntry),
		ackedSeq:        make(map[uint16]uint32),
		chainSeeds:      make(map[uint16]map[uint16]core.ChainState),
	}, nil
}

// send routes a packet over TCP fallback (if enabled) or UDP, using the same
// 2-byte big-endian length framing as the Node server.
func (c *NativeDartClient) send(buf []byte) {
	if c.useFallback && c.tcpConn != nil {
		out := make([]byte, 2+len(buf))
		binary.BigEndian.PutUint16(out[0:2], uint16(len(buf)))
		copy(out[2:], buf)
		c.tcpConn.Write(out)
	} else {
		c.conn.Write(buf)
	}
}

func (c *NativeDartClient) enableFallback(host string, port int) error {
	if c.useFallback {
		return nil
	}
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return err
	}
	c.tcpConn = conn
	c.useFallback = true
	fmt.Printf("[SYSTEM] Connected to TCP fallback at %s:%d\n", host, port)
	go func() {
		buf := make([]byte, 0)
		tmp := make([]byte, 4096)
		for {
			n, err := conn.Read(tmp)
			if err != nil {
				return
			}
			buf = append(buf, tmp[:n]...)
			for len(buf) >= 2 {
				l := int(binary.BigEndian.Uint16(buf[0:2]))
				if l == 0 || len(buf) < 2+l {
					break
				}
				payload := append([]byte(nil), buf[2:2+l]...)
				buf = buf[2+l:]
				c.handleMessage(payload)
			}
		}
	}()
	return nil
}

func (c *NativeDartClient) getDictionary(senderId uint16, maxSeq uint32) []byte {
	// Delta-compress against a bounded window of the SAME sender's history so
	// both sides always build identical dictionaries (and older history can
	// be pruned). The window is selected in the modular 24-bit space so it
	// stays correct across a sequence-number wrap.
	var msgsToConcat []*core.DataDart

	if senderId == c.senderId {
		for seq, dart := range c.sentMessages {
			dist := core.SeqDelta(seq, maxSeq)
			if dist >= 1 && dist <= core.DictWindow {
				msgsToConcat = append(msgsToConcat, dart)
			}
		}
	} else {
		if msgs, ok := c.receivedMessages[senderId]; ok {
			for seq, dart := range msgs {
				dist := core.SeqDelta(seq, maxSeq)
				if dist >= 1 && dist <= core.DictWindow {
					msgsToConcat = append(msgsToConcat, dart)
				}
			}
		}
	}

	// Oldest-first (largest distance behind maxSeq) so all implementations
	// build byte-identical dictionaries across a wrap.
	sort.Slice(msgsToConcat, func(i, j int) bool {
		return core.SeqDelta(msgsToConcat[i].Seq, maxSeq) > core.SeqDelta(msgsToConcat[j].Seq, maxSeq)
	})

	var buf bytes.Buffer
	for _, dart := range msgsToConcat {
		buf.WriteString(dart.Payload)
	}
	return buf.Bytes()
}

// pruneSent bounds memory by dropping sent history older than the dictionary
// window (+ slack), so the compression dictionary stays small.
func (c *NativeDartClient) pruneSent() {
	for seq := range c.sentMessages {
		if core.SeqDelta(seq, c.highestSentSeq) > core.DictWindow+16 {
			delete(c.sentMessages, seq)
			delete(c.messageKeys, seq)
		}
	}
}

func (c *NativeDartClient) pruneReceived(senderId uint16) {
	highest := c.highestReceived[senderId]
	if msgs, ok := c.receivedMessages[senderId]; ok {
		for seq := range msgs {
			if core.SeqDelta(seq, highest) > core.DictWindow+16 {
				delete(msgs, seq)
			}
		}
	}
	if ts, ok := c.nackTimestamps[senderId]; ok {
		for seq := range ts {
			if core.SeqDelta(seq, highest) > core.DictWindow+16 {
				delete(ts, seq)
			}
		}
	}
}

func (c *NativeDartClient) clearSyncTimers() {
	for _, t := range c.syncTimers {
		t.Stop()
	}
	c.syncTimers = nil
}

func (c *NativeDartClient) SendData(roomId uint16, payload string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if now.Sub(c.lastSendTime) < 250*time.Millisecond {
		fmt.Println("[SYSTEM] Rate limit: Sending too fast. Message dropped.")
		return
	}
	c.lastSendTime = now

	if _, ok := c.codec.ConvKeys[roomId]; !ok {
		c.pendingQueue = append(c.pendingQueue, payload)
		return
	}

	epoch := c.codec.CurrentEpochs[roomId]
	if epoch == 0 {
		epoch = 1
	}
	myChain, ok := c.getChain(roomId, epoch, c.senderId)
	if !ok {
		c.pendingQueue = append(c.pendingQueue, payload)
		return
	}
	idx := myChain.Index
	messageKey, state := core.AdvanceChain(myChain, idx)
	c.setChain(roomId, epoch, c.senderId, state)

	seq := c.nextSeq
	c.nextSeq = core.SeqNext(c.nextSeq)
	
	dart := &core.DataDart{
		Type:     core.TypeData,
		ConvId:   roomId,
		SenderId: c.senderId,
		Seq:      seq,
		Payload:  payload,
	}
	c.sentMessages[seq] = dart
	c.messageKeys[seq] = messageKeyEntry{key: messageKey, idx: idx}
	c.highestSentSeq = seq
	c.pruneSent()

	dict := c.getDictionary(c.senderId, seq)
	buf, err := c.codec.EncodeData(dart, dict, messageKey, idx, nil)
	if err == nil {
		c.send(buf)
	}

	fmt.Printf("\x1b[90m[↑] Sending Seq %d...\x1b[0m\r", seq)

	c.clearSyncTimers()
	c.syncProbe(roomId)
}

// Re-arming sync probe: while the most recent message stays unacknowledged,
// keep probing so SYNC-driven NACK repair retries under loss instead of
// stalling until the next rekey.
func (c *NativeDartClient) syncProbe(convId uint16) {
	c.syncTimers = append(c.syncTimers, time.AfterFunc(300*time.Millisecond, func() {
		c.sendSync(convId)
		if core.SeqDelta(c.highestSentSeq, c.ackedSeq[convId]) >= core.SeqMod/2 {
			c.syncProbe(convId)
		}
	}))
}

func (c *NativeDartClient) sendSync(convId uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if c.highestSentSeq == 0 {
		return
	}
	sync := &core.SyncDart{
		Type:       core.TypeSync,
		ConvId:     convId,
		SenderId:   c.senderId,
		HighestSeq: c.highestSentSeq,
	}
	buf, _ := c.codec.EncodeSync(sync, nil)
	serverPub := c.serverPubKeys[convId]
	if serverPub == nil {
		return
	}
	if key, err := core.PairwiseKey(c.ecdh, serverPub); err == nil {
		c.send(core.SignControlFrame(buf, key))
	}
}

func (c *NativeDartClient) sendNack(convId uint16, targetId uint16, missing []uint32) {
	nack := &core.NackDart{
		Type:       core.TypeNack,
		ConvId:     convId,
		SenderId:   c.senderId,
		TargetId:   targetId,
		MissingSeq: missing,
	}
	buf, _ := c.codec.EncodeNack(nack, nil)
	peerPub := c.roster[convId][targetId]
	if peerPub == nil {
		return
	}
	if key, err := core.PairwiseKey(c.ecdh, peerPub); err == nil {
		c.send(core.SignControlFrame(buf, key))
	}
}

func (c *NativeDartClient) sendAck(convId uint16, targetId uint16, seq uint32) {
	ack := &core.AckDart{
		Type:     core.TypeAck,
		ConvId:   convId,
		SenderId: c.senderId,
		TargetId: targetId,
		Seq:      seq,
	}
	buf, _ := c.codec.EncodeAck(ack, nil)
	peerPub := c.roster[convId][targetId]
	if peerPub == nil {
		return
	}
	if key, err := core.PairwiseKey(c.ecdh, peerPub); err == nil {
		c.send(core.SignControlFrame(buf, key))
	}
}

func (c *NativeDartClient) sendDictReset(convId uint16, targetId uint16) {
	reset := &core.DictResetDart{
		Type:     core.TypeDictReset,
		ConvId:   convId,
		SenderId: c.senderId,
		TargetId: targetId,
	}
	buf, _ := c.codec.EncodeDictReset(reset, nil)
	serverPub := c.serverPubKeys[convId]
	if serverPub == nil {
		return
	}
	if key, err := core.PairwiseKey(c.ecdh, serverPub); err == nil {
		c.send(core.SignControlFrame(buf, key))
	}
}

func (c *NativeDartClient) JoinRoom(roomId uint16) {
	c.mu.Lock()
	c.roomId = roomId
	reqNonce := make([]byte, 16)
	cryptorand.Read(reqNonce)
	req := &core.KeyReqDart{
		Type:         core.TypeKeyReq,
		ConvId:       roomId,
		SenderId:     c.senderId,
		ReqNonce:     reqNonce,
		ClientPubKey: c.ecdh.GetPublicKey(),
	}
	buf, _ := c.codec.EncodeKeyReq(req)
	c.send(buf)
	c.mu.Unlock()

	// Retry: each KeyReq makes the server re-notify the roster, which is how
	// members refresh stale pubkeys (MEMBER_INFO has no other retry). Without
	// this, a member that lost the roster update can never verify another
	// member's NACKs or decode their shares again.
	for _, delay := range []time.Duration{1000, 2000, 3000} {
		delay := delay
		time.AfterFunc(delay*time.Millisecond, func() {
			rn := make([]byte, 16)
			cryptorand.Read(rn)
			retryReq := *req
			retryReq.ReqNonce = rn
			c.mu.Lock()
			out, _ := c.codec.EncodeKeyReq(&retryReq)
			c.send(out)
			c.mu.Unlock()
		})
	}

	fmt.Printf("\x1b[36m[SYSTEM] Joining room %d (My ID: %d)...\x1b[0m\n", roomId, c.senderId)
	fmt.Printf("\x1b[36m[SYSTEM] Performing ECDH Key Exchange...\x1b[0m\n")
}

// ---- E2EE group-key management (caller holds c.mu) ----
func (c *NativeDartClient) adoptKey(convId uint16, epoch uint16, key []byte) {
	_, hadKey := c.codec.ConvKeys[convId]
	if c.codec.RoomKeys[convId] == nil {
		c.codec.RoomKeys[convId] = make(map[uint16][]byte)
	}
	c.codec.RoomKeys[convId][epoch] = key
	c.codec.ConvKeys[convId] = key
	c.codec.CurrentEpochs[convId] = epoch
	if c.sharedWith[convId] == nil {
		c.sharedWith[convId] = make(map[uint16]bool)
	} else {
		for k := range c.sharedWith[convId] {
			delete(c.sharedWith[convId], k)
		}
	}
	// Start a fresh per-sender ratchet chain for this epoch and share it.
	c.initOwnChain(convId, epoch)
	if !hadKey {
		fmt.Printf("\x1b[36m[SYSTEM] Room %d group key established (epoch %d). Type /quit to exit.\x1b[0m\n", convId, epoch)
		c.mu.Unlock()
		c.SendData(convId, fmt.Sprintf("User %d joined the room (Go Native Client)", c.senderId))
		c.mu.Lock()
		for _, pending := range c.pendingQueue {
			c.mu.Unlock()
			c.SendData(convId, pending)
			c.mu.Lock()
		}
		c.pendingQueue = nil
	}
	c.shareWithNewMembers(convId)
	c.scheduleRekey(convId)
}

func (c *NativeDartClient) shareWithNewMembers(convId uint16) {
	key, ok := c.codec.ConvKeys[convId]
	if !ok {
		return
	}
	epoch := c.codec.CurrentEpochs[convId]
	if epoch == 0 {
		epoch = 1
	}
	roster := c.roster[convId]
	done := c.sharedWith[convId]
	if done == nil {
		done = make(map[uint16]bool)
	}
	var targets []uint16
	for mId := range roster {
		if mId == c.senderId || done[mId] {
			continue
		}
		targets = append(targets, mId)
		done[mId] = true
	}
	c.sharedWith[convId] = done
	if len(targets) == 0 {
		return
	}
	doShare := func() {
		for _, mId := range targets {
			mPub := roster[mId]
			sharedSecret, err := c.ecdh.ComputeSecret(mPub)
			if err != nil {
				continue
			}
			hasher := sha256.New()
			hasher.Write(sharedSecret)
			transportKey := hasher.Sum(nil)
			share := &core.KeyShareDart{
				Type:         core.TypeKeyShare,
				ConvId:       convId,
				SenderId:     c.senderId,
				TargetId:     mId,
				Epoch:        epoch,
				Nonce:        make([]byte, 12),
				EncryptedKey: key,
			}
			cryptorand.Read(share.Nonce)
			if out, err := c.codec.EncodeKeyShare(share, transportKey); err == nil {
				c.send(out)
			}
		}
	}
	doShare()
	// Retry a couple of times: the group-key share goes over UDP and can be
	// lost; a member that misses it can't adopt the key or join the room.
	retry := func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		doShare()
	}
	time.AfterFunc(300*time.Millisecond, retry)
	time.AfterFunc(1000*time.Millisecond, retry)
}

// ---- Per-sender ratchet chain management ----

func (c *NativeDartClient) getChain(convId uint16, epoch uint16, senderId uint16) (core.ChainState, bool) {
	cs, ok := c.senderChains[convId][epoch][senderId]
	return cs, ok
}

func (c *NativeDartClient) setChain(convId uint16, epoch uint16, senderId uint16, state core.ChainState) {
	if c.senderChains[convId] == nil {
		c.senderChains[convId] = make(map[uint16]map[uint16]core.ChainState)
	}
	if c.senderChains[convId][epoch] == nil {
		c.senderChains[convId][epoch] = make(map[uint16]core.ChainState)
	}
	c.senderChains[convId][epoch][senderId] = state
}

// initOwnChain generates a fresh chain seed for my own sends in `epoch` and
// shares it with every member (so they can decrypt my future messages).
func (c *NativeDartClient) initOwnChain(convId uint16, epoch uint16) {
	seed := make([]byte, 32)
	cryptorand.Read(seed)
	c.setChain(convId, epoch, c.senderId, core.ChainState{Key: seed, Index: 0})
	if c.chainSeeds[convId] == nil {
		c.chainSeeds[convId] = make(map[uint16]core.ChainState)
	}
	c.chainSeeds[convId][epoch] = core.ChainState{Key: seed, Index: 0}
	c.chainSharedWith[convId] = make(map[uint16]bool)
	c.shareChainWithMembers(convId, epoch)
}

func (c *NativeDartClient) shareChainWithMembers(convId uint16, epoch uint16) {
	myChain, ok := c.getChain(convId, epoch, c.senderId)
	if !ok {
		return
	}
	if c.chainSharedWith[convId] == nil {
		c.chainSharedWith[convId] = make(map[uint16]bool)
	}
	var targets []uint16
	for mId := range c.roster[convId] {
		if mId == c.senderId || c.chainSharedWith[convId][mId] {
			continue
		}
		targets = append(targets, mId)
		c.chainSharedWith[convId][mId] = true
	}
	if len(targets) == 0 {
		return
	}
	shareLocked := func() {
		for _, mId := range targets {
			c.sendChainShare(convId, epoch, mId, myChain.Key, myChain.Index)
		}
	}
	shareLocked()
	// Retry a couple of times: the shares go over UDP and a receiver that
	// misses its only copy can never decrypt this sender's messages. A stale
	// share is safe (the chain is deterministic).
	retry := func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		shareLocked()
	}
	time.AfterFunc(300*time.Millisecond, retry)
	time.AfterFunc(1000*time.Millisecond, retry)
}

func (c *NativeDartClient) sendChainShare(convId uint16, epoch uint16, targetId uint16, chainKey []byte, chainIndex uint32) {
	mPub := c.roster[convId][targetId]
	if mPub == nil {
		return
	}
	sharedSecret, err := c.ecdh.ComputeSecret(mPub)
	if err != nil {
		return
	}
	hasher := sha256.New()
	hasher.Write(sharedSecret)
	transportKey := hasher.Sum(nil)
	share := &core.ChainShareDart{
		Type:       core.TypeChainShare,
		ConvId:     convId,
		SenderId:   c.senderId,
		TargetId:   targetId,
		Epoch:      epoch,
		Nonce:      make([]byte, 12),
		ChainKey:   chainKey,
		ChainIndex: chainIndex,
	}
	cryptorand.Read(share.Nonce)
	if out, err := c.codec.EncodeChainShare(share, transportKey); err == nil {
		c.send(out)
	}
}

func (c *NativeDartClient) handleChainShare(buf []byte) {
	convId := binary.BigEndian.Uint16(buf[1:3])
	senderId := binary.BigEndian.Uint16(buf[3:5])
	targetId := binary.BigEndian.Uint16(buf[5:7])
	if targetId != c.senderId {
		return
	}
	sharerPub := c.roster[convId][senderId]
	if sharerPub == nil {
		return
	}
	sharedSecret, err := c.ecdh.ComputeSecret(sharerPub)
	if err != nil {
		return
	}
	hasher := sha256.New()
	hasher.Write(sharedSecret)
	transportKey := hasher.Sum(nil)
	decoded, err := c.codec.DecodeChainShare(buf, transportKey)
	if err != nil {
		return
	}
	c.setChain(convId, decoded.Epoch, decoded.SenderId, core.ChainState{Key: decoded.ChainKey, Index: decoded.ChainIndex})
}

// Forward secrecy: rotate the group key. Old epochs stay decryptable via
// RoomKeys; a compromised key only exposes its own epoch.
func (c *NativeDartClient) rekey(convId uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.doRekey(convId)
}

// doRekey performs the rotation; the caller must hold c.mu.
func (c *NativeDartClient) doRekey(convId uint16) {
	if !c.isCreator[convId] {
		return
	}
	current := c.codec.CurrentEpochs[convId]
	if current == 0 {
		current = 1
	}
	key := make([]byte, 32)
	cryptorand.Read(key)
	c.adoptKey(convId, current+1, key)
	c.pruneOldEpochs(convId)
}

func (c *NativeDartClient) scheduleRekey(convId uint16) {
	if c.rekeyTimer != nil {
		c.rekeyTimer.Stop()
	}
	secs := 300
	if v, err := strconv.Atoi(os.Getenv("DART_REKEY_SECONDS")); err == nil && v > 0 {
		secs = v
	}
	c.rekeyTimer = time.AfterFunc(time.Duration(secs)*time.Second, func() { c.rekey(convId) })
}

func (c *NativeDartClient) pruneOldEpochs(convId uint16) {
	current := c.codec.CurrentEpochs[convId]
	keys := c.codec.RoomKeys[convId]
	if keys == nil {
		return
	}
	for epoch := range keys {
		if epoch+4 < current {
			delete(keys, epoch)
		}
	}
}

func (c *NativeDartClient) Listen() {
	buf := make([]byte, 65535)
	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			return
		}
		c.handleMessage(append([]byte(nil), buf[:n]...))
	}
}

func (c *NativeDartClient) declarePermanentLoss(convId uint16, senderId uint16, lostSeq uint32) {
	if _, ok := c.receivedMessages[senderId]; !ok {
		c.receivedMessages[senderId] = make(map[uint32]*core.DataDart)
	}
	
	c.receivedMessages[senderId][lostSeq] = &core.DataDart{
		Type:     core.TypeData,
		ConvId:   convId,
		SenderId: senderId,
		Seq:      lostSeq,
		Payload:  "",
	}
	
	if d := core.SeqDelta(c.highestReceived[senderId], lostSeq); d > 0 && d < core.SeqMod/2 {
		c.highestReceived[senderId] = lostSeq
	}
	
	c.receivedMessages[senderId] = make(map[uint32]*core.DataDart) // clear
	c.outOfOrderBuffer[senderId] = make(map[uint32][]byte) // clear
	
	c.sendDictReset(convId, senderId)
}

func (c *NativeDartClient) processBufferedPackets(senderId uint16) {
	nextSeq := core.SeqNext(c.highestReceived[senderId])
	bufferMap, ok := c.outOfOrderBuffer[senderId]
	if !ok {
		return
	}
	
	for {
		buf, has := bufferMap[nextSeq]
		if !has {
			break
		}
		delete(bufferMap, nextSeq)
		dec := c.decryptDataInOrder(buf, senderId)
		if dec != nil && dec.SenderId == senderId {
			c.processDataPacket(buf, dec, senderId, nextSeq)
		}
		nextSeq = core.SeqNext(nextSeq)
	}
}

// decryptDataInOrder decrypts a data packet with the sender's ratchet chain,
// advancing the chain to the packet's index. Only commits after a successful
// decrypt, so a failed attempt doesn't burn chain keys.
func (c *NativeDartClient) decryptDataInOrder(buf []byte, senderId uint16) *core.DecryptedData {
	epoch := binary.BigEndian.Uint16(buf[21:23])
	idx := binary.BigEndian.Uint32(buf[27:31])
	convId := binary.BigEndian.Uint16(buf[1:3])
	chain, ok := c.getChain(convId, epoch, senderId)
	if !ok || idx < chain.Index {
		return nil
	}
	messageKey, state := core.AdvanceChain(chain, idx)
	dec, err := c.codec.DecryptData(buf, messageKey)
	if err != nil {
		return nil
	}
	c.setChain(convId, epoch, senderId, state)
	return dec
}

func (c *NativeDartClient) processDataPacket(buf []byte, dec *core.DecryptedData, parsedSenderId uint16, seq uint32) {
	if dec.SenderId != parsedSenderId {
		return
	}
	dict := c.getDictionary(parsedSenderId, seq)
	if !bytes.Equal(dec.DictFp, core.DictFingerprint(dict)) {
		fmt.Printf("\x1b[31m[SYSTEM] Dictionary desync detected (fingerprint). Sending automatic recovery signal...\x1b[0m\n")
		delete(c.receivedMessages, parsedSenderId)
		c.sendDictReset(dec.ConvId, parsedSenderId)
		return
	}
	payloadBytes, err := core.InflateData(dec.Compressed, dict)
	if err != nil {
		fmt.Printf("\x1b[31m[SYSTEM] Dictionary desync detected. Sending automatic recovery signal...\x1b[0m\n")
		delete(c.receivedMessages, parsedSenderId)
		c.sendDictReset(dec.ConvId, parsedSenderId)
		return
	}
	dart := &core.DataDart{
		Type:     core.TypeData,
		ConvId:   dec.ConvId,
		SenderId: parsedSenderId,
		Seq:      seq,
		Payload:  string(payloadBytes),
	}
	
	highestReceived := c.highestReceived[dart.SenderId]
	if _, ok := c.receivedMessages[dart.SenderId]; !ok {
		c.receivedMessages[dart.SenderId] = make(map[uint32]*core.DataDart)
	}
	
	if _, has := c.receivedMessages[dart.SenderId][dart.Seq]; !has {
		c.receivedMessages[dart.SenderId][dart.Seq] = dart
		d := uint32(1)
		if _, ok := c.highestReceived[dart.SenderId]; ok {
			d = core.SeqDelta(highestReceived, dart.Seq)
		}
		if d > 0 && d < core.SeqMod/2 {
			c.highestReceived[dart.SenderId] = dart.Seq
		}
		c.pruneReceived(dart.SenderId)
		
		if strings.HasPrefix(dart.Payload, "User ") && strings.Contains(dart.Payload, " joined ") {
			fmt.Printf("\x1b[36m[SYSTEM] %s\x1b[0m\n", dart.Payload)
		} else if dart.Payload != "" {
			fmt.Printf("\x1b[32m[User %d]: %s\x1b[0m\n", dart.SenderId, dart.Payload)
		}
		
		if t, ok := c.ackTimers[dart.SenderId]; ok {
			t.Stop()
		}
		c.ackTimers[dart.SenderId] = time.AfterFunc(200*time.Millisecond, func() {
			c.mu.Lock()
			c.sendAck(dart.ConvId, dart.SenderId, dart.Seq)
			c.mu.Unlock()
		})
	}
}

func (c *NativeDartClient) handleMessage(buf []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(buf) == 0 {
		return
	}

	typ := buf[0]

	// Try-catch equivalent for panics in Decode
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("\x1b[31m[SYSTEM] Packet dropped (decrypt failure or tamper detected).\x1b[0m")
		}
	}()

	switch typ {
	case core.TypeData:
		if len(buf) < 7+24 {
			return
		}
		if int(buf[6]) < 24 {
			return
		}
		convId := binary.BigEndian.Uint16(buf[1:3])
		seq := uint32(buf[3])<<16 | uint32(buf[4])<<8 | uint32(buf[5])
		parsedSenderId := binary.BigEndian.Uint16(buf[7:9])

		_, hasBaseline := c.highestReceived[parsedSenderId]
		highestReceived := c.highestReceived[parsedSenderId]
		// Modular gap test: 0 = duplicate, >= SeqMod/2 = stale, 1 = exact next.
		// A receiver with no baseline yet treats the first packet as its
		// baseline, except when the first seq is within the recoverable window:
		// then NACK the real gap instead of accepting an out-of-order start.
		ahead := uint32(1)
		if hasBaseline {
			ahead = core.SeqDelta(highestReceived, seq)
		} else if seq >= 1 && seq <= core.DictWindow {
			ahead = seq
		}
		if ahead == 0 || ahead >= core.SeqMod/2 {
			return
		}

		if ahead > 1 {
			if c.outOfOrderBuffer[parsedSenderId] == nil {
				c.outOfOrderBuffer[parsedSenderId] = make(map[uint32][]byte)
			}
			c.outOfOrderBuffer[parsedSenderId][seq] = buf

			var missing []uint32
			for k := uint32(1); k < ahead; k++ {
				i := (highestReceived + k) & 0xFFFFFF
				_, inBuffer := c.outOfOrderBuffer[parsedSenderId][i]
				msgs, hasSender := c.receivedMessages[parsedSenderId]
				inReceived := false
				if hasSender {
					_, inReceived = msgs[i]
				}

				if !inBuffer && !inReceived {
					if c.nackTimestamps[parsedSenderId] == nil {
						c.nackTimestamps[parsedSenderId] = make(map[uint32]time.Time)
					}
					ts, hasTs := c.nackTimestamps[parsedSenderId][i]
					if !hasTs {
						c.nackTimestamps[parsedSenderId][i] = time.Now()
						missing = append(missing, i)
					} else {
						if time.Since(ts) > 4*time.Second {
							fmt.Printf("\x1b[31m[SYSTEM] Packet seq %d from User %d permanently lost. Resynchronizing...\x1b[0m\n", i, parsedSenderId)
							c.declarePermanentLoss(convId, parsedSenderId, i)
						} else {
							missing = append(missing, i)
						}
					}
				}
			}
			if len(missing) > 0 {
				fmt.Printf("\x1b[33m[SYSTEM] Gap detected. Sent NACK for seqs: %v\x1b[0m\n", missing)
				c.sendNack(convId, parsedSenderId, missing)
			}
			return
		}

		dec := c.decryptDataInOrder(buf, parsedSenderId)
		if dec != nil {
			c.processDataPacket(buf, dec, parsedSenderId, seq)
			c.processBufferedPackets(parsedSenderId)
		}

	case core.TypeChainShare:
		c.handleChainShare(buf)

	case core.TypeNack:
		nackConvId := binary.BigEndian.Uint16(buf[1:3])
		nackSenderId := binary.BigEndian.Uint16(buf[3:5])
		nackTargetId := binary.BigEndian.Uint16(buf[5:7])
		if nackTargetId != c.senderId {
			return
		}
		// Verify the sender's per-sender MAC so a group member can't forge
		// another member's NACK.
		peerPub := c.roster[nackConvId][nackSenderId]
		if peerPub == nil {
			return
		}
		key, err := core.PairwiseKey(c.ecdh, peerPub)
		if err != nil {
			return
		}
		stripped, ok := core.VerifyControlFrame(buf, key)
		if !ok {
			return
		}
		nack, err := c.codec.DecodeNack(stripped)
		if err != nil {
			return
		}
		fmt.Printf("\x1b[33m[SYSTEM] Receiver missed seqs %v. Sending NACK repairs...\x1b[0m\n", nack.MissingSeq)
		for _, seq := range nack.MissingSeq {
			if dart, ok := c.sentMessages[seq]; ok {
				if mk, ok := c.messageKeys[seq]; ok {
					dict := c.getDictionary(c.senderId, seq)
					outBuf, _ := c.codec.EncodeData(dart, dict, mk.key, mk.idx, nil)
					c.send(outBuf)
				}
			}
		}
		// The NACKer likely missed the chain share too (it can't decrypt my
		// stream without one). Re-share the chain SEED (index 0) so it can
		// reach back and decrypt the whole epoch, not just future messages.
		if epoch := c.codec.CurrentEpochs[nackConvId]; epoch != 0 {
			if seed, ok := c.chainSeeds[nackConvId][epoch]; ok {
				c.sendChainShare(nackConvId, epoch, nackSenderId, seed.Key, seed.Index)
			}
		}

	case core.TypeSync:
		// SYNC is keyed to the relay server, which verified and relayed it.
		syncStripped, ok := core.StripControlFrame(buf)
		if !ok {
			return
		}
		sync, err := c.codec.DecodeSync(syncStripped)
		if err != nil {
			return
		}
		_, hasBaseline := c.highestReceived[sync.SenderId]
		highestReceived := c.highestReceived[sync.SenderId]
		// Fresh receiver: NACK the whole reported range; otherwise only the
		// modular distance ahead of what we've seen (handles wraps).
		ahead := sync.HighestSeq
		if hasBaseline {
			ahead = core.SeqDelta(highestReceived, sync.HighestSeq)
		}
		if ahead > 0 && ahead < core.SeqMod/2 {
			var missing []uint32
			if c.receivedMessages[sync.SenderId] == nil {
				c.receivedMessages[sync.SenderId] = make(map[uint32]*core.DataDart)
			}
			for k := uint32(1); k <= ahead; k++ {
				i := (highestReceived + k) & 0xFFFFFF
				_, inBuffer := c.outOfOrderBuffer[sync.SenderId][i]
				_, inReceived := c.receivedMessages[sync.SenderId][i]
				if !inBuffer && !inReceived {
					if c.nackTimestamps[sync.SenderId] == nil {
						c.nackTimestamps[sync.SenderId] = make(map[uint32]time.Time)
					}
					ts, hasTs := c.nackTimestamps[sync.SenderId][i]
					if !hasTs {
						c.nackTimestamps[sync.SenderId][i] = time.Now()
						missing = append(missing, i)
					} else {
						if time.Since(ts) > 4*time.Second {
							fmt.Printf("\x1b[31m[SYSTEM] Packet seq %d from User %d permanently lost. Resynchronizing...\x1b[0m\n", i, sync.SenderId)
							c.declarePermanentLoss(sync.ConvId, sync.SenderId, i)
							c.processBufferedPackets(sync.SenderId)
						} else {
							missing = append(missing, i)
						}
					}
				}
			}
			if len(missing) > 0 {
				fmt.Printf("\x1b[33m[SYSTEM] Sync probe revealed gap. Sent NACK for seqs: %v\x1b[0m\n", missing)
				c.sendNack(sync.ConvId, sync.SenderId, missing)
			}
		}

	case core.TypeAck:
		ackConvId := binary.BigEndian.Uint16(buf[1:3])
		ackSenderId := binary.BigEndian.Uint16(buf[3:5])
		ackTargetId := binary.BigEndian.Uint16(buf[5:7])
		if ackTargetId != c.senderId {
			return
		}
		peerPub := c.roster[ackConvId][ackSenderId]
		if peerPub == nil {
			return
		}
		key, err := core.PairwiseKey(c.ecdh, peerPub)
		if err != nil {
			return
		}
		ackStripped, ok := core.VerifyControlFrame(buf, key)
		if !ok {
			return
		}
		ack, err := c.codec.DecodeAck(ackStripped)
		if err == nil && core.SeqDelta(c.highestSentSeq, ack.Seq) < core.SeqMod/2 {
			// Record the ACK; the re-arming sync probe stops on its own once
			// the latest message is acknowledged.
			c.ackedSeq[ack.ConvId] = ack.Seq
			fmt.Printf("\x1b[90m[✓] Delivered (Seq %d)                                  \x1b[0m\n", ack.Seq)
		}

	case core.TypeKeyShare:
		if len(buf) < 7 {
			return
		}
		convId := binary.BigEndian.Uint16(buf[1:3])
		senderId := binary.BigEndian.Uint16(buf[3:5])
		targetId := binary.BigEndian.Uint16(buf[5:7])
		if targetId != c.senderId {
			return
		}
		sharerPub := c.roster[convId][senderId]
		if sharerPub == nil {
			return
		}
		sharedSecret, err := c.ecdh.ComputeSecret(sharerPub)
		if err != nil {
			return
		}
		hasher := sha256.New()
		hasher.Write(sharedSecret)
		transportKey := hasher.Sum(nil)
		epoch, groupKey, err := c.codec.DecodeKeyShare(buf, transportKey)
		if err != nil {
			return
		}
		currentEpoch := c.codec.CurrentEpochs[convId]
		_, has := c.codec.ConvKeys[convId]
		curKey := c.codec.ConvKeys[convId]
		// Adopt on first join, on a newer epoch, or on an equal epoch with a
		// DIFFERENT key (a restarted creator re-uses epoch 1 with a fresh key).
		if !has || epoch > currentEpoch || (epoch == currentEpoch && !bytes.Equal(curKey, groupKey)) {
			c.adoptKey(convId, epoch, groupKey)
		}

	case core.TypeMemberInfo:
		serverPub, err := core.MemberInfoServerKey(buf)
		if err != nil {
			return
		}
		fp := core.ServerFingerprint(serverPub)
		if c.serverFingerprint != "" {
			if fp != c.serverFingerprint {
				fmt.Println("\x1b[31m[SYSTEM] SERVER FINGERPRINT MISMATCH — possible MITM. Aborting key exchange.\x1b[0m")
				return
			}
		}
		sharedSecret, err := c.ecdh.ComputeSecret(serverPub)
		if err != nil {
			return
		}
		hasher := sha256.New()
		hasher.Write(sharedSecret)
		transportKey := hasher.Sum(nil)
		info, err := c.codec.DecodeMemberInfo(buf, transportKey)
		if err != nil {
			fmt.Println("\x1b[31m[SYSTEM] Could not authenticate server membership info. Aborting.\x1b[0m")
			return
		}
		roster := make(map[uint16][]byte)
		for _, m := range info.Members {
			roster[m.SenderId] = m.PubKey
		}
		prevRoster, hadRoster := c.roster[info.ConvId]
		c.roster[info.ConvId] = roster
		if hadRoster {
			// A member whose pubkey changed (reconnect with a fresh ECDH
			// keypair) needs fresh group-key and chain shares under the new
			// key; drop the shared-with flags so the shares are re-sent.
			for sid, pub := range roster {
				if prevPub, ok := prevRoster[sid]; ok && !bytes.Equal(prevPub, pub) {
					delete(c.sharedWith[info.ConvId], sid)
					delete(c.chainSharedWith[info.ConvId], sid)
				}
			}
		}
		c.serverPubKeys[info.ConvId] = serverPub
		prevCreator := c.isCreator[info.ConvId]
		c.isCreator[info.ConvId] = info.Creator
		if _, has := c.codec.ConvKeys[info.ConvId]; has {
			c.shareWithNewMembers(info.ConvId)
		} else if info.Creator {
			key := make([]byte, 32)
			cryptorand.Read(key)
			c.adoptKey(info.ConvId, 1, key)
		}
		// If I just became the creator (successor election after the previous
		// creator left), rotate immediately so the departed member loses access.
		if info.Creator && !prevCreator {
			if _, has := c.codec.ConvKeys[info.ConvId]; has {
				c.doRekey(info.ConvId)
			}
		}
		// Share my ratchet chain with any members that just joined.
		epoch := c.codec.CurrentEpochs[info.ConvId]
		if epoch == 0 {
			epoch = 1
		}
		c.shareChainWithMembers(info.ConvId, epoch)
		c.scheduleRekey(info.ConvId)

	case core.TypeDictReset:
		// Dict-Reset is keyed to the relay server, which verified it.
		resetStripped, ok := core.StripControlFrame(buf)
		if !ok {
			return
		}
		reset, err := c.codec.DecodeDictReset(resetStripped)
		if err == nil {
			if reset.TargetId == c.senderId {
				fmt.Printf("\x1b[31m[SYSTEM] User %d requested a dictionary reset. Flushing history...\x1b[0m\n", reset.SenderId)
				c.sentMessages = make(map[uint32]*core.DataDart)
			} else {
				delete(c.receivedMessages, reset.TargetId)
			}
		}

	default:
		fmt.Printf("\x1b[31mUnknown packet type: %d\x1b[0m\n", typ)
	}
}

func main() {
	client, err := NewNativeDartClient("127.0.0.1", 9000)
	if err != nil {
		fmt.Println("Failed to connect:", err)
		return
	}
	
	go client.Listen()

	if fb := os.Getenv("DART_TCP_FALLBACK"); fb != "" {
		host, portStr, err := net.SplitHostPort(fb)
		if err == nil {
			if port, perr := strconv.Atoi(portStr); perr == nil {
				if err := client.enableFallback(host, port); err != nil {
					fmt.Println("TCP fallback failed:", err)
				}
			}
		}
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Room ID to join (e.g. 1): ")
	roomInput, _ := reader.ReadString('\n')
	roomId, err := strconv.Atoi(strings.TrimSpace(roomInput))
	if err != nil {
		fmt.Println("Invalid Room ID")
		return
	}

	client.JoinRoom(uint16(roomId))

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\n\x1b[36m[SYSTEM] Caught interrupt signal. Disconnecting...\x1b[0m")
		os.Exit(0)
	}()

	for {
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)
		if text == "/quit" || text == "/exit" {
			fmt.Println("\x1b[36m[SYSTEM] Disconnecting...\x1b[0m")
			os.Exit(0)
		}
		if text != "" {
			client.SendData(client.roomId, text)
		}
	}
}
