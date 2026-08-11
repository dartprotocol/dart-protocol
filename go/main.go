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

type NativeDartClient struct {
	conn       *net.UDPConn
	senderId   uint16
	roomId     uint16
	codec      *core.Codec
	ecdh       *core.ECDH
	serverAddr *net.UDPAddr

	serverFingerprint string

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
	// be pruned).
	var msgsToConcat []*core.DataDart
	minSeq := uint32(1)
	if maxSeq > core.DictWindow {
		minSeq = maxSeq - core.DictWindow
	}

	if senderId == c.senderId {
		for seq, dart := range c.sentMessages {
			if seq >= minSeq && seq < maxSeq {
				msgsToConcat = append(msgsToConcat, dart)
			}
		}
	} else {
		if msgs, ok := c.receivedMessages[senderId]; ok {
			for seq, dart := range msgs {
				if seq >= minSeq && seq < maxSeq {
					msgsToConcat = append(msgsToConcat, dart)
				}
			}
		}
	}

	sort.Slice(msgsToConcat, func(i, j int) bool {
		return msgsToConcat[i].Seq < msgsToConcat[j].Seq
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
	minSeq := uint32(1)
	if c.highestSentSeq > core.DictWindow+16 {
		minSeq = c.highestSentSeq - core.DictWindow - 16
	}
	for seq := range c.sentMessages {
		if seq < minSeq {
			delete(c.sentMessages, seq)
		}
	}
}

func (c *NativeDartClient) pruneReceived(senderId uint16) {
	highest := c.highestReceived[senderId]
	minSeq := uint32(1)
	if highest > core.DictWindow+16 {
		minSeq = highest - core.DictWindow - 16
	}
	if msgs, ok := c.receivedMessages[senderId]; ok {
		for seq := range msgs {
			if seq < minSeq {
				delete(msgs, seq)
			}
		}
	}
	if ts, ok := c.nackTimestamps[senderId]; ok {
		for seq := range ts {
			if seq < minSeq {
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

	seq := c.nextSeq
	c.nextSeq++
	
	dart := &core.DataDart{
		Type:     core.TypeData,
		ConvId:   roomId,
		SenderId: c.senderId,
		Seq:      seq,
		Payload:  payload,
	}
	c.sentMessages[seq] = dart
	c.highestSentSeq = seq
	c.pruneSent()

	dict := c.getDictionary(c.senderId, seq)
	buf, err := c.codec.EncodeData(dart, dict)
	if err == nil {
		c.send(buf)
	}

	fmt.Printf("\x1b[90m[↑] Sending Seq %d...\x1b[0m\r", seq)

	c.clearSyncTimers()
	c.syncTimers = append(c.syncTimers, time.AfterFunc(300*time.Millisecond, func() { c.sendSync(roomId) }))
	c.syncTimers = append(c.syncTimers, time.AfterFunc(1000*time.Millisecond, func() { c.sendSync(roomId) }))
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
	buf, _ := c.codec.EncodeSync(sync)
	c.send(buf)
}

func (c *NativeDartClient) sendNack(convId uint16, senderId uint16, missing []uint32) {
	nack := &core.NackDart{
		Type:       core.TypeNack,
		ConvId:     convId,
		SenderId:   senderId,
		MissingSeq: missing,
	}
	buf, _ := c.codec.EncodeNack(nack)
	c.send(buf)
}

func (c *NativeDartClient) sendAck(convId uint16, targetId uint16, seq uint32) {
	ack := &core.AckDart{
		Type:     core.TypeAck,
		ConvId:   convId,
		SenderId: c.senderId,
		TargetId: targetId,
		Seq:      seq,
	}
	buf, _ := c.codec.EncodeAck(ack)
	c.send(buf)
}

func (c *NativeDartClient) sendDictReset(convId uint16, targetId uint16) {
	reset := &core.DictResetDart{
		Type:     core.TypeDictReset,
		ConvId:   convId,
		SenderId: c.senderId,
		TargetId: targetId,
	}
	buf, _ := c.codec.EncodeDictReset(reset)
	c.send(buf)
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
	for mId, mPub := range roster {
		if mId == c.senderId || done[mId] {
			continue
		}
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
		done[mId] = true
	}
	c.sharedWith[convId] = done
}

// Forward secrecy: rotate the group key. Old epochs stay decryptable via
// RoomKeys; a compromised key only exposes its own epoch.
func (c *NativeDartClient) rekey(convId uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()
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
	
	if lostSeq > c.highestReceived[senderId] {
		c.highestReceived[senderId] = lostSeq
	}
	
	c.receivedMessages[senderId] = make(map[uint32]*core.DataDart) // clear
	c.outOfOrderBuffer[senderId] = make(map[uint32][]byte) // clear
	
	c.sendDictReset(convId, senderId)
}

func (c *NativeDartClient) processBufferedPackets(senderId uint16) {
	nextSeq := c.highestReceived[senderId] + 1
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
		c.processDataPacket(buf, senderId, nextSeq)
		nextSeq++
	}
}

func (c *NativeDartClient) processDataPacket(buf []byte, parsedSenderId uint16, seq uint32) {
	dec, err := c.codec.DecryptData(buf)
	if err != nil || dec.SenderId != parsedSenderId {
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
		if dart.Seq > highestReceived {
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
		dec, err := c.codec.DecryptData(buf)
		if err != nil {
			fmt.Printf("\x1b[31m[SYSTEM] Packet dropped (decrypt failure or tamper detected): %v\x1b[0m\n", err)
			return
		}
		parsedSenderId := dec.SenderId
		seq := dec.Seq
		convId := dec.ConvId

		highestReceived := c.highestReceived[parsedSenderId]
		if seq <= highestReceived {
			return
		}

		if seq > highestReceived+1 {
			if c.outOfOrderBuffer[parsedSenderId] == nil {
				c.outOfOrderBuffer[parsedSenderId] = make(map[uint32][]byte)
			}
			c.outOfOrderBuffer[parsedSenderId][seq] = buf

			var missing []uint32
			for i := highestReceived + 1; i < seq; i++ {
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

		c.processDataPacket(buf, parsedSenderId, seq)
		c.processBufferedPackets(parsedSenderId)

	case core.TypeNack:
		nack, err := c.codec.DecodeNack(buf)
		if err != nil || nack.SenderId != c.senderId {
			return
		}
		fmt.Printf("\x1b[33m[SYSTEM] Receiver missed seqs %v. Sending NACK repairs...\x1b[0m\n", nack.MissingSeq)
		for _, seq := range nack.MissingSeq {
			if dart, ok := c.sentMessages[seq]; ok {
				dict := c.getDictionary(c.senderId, seq)
				outBuf, _ := c.codec.EncodeData(dart, dict)
				c.send(outBuf)
			}
		}

	case core.TypeSync:
		sync, err := c.codec.DecodeSync(buf)
		if err != nil {
			return
		}
		highestReceived := c.highestReceived[sync.SenderId]
		if sync.HighestSeq > highestReceived {
			var missing []uint32
			if c.receivedMessages[sync.SenderId] == nil {
				c.receivedMessages[sync.SenderId] = make(map[uint32]*core.DataDart)
			}
			for i := highestReceived + 1; i <= sync.HighestSeq; i++ {
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
			} else if highestReceived == sync.HighestSeq {
				c.sendAck(sync.ConvId, sync.SenderId, highestReceived)
			}
		}

	case core.TypeAck:
		ack, err := c.codec.DecodeAck(buf)
		if err == nil && ack.TargetId == c.senderId && ack.Seq >= c.highestSentSeq {
			c.clearSyncTimers()
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
		if _, has := c.codec.ConvKeys[convId]; !has || epoch > currentEpoch {
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
		c.roster[info.ConvId] = roster
		c.isCreator[info.ConvId] = info.Creator
		if _, has := c.codec.ConvKeys[info.ConvId]; has {
			c.shareWithNewMembers(info.ConvId)
		} else if info.Creator {
			key := make([]byte, 32)
			cryptorand.Read(key)
			c.adoptKey(info.ConvId, 1, key)
		}
		c.scheduleRekey(info.ConvId)

	case core.TypeDictReset:
		reset, err := c.codec.DecodeDictReset(buf)
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
