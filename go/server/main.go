package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"dartgo/core"
	"github.com/gorilla/websocket"
)

type PeerType string

const (
	PeerUDP PeerType = "udp"
	PeerWS  PeerType = "ws"
	PeerTCP PeerType = "tcp"
)

type Peer struct {
	ID             string
	Type           PeerType
	UDPAddr        *net.UDPAddr
	WSConn         *websocket.Conn
	TCPConn        net.Conn
	LastPacketTime time.Time
	PacketCount    int
	wsMu           sync.Mutex // Protects concurrent writes to WSConn
	tcpMu          sync.Mutex // Protects concurrent writes to TCPConn
}

type DartGroupServer struct {
	udpConn  *net.UDPConn
	codec    *core.Codec
	serverECDH *core.ECDH

	mu          sync.Mutex
	groups      map[uint16][]*Peer
	clientMap   map[uint16]map[uint16]*Peer
	peerIdentity map[string]uint16
	members     map[uint16]map[uint16][]byte // blind: public membership only
	creator     map[uint16]uint16            // first member (generates/rotates the key)
	messageCache map[uint16]map[uint16]map[uint32][]byte
	highestSeq  map[uint16]map[uint16]uint32

	upgrader websocket.Upgrader
}

// loadOrCreateServerKey loads the server's long-term ECDH key from disk (hex
// of the 32-byte P-256 scalar) so its public-key fingerprint is stable across
// restarts — required for clients to pin it.
func loadOrCreateServerKey() *core.ECDH {
	keyFile := os.Getenv("DART_SERVER_KEY_FILE")
	if keyFile == "" {
		keyFile = "dart_server.key"
	}
	if data, err := ioutil.ReadFile(keyFile); err == nil {
		priv, err := hex.DecodeString(strings.TrimSpace(string(data)))
		if err == nil {
			if ecdh, err := core.NewECDHFromPrivate(priv); err == nil {
				return ecdh
			}
		}
		log.Printf("Could not load server key from %s; generating a new one.", keyFile)
	}
	ecdh, err := core.NewECDH()
	if err != nil {
		log.Fatalf("Failed to generate Server ECDH: %v", err)
	}
	if err := ioutil.WriteFile(keyFile, []byte(hex.EncodeToString(ecdh.GetPrivateKey())), 0600); err != nil {
		log.Printf("Warning: could not persist server key: %v", err)
	}
	return ecdh
}

func NewDartGroupServer() *DartGroupServer {
	ecdh := loadOrCreateServerKey()
	log.Printf("Server key fingerprint: %s", core.ServerFingerprint(ecdh.GetPublicKey()))
	log.Printf("  -> Pin it in clients (e.g. DART_SERVER_FINGERPRINT=%s) to prevent MITM on key exchange.", core.ServerFingerprint(ecdh.GetPublicKey()))
	return &DartGroupServer{
		codec:        core.NewCodec(),
		serverECDH:   ecdh,
		groups:       make(map[uint16][]*Peer),
		clientMap:    make(map[uint16]map[uint16]*Peer),
		peerIdentity: make(map[string]uint16),
		members:      make(map[uint16]map[uint16][]byte),
		creator:      make(map[uint16]uint16),
		messageCache: make(map[uint16]map[uint16]map[uint32][]byte),
		highestSeq:   make(map[uint16]map[uint16]uint32),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

func (s *DartGroupServer) StartUDP(port int) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("UDP Resolve Error: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("UDP Listen Error: %v", err)
	}
	s.udpConn = conn
	log.Printf("UDP Server listening on %d", port)

	buf := make([]byte, 65535)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("UDP Read Error: %v", err)
			continue
		}
		
		msg := make([]byte, n)
		copy(msg, buf[:n])
		
		peerID := fmt.Sprintf("udp:%s", raddr.String())
		peer := &Peer{
			ID:      peerID,
			Type:    PeerUDP,
			UDPAddr: raddr,
		}
		
		go s.handleMessage(msg, peer)
	}
}

func (s *DartGroupServer) StartWS(port int) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := s.upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("WS Upgrade Error: %v", err)
			return
		}
		peerID := fmt.Sprintf("ws:%s", r.RemoteAddr)
		peer := &Peer{
			ID:     peerID,
			Type:   PeerWS,
			WSConn: conn,
		}
		
		go func() {
			defer func() {
				s.removePeer(peerID)
				conn.Close()
			}()
			
			for {
				msgType, msg, err := conn.ReadMessage()
				if err != nil {
					break
				}
				if msgType == websocket.BinaryMessage {
					s.handleMessage(msg, peer)
				}
			}
		}()
	})

	log.Printf("WebSocket Server listening on %d", port)
	go func() {
		if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
			log.Fatalf("HTTP Listen Error: %v", err)
		}
	}()
}

func (s *DartGroupServer) joinGroup(convId uint16, peer *Peer) {
	s.mu.Lock()
	defer s.mu.Unlock()

	group := s.groups[convId]
	found := false
	for _, p := range group {
		if p.ID == peer.ID {
			found = true
			
			// Update the peer in place so we keep its state/socket
			if p.Type == PeerUDP {
				p.UDPAddr = peer.UDPAddr
			}
			break
		}
	}
	if !found {
		s.groups[convId] = append(group, peer)
	}
}

func (s *DartGroupServer) removePeer(peerId string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var leftConvs []uint16
	for convId, group := range s.groups {
		before := len(group)
		var newGroup []*Peer
		for _, p := range group {
			if p.ID != peerId {
				newGroup = append(newGroup, p)
			}
		}
		s.groups[convId] = newGroup
		if len(newGroup) != before {
			leftConvs = append(leftConvs, convId)
		}
	}
	// Remove the departed member and notify the rest so they can re-key.
	senderId, ok := s.peerIdentity[peerId]
	for _, convId := range leftConvs {
		if ok {
			delete(s.members[convId], senderId)
		}
		s.notifyMembersLocked(convId)
	}
}

// notifyMembers broadcasts the current roster (encrypted per member) to every
// member. Caller must hold s.mu.
func (s *DartGroupServer) notifyMembersLocked(convId uint16) {
	mems := s.members[convId]
	if mems == nil {
		return
	}
	roster := make([]core.Member, 0, len(mems))
	for sid, pub := range mems {
		roster = append(roster, core.Member{SenderId: sid, PubKey: pub})
	}
	for mSenderId, mPubKey := range mems {
		sharedSecret, err := s.serverECDH.ComputeSecret(mPubKey)
		if err != nil {
			continue
		}
		hasher := sha256.New()
		hasher.Write(sharedSecret)
		transportKey := hasher.Sum(nil)
		info := &core.MemberInfo{
			Type:         core.TypeMemberInfo,
			ConvId:       convId,
			SenderId:     mSenderId,
			ServerPubKey: s.serverECDH.GetPublicKey(),
			Creator:      s.creator[convId] == mSenderId,
			Members:      roster,
		}
		if out, err := s.codec.EncodeMemberInfo(info, transportKey); err == nil {
			if tp := s.clientMap[convId][mSenderId]; tp != nil {
				s.sendToPeer(out, tp)
			}
		}
	}
}

func (s *DartGroupServer) notifyMembers(convId uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notifyMembersLocked(convId)
}

func (s *DartGroupServer) sendToPeer(buf []byte, peer *Peer) {
	if peer.Type == PeerUDP && peer.UDPAddr != nil {
		s.udpConn.WriteToUDP(buf, peer.UDPAddr)
	} else if peer.Type == PeerWS && peer.WSConn != nil {
		peer.wsMu.Lock()
		peer.WSConn.WriteMessage(websocket.BinaryMessage, buf)
		peer.wsMu.Unlock()
	} else if peer.Type == PeerTCP && peer.TCPConn != nil {
		// 2-byte big-endian length prefix + payload (same framing as the Node server)
		out := make([]byte, 2+len(buf))
		binary.BigEndian.PutUint16(out[0:2], uint16(len(buf)))
		copy(out[2:], buf)
		peer.tcpMu.Lock()
		peer.TCPConn.Write(out)
		peer.tcpMu.Unlock()
	}
}

// StartTCP runs the TCP fallback listener (same framing as the Node server).
func (s *DartGroupServer) StartTCP(port int) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("TCP Listen Error: %v", err)
	}
	log.Printf("TCP Server listening on %d", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go s.handleTCPConn(conn)
	}
}

func (s *DartGroupServer) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	peerID := fmt.Sprintf("tcp:%s", conn.RemoteAddr().String())
	peer := &Peer{
		ID:      peerID,
		Type:    PeerTCP,
		TCPConn: conn,
	}
	buf := make([]byte, 0)
	tmp := make([]byte, 4096)
	for {
		n, err := conn.Read(tmp)
		if err != nil {
			break
		}
		buf = append(buf, tmp[:n]...)
		for len(buf) >= 2 {
			l := int(binary.BigEndian.Uint16(buf[0:2]))
			if l == 0 || len(buf) < 2+l {
				break
			}
			payload := append([]byte(nil), buf[2:2+l]...)
			buf = buf[2+l:]
			s.handleMessage(payload, peer)
		}
	}
	s.removePeer(peerID)
}

func (s *DartGroupServer) handleMessage(buf []byte, peer *Peer) {
	if len(buf) == 0 {
		return
	}

	// Rate limiting logic
	s.mu.Lock()
	now := time.Now()
	
	var actualPeer *Peer
	// Find or register actual peer for rate limiting state
	found := false
	for _, group := range s.groups {
		for _, p := range group {
			if p.ID == peer.ID {
				actualPeer = p
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		actualPeer = peer
		actualPeer.LastPacketTime = now
		actualPeer.PacketCount = 0
	}
	
	if now.Sub(actualPeer.LastPacketTime) > time.Second {
		actualPeer.LastPacketTime = now
		actualPeer.PacketCount = 0
	}
	actualPeer.PacketCount++
	if actualPeer.PacketCount > 100 {
		s.mu.Unlock()
		log.Printf("[Server] Rate limit exceeded for %s. Dropping packet.", peer.ID)
		return
	}
	s.mu.Unlock()

	typ := buf[0]
	if len(buf) < 3 {
		return
	}
	convId := binary.BigEndian.Uint16(buf[1:3])
	
	s.joinGroup(convId, actualPeer)
	
	s.mu.Lock()
	if typ != core.TypeData && len(buf) >= 5 {
		senderId := binary.BigEndian.Uint16(buf[3:5])
		s.peerIdentity[actualPeer.ID] = senderId
		if s.clientMap[convId] == nil {
			s.clientMap[convId] = make(map[uint16]*Peer)
		}
		s.clientMap[convId][senderId] = actualPeer
	}
	s.mu.Unlock()

	switch typ {
	case core.TypeData:
		if len(buf) < 7 {
			return
		}
		s.mu.Lock()
		senderId, ok := s.peerIdentity[actualPeer.ID]
		s.mu.Unlock()
		if !ok {
			log.Printf("[Server] Dropping DataDart from unknown peer %s (no key exchange seen).", peer.ID)
			return
		}
		seq := uint32(buf[3])<<16 | uint32(buf[4])<<8 | uint32(buf[5])
		log.Printf("[Server] DataDart Conv:%d Sender:%d Seq:%d", convId, senderId, seq)
		
		s.mu.Lock()
		if s.messageCache[convId] == nil {
			s.messageCache[convId] = make(map[uint16]map[uint32][]byte)
		}
		if s.messageCache[convId][senderId] == nil {
			s.messageCache[convId][senderId] = make(map[uint32][]byte)
		}
		s.messageCache[convId][senderId][seq] = buf
		
		if s.highestSeq[convId] == nil {
			s.highestSeq[convId] = make(map[uint16]uint32)
		}
		currentHighest := s.highestSeq[convId][senderId]
		
		// GC Cache
		minSeq := uint32(1)
		maxS := seq
		if currentHighest > maxS {
			maxS = currentHighest
		}
		if maxS > 200 {
			minSeq = maxS - 200
		}
		for k := range s.messageCache[convId][senderId] {
			if k < minSeq {
				delete(s.messageCache[convId][senderId], k)
			}
		}
		
		var missing []uint32
		if seq > currentHighest+1 {
			for i := currentHighest + 1; i < seq; i++ {
				if _, ok := s.messageCache[convId][senderId][i]; !ok {
					missing = append(missing, i)
				}
			}
		}
		if seq > currentHighest {
			s.highestSeq[convId][senderId] = seq
		}
		
		// copy group to release lock
		group := make([]*Peer, len(s.groups[convId]))
		copy(group, s.groups[convId])
		s.mu.Unlock()

		if len(missing) > 0 {
			s.sendNack(convId, senderId, missing, actualPeer)
		}
		
		fanned := 0
		for _, p := range group {
			if p.ID != actualPeer.ID {
				s.sendToPeer(buf, p)
				fanned++
			}
		}
		log.Printf("[Server] Fanned out to %d peers", fanned)

	case core.TypeKeyReq:
		req, err := s.codec.DecodeKeyReq(buf)
		if err != nil {
			return
		}
		log.Printf("[Server] KeyReq Conv:%d Sender:%d", req.ConvId, req.SenderId)

		// The server is BLIND: it never sees or stores group keys. It only
		// tracks public membership and relays opaque key shares.
		s.mu.Lock()
		if s.members[req.ConvId] == nil {
			s.members[req.ConvId] = make(map[uint16][]byte)
			s.creator[req.ConvId] = req.SenderId
		}
		s.members[req.ConvId][req.SenderId] = req.ClientPubKey
		s.mu.Unlock()
		s.notifyMembers(req.ConvId)

	case core.TypeKeyShare:
		// Relay the (opaque, encrypted) group-key share to its target.
		if len(buf) < 7 {
			return
		}
		targetId := binary.BigEndian.Uint16(buf[5:7])
		s.mu.Lock()
		var targetPeer *Peer
		if m, ok := s.clientMap[convId]; ok {
			targetPeer = m[targetId]
		}
		s.mu.Unlock()
		if targetPeer != nil {
			s.sendToPeer(buf, targetPeer)
		}

	case core.TypeNack:
		nack, err := s.codec.DecodeNack(buf)
		if err != nil {
			return
		}
		
		s.mu.Lock()
		var missingFromServer []uint32
		var cacheMap map[uint32][]byte
		if s.messageCache[nack.ConvId] != nil {
			cacheMap = s.messageCache[nack.ConvId][nack.SenderId]
		}
		
		for _, seq := range nack.MissingSeq {
			if cached, ok := cacheMap[seq]; ok {
				s.sendToPeer(cached, actualPeer)
			} else {
				missingFromServer = append(missingFromServer, seq)
			}
		}
		group := make([]*Peer, len(s.groups[nack.ConvId]))
		copy(group, s.groups[nack.ConvId])
		s.mu.Unlock()
		
		if len(missingFromServer) > 0 {
			for _, p := range group {
				if p.ID != actualPeer.ID {
					s.sendNack(nack.ConvId, nack.SenderId, missingFromServer, p)
				}
			}
		}

	case core.TypeSync:
		sync, err := s.codec.DecodeSync(buf)
		if err != nil {
			return
		}
		
		s.mu.Lock()
		currentHighest := uint32(0)
		if s.highestSeq[sync.ConvId] != nil {
			currentHighest = s.highestSeq[sync.ConvId][sync.SenderId]
		}
		
		var missing []uint32
		if sync.HighestSeq > currentHighest {
			for i := currentHighest + 1; i <= sync.HighestSeq; i++ {
				found := false
				if s.messageCache[sync.ConvId] != nil && s.messageCache[sync.ConvId][sync.SenderId] != nil {
					_, found = s.messageCache[sync.ConvId][sync.SenderId][i]
				}
				if !found {
					missing = append(missing, i)
				}
			}
		}
		
		group := make([]*Peer, len(s.groups[sync.ConvId]))
		copy(group, s.groups[sync.ConvId])
		s.mu.Unlock()

		if len(missing) > 0 {
			s.sendNack(sync.ConvId, sync.SenderId, missing, actualPeer)
		}
		
		for _, p := range group {
			if p.ID != actualPeer.ID {
				s.sendToPeer(buf, p)
			}
		}

	case 0x06: // DictReset
		s.mu.Lock()
		group := make([]*Peer, len(s.groups[convId]))
		copy(group, s.groups[convId])
		s.mu.Unlock()
		for _, p := range group {
			if p.ID != actualPeer.ID {
				s.sendToPeer(buf, p)
			}
		}

	case 0x07: // Ack
		if len(buf) < 7 {
			return
		}
		targetId := binary.BigEndian.Uint16(buf[5:7])
		s.mu.Lock()
		var targetPeer *Peer
		if m, ok := s.clientMap[convId]; ok {
			targetPeer = m[targetId]
		}
		s.mu.Unlock()
		if targetPeer != nil {
			s.sendToPeer(buf, targetPeer)
		}
	}
}

func (s *DartGroupServer) sendNack(convId uint16, senderId uint16, missingSeq []uint32, peer *Peer) {
	nack := &core.NackDart{
		Type:       core.TypeNack,
		ConvId:     convId,
		SenderId:   senderId,
		MissingSeq: missingSeq,
	}
	if out, err := s.codec.EncodeNack(nack); err == nil {
		s.sendToPeer(out, peer)
	}
}

func main() {
	fmt.Println("Starting Go Dart Group Server...")
	server := NewDartGroupServer()
	
	go server.StartUDP(9000)
	go server.StartTCP(9001)
	go server.StartWS(9002)
	
	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	fmt.Println("Shutting down...")
}
