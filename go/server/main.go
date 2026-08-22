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
	udpConn    *net.UDPConn
	codec      *core.Codec
	serverECDH *core.ECDH

	mu           sync.Mutex
	groups       map[uint16][]*Peer
	clientMap    map[uint16]map[uint16]*Peer
	peerIdentity map[string]uint16
	members      map[uint16]map[uint16][]byte // blind: public membership only
	creator      map[uint16]uint16            // first member (generates/rotates the key)
	messageCache map[uint16]map[uint16]map[uint32][]byte
	highestSeq   map[uint16]map[uint16]uint32

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

// cloneUDPAddr copies IP bytes. Go 1.15's ReadFromUDP aliases the syscall
// sockaddr (`IP: sa.Addr[0:]`), so storing raddr and reading another packet
// mutates the first peer's address. Rust copies SocketAddr; we must too.
func cloneUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	if a == nil {
		return nil
	}
	dup := *a
	if a.IP != nil {
		dup.IP = append(net.IP(nil), a.IP...)
	}
	return &dup
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
			UDPAddr: cloneUDPAddr(raddr),
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
				p.UDPAddr = cloneUDPAddr(peer.UDPAddr)
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
			// If the creator left, elect a successor (the smallest remaining
			// senderId) so key rotation continues after the creator is gone.
			if s.creator[convId] == senderId {
				if len(s.members[convId]) == 0 {
					delete(s.creator, convId)
				} else {
					successor := uint16(0xFFFF)
					for sid := range s.members[convId] {
						if sid < successor {
							successor = sid
						}
					}
					s.creator[convId] = successor
				}
			}
			// Last member gone: drop the room entirely so the next KeyReq
			// starts a fresh conversation (new creator, new epoch).
			if len(s.members[convId]) == 0 {
				delete(s.members, convId)
			}
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
		if out, err := s.codec.EncodeMemberInfo(info, transportKey, nil); err == nil {
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
	if actualPeer.PacketCount > 500 {
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
		_, hasBaseline := s.highestSeq[convId][senderId]
		currentHighest := s.highestSeq[convId][senderId]

		// Modular gap test: 0 = duplicate, >= SeqMod/2 = stale, 1 = exact next.
		// A fresh server (no baseline yet) treats the first packet as its
		// baseline so joining mid-conversation (even near a wrap) works.
		ahead := uint32(1)
		if hasBaseline {
			ahead = core.SeqDelta(currentHighest, seq)
		}

		// GC Cache: keep only the last 200 packets. The reference point is the
		// modularly-newer of the two, so pruning stays correct across a wrap.
		ref := seq
		if ahead >= core.SeqMod/2 {
			ref = currentHighest
		}
		for k := range s.messageCache[convId][senderId] {
			if core.SeqDelta(k, ref) > 200 {
				delete(s.messageCache[convId][senderId], k)
			}
		}

		// The server is blind (no group key / no member signing key), so it
		// does not originate NACKs; loss recovery happens through member-signed
		// NACKs, which the server repairs from cache or relays verbatim.
		if ahead > 0 && ahead < core.SeqMod/2 {
			s.highestSeq[convId][senderId] = seq
		}

		// copy group to release lock
		group := make([]*Peer, len(s.groups[convId]))
		copy(group, s.groups[convId])
		s.mu.Unlock()

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
		// If the recorded creator has no live transport peer any more (its
		// socket closed before a successor election), hand creatorship to the
		// incoming member so key rotation can start.
		if cid, ok := s.creator[req.ConvId]; ok {
			if _, alive := s.clientMap[req.ConvId][cid]; !alive {
				s.creator[req.ConvId] = req.SenderId
			}
		} else {
			s.creator[req.ConvId] = req.SenderId
		}
		// Last-writer-wins: a client reconnects with a fresh ECDH keypair on
		// every restart (UDP peers have no close event), so the roster binding
		// must follow the latest KeyReq or reconnects are locked out permanently.
		s.members[req.ConvId][req.SenderId] = req.ClientPubKey
		s.mu.Unlock()
		s.notifyMembers(req.ConvId)

	case core.TypeKeyShare, core.TypeChainShare:
		// Relay the (opaque, encrypted) key / ratchet-chain share to its target.
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
		} else {
			log.Printf("[Server] Dropping share: no peer for target %d conv %d", targetId, convId)
		}

	case core.TypeNack:
		nackStripped, ok := core.StripControlFrame(buf)
		if !ok {
			return
		}
		nack, err := core.ParseNack(nackStripped)
		if err != nil {
			return
		}

		s.mu.Lock()
		var missingFromServer []uint32
		var cacheMap map[uint32][]byte
		if s.messageCache[nack.ConvId] != nil {
			cacheMap = s.messageCache[nack.ConvId][nack.TargetId]
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
		targetPeer := s.clientMap[nack.ConvId][nack.TargetId]
		s.mu.Unlock()

		// Always relay the member-signed NACK to the target member (the data
		// sender): the cache repair alone cannot fix a receiver that also lost
		// the sender's ratchet-chain share, and only the sender can re-share it.
		if targetPeer != nil && targetPeer.ID != actualPeer.ID {
			s.sendToPeer(buf, targetPeer)
		} else if len(missingFromServer) > 0 {
			// Fall back to the group relay so any peer holding the messages
			// can act on it.
			for _, p := range group {
				if p.ID != actualPeer.ID {
					s.sendToPeer(buf, p)
				}
			}
		}

	case core.TypeSync:
		// The server is keyed into every SYNC (sender -> server). Verify before
		// relaying so a group member can't forge another member's SYNC.
		syncConvId := binary.BigEndian.Uint16(buf[1:3])
		syncSenderId := binary.BigEndian.Uint16(buf[3:5])
		var memberPub []byte
		s.mu.Lock()
		if s.members[syncConvId] != nil {
			memberPub = s.members[syncConvId][syncSenderId]
		}
		s.mu.Unlock()
		if memberPub == nil {
			return
		}
		key, err := core.PairwiseKey(s.serverECDH, memberPub)
		if err != nil {
			return
		}
		if _, ok := core.VerifyControlFrame(buf, key); !ok {
			return
		}

		s.mu.Lock()
		group := make([]*Peer, len(s.groups[syncConvId]))
		copy(group, s.groups[syncConvId])
		s.mu.Unlock()

		for _, p := range group {
			if p.ID != actualPeer.ID {
				s.sendToPeer(buf, p)
			}
		}

	case 0x06: // DictReset - keyed to the server; verify before relaying so a
		// group member can't forge another member's Dict-Reset.
		resetConvId := binary.BigEndian.Uint16(buf[1:3])
		resetSenderId := binary.BigEndian.Uint16(buf[3:5])
		var memberPub []byte
		s.mu.Lock()
		if s.members[resetConvId] != nil {
			memberPub = s.members[resetConvId][resetSenderId]
		}
		s.mu.Unlock()
		if memberPub == nil {
			return
		}
		key, err := core.PairwiseKey(s.serverECDH, memberPub)
		if err != nil {
			return
		}
		if _, ok := core.VerifyControlFrame(buf, key); !ok {
			return
		}

		s.mu.Lock()
		group := make([]*Peer, len(s.groups[resetConvId]))
		copy(group, s.groups[resetConvId])
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
