package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

const (
	ProtocolMagic   = "BZSC"
	ProtocolVersion = uint16(1)
	MaxFrameSize    = 64 * 1024 * 1024 // 64 MB safety cap per frame
)

// TransferMode defines the direction of synchronization.
type TransferMode uint8

const (
	ModePush TransferMode = 1 // Client -> Server
	ModePull TransferMode = 2 // Server -> Client
)

// MessageType identifies binary frames on the wire.
type MessageType uint8

const (
	MsgHello      MessageType = 1
	MsgHelloAck   MessageType = 2
	MsgManifest   MessageType = 3
	MsgSyncPlan   MessageType = 4
	MsgFileOpen   MessageType = 5
	MsgBlockData  MessageType = 6
	MsgBlockCopy  MessageType = 7
	MsgFileCommit MessageType = 8
	MsgFileAck    MessageType = 9
	MsgDone       MessageType = 10
	MsgDoneAck    MessageType = 11
	MsgError      MessageType = 12
)

// SyncAction tells the sender what to do for a specific file.
type SyncAction uint8

const (
	ActionSkip  SyncAction = 0
	ActionFull  SyncAction = 1
	ActionDelta SyncAction = 2
)

// Conn wraps a thread-safe framed binary connection with atomic wire byte counters.
type Conn struct {
	r            *bufio.Reader
	w            *bufio.Writer
	wMu          sync.Mutex
	bytesRead    atomic.Int64
	bytesWritten atomic.Int64
}

// NewConn initializes a buffered binary connection.
func NewConn(r io.Reader, w io.Writer) *Conn {
	return &Conn{
		r: bufio.NewReaderSize(r, 1024*1024),
		w: bufio.NewWriterSize(w, 1024*1024),
	}
}

// BytesRead returns total raw protocol bytes read from the underlying stream.
func (c *Conn) BytesRead() int64 {
	return c.bytesRead.Load()
}

// BytesWritten returns total raw protocol bytes written to the underlying stream.
func (c *Conn) BytesWritten() int64 {
	return c.bytesWritten.Load()
}

// SendFrame writes a single framed message atomically to the underlying stream.
func (c *Conn) SendFrame(msgType MessageType, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return fmt.Errorf("frame size %d exceeds maximum %d", len(payload), MaxFrameSize)
	}

	c.wMu.Lock()
	defer c.wMu.Unlock()

	var header [9]byte
	copy(header[0:4], ProtocolMagic)
	header[4] = byte(msgType)
	binary.LittleEndian.PutUint32(header[5:9], uint32(len(payload)))

	if _, err := c.w.Write(header[:]); err != nil {
		return err
	}
	c.bytesWritten.Add(int64(len(header)))

	if len(payload) > 0 {
		if _, err := c.w.Write(payload); err != nil {
			return err
		}
		c.bytesWritten.Add(int64(len(payload)))
	}
	return c.w.Flush()
}

// ReadFrame reads the next complete binary frame from the stream.
func (c *Conn) ReadFrame() (MessageType, []byte, error) {
	var header [9]byte
	if _, err := io.ReadFull(c.r, header[:]); err != nil {
		return 0, nil, err
	}
	c.bytesRead.Add(int64(len(header)))

	if string(header[0:4]) != ProtocolMagic {
		return 0, nil, errors.New("invalid protocol magic: corrupted stream or unexpected remote stdout output")
	}

	msgType := MessageType(header[4])
	length := binary.LittleEndian.Uint32(header[5:9])
	if length > MaxFrameSize {
		return 0, nil, fmt.Errorf("incoming frame size %d exceeds maximum %d", length, MaxFrameSize)
	}

	var payload []byte
	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(c.r, payload); err != nil {
			return 0, nil, err
		}
		c.bytesRead.Add(int64(len(payload)))
	}
	return msgType, payload, nil
}

// --- Payload Serialization Models ---

type HelloMsg struct {
	Version     uint16
	Mode        TransferMode
	BlockSize   uint32
	Threads     uint16
	VerifyAll   bool
	DeleteExtra bool
	TargetPath  string
}

func (m *HelloMsg) Marshal() []byte {
	buf := make([]byte, 0, 32+len(m.TargetPath))
	buf = binary.LittleEndian.AppendUint16(buf, m.Version)
	buf = append(buf, byte(m.Mode))
	buf = binary.LittleEndian.AppendUint32(buf, m.BlockSize)
	buf = binary.LittleEndian.AppendUint16(buf, m.Threads)
	buf = append(buf, boolToByte(m.VerifyAll), boolToByte(m.DeleteExtra))
	buf = appendString(buf, m.TargetPath)
	return buf
}

func UnmarshalHello(b []byte) (*HelloMsg, error) {
	if len(b) < 13 {
		return nil, errors.New("truncated HelloMsg")
	}
	m := &HelloMsg{
		Version:     binary.LittleEndian.Uint16(b[0:2]),
		Mode:        TransferMode(b[2]),
		BlockSize:   binary.LittleEndian.Uint32(b[3:7]),
		Threads:     binary.LittleEndian.Uint16(b[7:9]),
		VerifyAll:   b[9] != 0,
		DeleteExtra: b[10] != 0,
	}
	s, _, err := readString(b[11:])
	if err != nil {
		return nil, err
	}
	m.TargetPath = s
	return m, nil
}

type FileMeta struct {
	RelPath string // Always normalized with forward slashes '/'
	Size    int64
	ModTime int64 // Unix nanoseconds
	Mode    uint32
	IsDir   bool
}

func MarshalManifest(files []FileMeta) []byte {
	buf := make([]byte, 0, len(files)*64+4)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(files)))
	for _, f := range files {
		buf = appendString(buf, f.RelPath)
		buf = binary.LittleEndian.AppendUint64(buf, uint64(f.Size))
		buf = binary.LittleEndian.AppendUint64(buf, uint64(f.ModTime))
		buf = binary.LittleEndian.AppendUint32(buf, f.Mode)
		buf = append(buf, boolToByte(f.IsDir))
	}
	return buf
}

func UnmarshalManifest(b []byte) ([]FileMeta, error) {
	if len(b) < 4 {
		return nil, errors.New("truncated Manifest")
	}
	count := binary.LittleEndian.Uint32(b[0:4])
	pos := 4
	files := make([]FileMeta, 0, count)
	for i := uint32(0); i < count; i++ {
		rel, n, err := readString(b[pos:])
		if err != nil {
			return nil, err
		}
		pos += n
		if pos+21 > len(b) {
			return nil, errors.New("truncated FileMeta entry")
		}
		size := int64(binary.LittleEndian.Uint64(b[pos : pos+8]))
		mod := int64(binary.LittleEndian.Uint64(b[pos+8 : pos+16]))
		mode := binary.LittleEndian.Uint32(b[pos+16 : pos+20])
		isDir := b[pos+20] != 0
		pos += 21
		files = append(files, FileMeta{
			RelPath: rel,
			Size:    size,
			ModTime: mod,
			Mode:    mode,
			IsDir:   isDir,
		})
	}
	return files, nil
}

type FilePlan struct {
	FileID      uint32
	RelPath     string
	Size        int64
	ModTime     int64
	Mode        uint32
	IsDir       bool
	Action      SyncAction
	BlockHashes [][32]byte // Populated only when Action == ActionDelta
}

func MarshalSyncPlan(plans []FilePlan) []byte {
	buf := make([]byte, 0, len(plans)*64+4)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(plans)))
	for _, p := range plans {
		buf = binary.LittleEndian.AppendUint32(buf, p.FileID)
		buf = appendString(buf, p.RelPath)
		buf = binary.LittleEndian.AppendUint64(buf, uint64(p.Size))
		buf = binary.LittleEndian.AppendUint64(buf, uint64(p.ModTime))
		buf = binary.LittleEndian.AppendUint32(buf, p.Mode)
		buf = append(buf, boolToByte(p.IsDir), byte(p.Action))
		buf = binary.LittleEndian.AppendUint32(buf, uint32(len(p.BlockHashes)))
		for _, h := range p.BlockHashes {
			buf = append(buf, h[:]...)
		}
	}
	return buf
}

func UnmarshalSyncPlan(b []byte) ([]FilePlan, error) {
	if len(b) < 4 {
		return nil, errors.New("truncated SyncPlan")
	}
	count := binary.LittleEndian.Uint32(b[0:4])
	pos := 4
	plans := make([]FilePlan, 0, count)
	for i := uint32(0); i < count; i++ {
		if pos+4 > len(b) {
			return nil, errors.New("truncated FilePlan ID")
		}
		fileID := binary.LittleEndian.Uint32(b[pos : pos+4])
		pos += 4

		rel, n, err := readString(b[pos:])
		if err != nil {
			return nil, err
		}
		pos += n

		if pos+26 > len(b) {
			return nil, errors.New("truncated FilePlan metadata")
		}
		size := int64(binary.LittleEndian.Uint64(b[pos : pos+8]))
		mod := int64(binary.LittleEndian.Uint64(b[pos+8 : pos+16]))
		mode := binary.LittleEndian.Uint32(b[pos+16 : pos+20])
		isDir := b[pos+20] != 0
		action := SyncAction(b[pos+21])
		numHashes := binary.LittleEndian.Uint32(b[pos+22 : pos+26])
		pos += 26

		hashes := make([][32]byte, numHashes)
		for j := uint32(0); j < numHashes; j++ {
			if pos+32 > len(b) {
				return nil, errors.New("truncated block hash in SyncPlan")
			}
			copy(hashes[j][:], b[pos:pos+32])
			pos += 32
		}

		plans = append(plans, FilePlan{
			FileID:      fileID,
			RelPath:     rel,
			Size:        size,
			ModTime:     mod,
			Mode:        mode,
			IsDir:       isDir,
			Action:      action,
			BlockHashes: hashes,
		})
	}
	return plans, nil
}

type FileOpenMsg struct {
	FileID  uint32
	RelPath string
	Size    int64
	ModTime int64
	Mode    uint32
	IsDir   bool
	IsDelta bool
}

func (m *FileOpenMsg) Marshal() []byte {
	buf := make([]byte, 0, 32+len(m.RelPath))
	buf = binary.LittleEndian.AppendUint32(buf, m.FileID)
	buf = appendString(buf, m.RelPath)
	buf = binary.LittleEndian.AppendUint64(buf, uint64(m.Size))
	buf = binary.LittleEndian.AppendUint64(buf, uint64(m.ModTime))
	buf = binary.LittleEndian.AppendUint32(buf, m.Mode)
	buf = append(buf, boolToByte(m.IsDir), boolToByte(m.IsDelta))
	return buf
}

func UnmarshalFileOpen(b []byte) (*FileOpenMsg, error) {
	if len(b) < 6 {
		return nil, errors.New("truncated FileOpenMsg")
	}
	fileID := binary.LittleEndian.Uint32(b[0:4])
	rel, n, err := readString(b[4:])
	if err != nil {
		return nil, err
	}
	pos := 4 + n
	if pos+22 > len(b) {
		return nil, errors.New("truncated FileOpenMsg fields")
	}
	return &FileOpenMsg{
		FileID:  fileID,
		RelPath: rel,
		Size:    int64(binary.LittleEndian.Uint64(b[pos : pos+8])),
		ModTime: int64(binary.LittleEndian.Uint64(b[pos+8 : pos+16])),
		Mode:    binary.LittleEndian.Uint32(b[pos+16 : pos+20]),
		IsDir:   b[pos+20] != 0,
		IsDelta: b[pos+21] != 0,
	}, nil
}

type BlockDataMsg struct {
	FileID  uint32
	Offset  int64
	SHA256  [32]byte
	Payload []byte
}

func (m *BlockDataMsg) Marshal() []byte {
	buf := make([]byte, 44+len(m.Payload))
	binary.LittleEndian.PutUint32(buf[0:4], m.FileID)
	binary.LittleEndian.PutUint64(buf[4:12], uint64(m.Offset))
	copy(buf[12:44], m.SHA256[:])
	copy(buf[44:], m.Payload)
	return buf
}

func UnmarshalBlockData(b []byte) (*BlockDataMsg, error) {
	if len(b) < 44 {
		return nil, errors.New("truncated BlockDataMsg")
	}
	m := &BlockDataMsg{
		FileID:  binary.LittleEndian.Uint32(b[0:4]),
		Offset:  int64(binary.LittleEndian.Uint64(b[4:12])),
		Payload: b[44:],
	}
	copy(m.SHA256[:], b[12:44])
	return m, nil
}

type BlockCopyMsg struct {
	FileID uint32
	Offset int64
	Length int32
}

func (m *BlockCopyMsg) Marshal() []byte {
	var buf [16]byte
	binary.LittleEndian.PutUint32(buf[0:4], m.FileID)
	binary.LittleEndian.PutUint64(buf[4:12], uint64(m.Offset))
	binary.LittleEndian.PutUint32(buf[12:16], uint32(m.Length))
	return buf[:]
}

func UnmarshalBlockCopy(b []byte) (*BlockCopyMsg, error) {
	if len(b) < 16 {
		return nil, errors.New("truncated BlockCopyMsg")
	}
	return &BlockCopyMsg{
		FileID: binary.LittleEndian.Uint32(b[0:4]),
		Offset: int64(binary.LittleEndian.Uint64(b[4:12])),
		Length: int32(binary.LittleEndian.Uint32(b[12:16])),
	}, nil
}

type FileCommitMsg struct {
	FileID     uint32
	FullSHA256 [32]byte
}

func (m *FileCommitMsg) Marshal() []byte {
	var buf [36]byte
	binary.LittleEndian.PutUint32(buf[0:4], m.FileID)
	copy(buf[4:36], m.FullSHA256[:])
	return buf[:]
}

func UnmarshalFileCommit(b []byte) (*FileCommitMsg, error) {
	if len(b) < 36 {
		return nil, errors.New("truncated FileCommitMsg")
	}
	m := &FileCommitMsg{
		FileID: binary.LittleEndian.Uint32(b[0:4]),
	}
	copy(m.FullSHA256[:], b[4:36])
	return m, nil
}

type FileAckMsg struct {
	FileID uint32
	Err    string
}

func (m *FileAckMsg) Marshal() []byte {
	buf := make([]byte, 0, 6+len(m.Err))
	buf = binary.LittleEndian.AppendUint32(buf, m.FileID)
	buf = appendString(buf, m.Err)
	return buf
}

func UnmarshalFileAck(b []byte) (*FileAckMsg, error) {
	if len(b) < 6 {
		return nil, errors.New("truncated FileAckMsg")
	}
	fileID := binary.LittleEndian.Uint32(b[0:4])
	errMsg, _, err := readString(b[4:])
	if err != nil {
		return nil, err
	}
	return &FileAckMsg{FileID: fileID, Err: errMsg}, nil
}

// --- Helper Functions ---

func appendString(buf []byte, s string) []byte {
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(s)))
	return append(buf, s...)
}

func readString(b []byte) (string, int, error) {
	if len(b) < 2 {
		return "", 0, errors.New("truncated string length")
	}
	n := int(binary.LittleEndian.Uint16(b[0:2]))
	if len(b) < 2+n {
		return "", 0, errors.New("truncated string bytes")
	}
	return string(b[2 : 2+n]), 2 + n, nil
}

func boolToByte(v bool) byte {
	if v {
		return 1
	}
	return 0
}
