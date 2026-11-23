package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

var AppVersion = "1.0.0"

type Endpoint struct {
	IsRemote bool
	UserHost string
	Path     string
}

// ParseEndpoint distinguishes Windows drive paths (e.g. C:\data) from SSH specs (user@host:/data).
func ParseEndpoint(raw string) Endpoint {
	colonIdx := strings.IndexByte(raw, ':')
	if colonIdx == 1 && len(raw) >= 2 {
		c := raw[0]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return Endpoint{IsRemote: false, Path: raw}
		}
	}
	if colonIdx > 1 {
		hostPart := raw[:colonIdx]
		pathPart := raw[colonIdx+1:]
		if !strings.ContainsAny(hostPart, `/\`) && pathPart != "" {
			return Endpoint{
				IsRemote: true,
				UserHost: hostPart,
				Path:     pathPart,
			}
		}
	}
	return Endpoint{IsRemote: false, Path: raw}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `BlitzSync v%s - High-speed, multi-threaded, verified cross-platform file transfer

Usage:
  blitzsync [options] <source> <destination>

Examples:
  # Push folder from Windows to Linux using built-in high-speed native Go SSH
  blitzsync.exe -b 8192 -t 8 "C:\Media\Videos" server:/mnt/storage/videos

  # Specify an explicit SSH private key and custom port
  blitzsync.exe -i "C:\Users\me\.ssh\id_ed25519" -p 2222 "C:\Data" user@192.168.1.50:/srv/data

  # Pull folder from Linux to Windows
  blitzsync.exe -t 8 user@192.168.1.50:/mnt/storage/backups "D:\Backups"

Options:
  -t, --threads <int>       Number of parallel hashing & transfer workers (default: %d)
  -b, --block-size <int>    Block size in KB for delta sync and chunking (default: 1024)
  -i, --identity <string>   Path to SSH private key file (auto-reads ~/.ssh/config by default)
  -p, --port <int>          Remote SSH port (overrides ~/.ssh/config)
  -e, --ssh <string>        Optional external SSH binary command (uses built-in Go SSH if omitted)
      --remote-bin <string> Path to blitzsync binary on remote host (default: "blitzsync")
      --verify              Force full block-by-block SHA-256 comparison even if size & mtime match
      --delete              Delete extraneous files from destination directory
      --dry-run             Show sync plan without transferring or deleting files
  -v, --version             Print version and exit
  -h, --help                Show this help message
`, AppVersion, runtime.NumCPU())
}

func main() {
	var (
		threads     int
		blockSizeKB int
		keyPath     string
		sshPort     int
		sshCmd      string
		remoteBin   string
		verifyAll   bool
		deleteExtra bool
		dryRun      bool
		serverMode  bool
		showVersion bool
	)

	flag.IntVar(&threads, "t", runtime.NumCPU(), "")
	flag.IntVar(&threads, "threads", runtime.NumCPU(), "")
	flag.IntVar(&blockSizeKB, "b", 1024, "")
	flag.IntVar(&blockSizeKB, "block-size", 1024, "")
	flag.StringVar(&keyPath, "i", "", "")
	flag.StringVar(&keyPath, "identity", "", "")
	flag.IntVar(&sshPort, "p", 0, "")
	flag.IntVar(&sshPort, "port", 0, "")
	flag.StringVar(&sshCmd, "e", "", "")
	flag.StringVar(&sshCmd, "ssh", "", "")
	flag.StringVar(&remoteBin, "remote-bin", "blitzsync", "")
	flag.BoolVar(&verifyAll, "verify", false, "")
	flag.BoolVar(&deleteExtra, "delete", false, "")
	flag.BoolVar(&dryRun, "dry-run", false, "")
	flag.BoolVar(&serverMode, "server", false, "")
	flag.BoolVar(&showVersion, "v", false, "")
	flag.BoolVar(&showVersion, "version", false, "")
	flag.Usage = printUsage
	flag.Parse()

	if showVersion {
		fmt.Printf("blitzsync %s (%s/%s)\n", AppVersion, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	if serverMode {
		if err := runServer(); err != nil {
			fmt.Fprintf(os.Stderr, "blitzsync server error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) != 2 {
		printUsage()
		os.Exit(2)
	}

	if threads < 1 {
		threads = 1
	}
	if blockSizeKB < 16 {
		blockSizeKB = 16
	}
	blockSize := blockSizeKB * 1024

	src := ParseEndpoint(args[0])
	dst := ParseEndpoint(args[1])

	if src.IsRemote && dst.IsRemote {
		fmt.Fprintln(os.Stderr, "error: remote-to-remote transfers are not supported directly")
		os.Exit(2)
	}

	startTime := time.Now()

	if !src.IsRemote && !dst.IsRemote {
		if err := runLocalSync(src.Path, dst.Path, blockSize, threads, verifyAll, deleteExtra, dryRun); err != nil {
			fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
			os.Exit(1)
		}
	} else if !src.IsRemote && dst.IsRemote {
		if err := runRemotePush(src.Path, dst, keyPath, sshPort, sshCmd, remoteBin, blockSize, threads, verifyAll, deleteExtra, dryRun); err != nil {
			fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
			os.Exit(1)
		}
	} else {
		if err := runRemotePull(src, dst.Path, keyPath, sshPort, sshCmd, remoteBin, blockSize, threads, verifyAll, deleteExtra, dryRun); err != nil {
			fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Fprintf(os.Stderr, "\nCompleted in %s\n", time.Since(startTime).Round(time.Millisecond))
}

func openRemoteConnection(userHost, keyPath string, sshPort int, sshCmd, remoteBin string) (*Conn, func() error, error) {
	if strings.TrimSpace(sshCmd) == "" {
		return spawnNativeSSH(userHost, keyPath, sshPort, remoteBin)
	}
	return spawnExternalSSH(userHost, keyPath, sshPort, sshCmd, remoteBin)
}

func splitCommandArgs(cmd string) ([]string, error) {
	var args []string
	var cur strings.Builder
	var quote rune
	inToken := false

	for _, r := range cmd {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
			inToken = true
		case r == ' ' || r == '\t':
			if inToken {
				args = append(args, cur.String())
				cur.Reset()
				inToken = false
			}
		default:
			cur.WriteRune(r)
			inToken = true
		}
	}
	if quote != 0 {
		return nil, errors.New("unclosed quote in -e ssh command")
	}
	if inToken {
		args = append(args, cur.String())
	}
	return args, nil
}

func spawnExternalSSH(userHost, keyPath string, sshPort int, sshCmd, remoteBin string) (*Conn, func() error, error) {
	parts, err := splitCommandArgs(sshCmd)
	if err != nil || len(parts) == 0 {
		return nil, nil, errors.New("invalid external ssh command")
	}
	sshArgs := append([]string{}, parts[1:]...)
	if keyPath != "" {
		sshArgs = append(sshArgs, "-i", keyPath)
	}
	if sshPort > 0 {
		sshArgs = append(sshArgs, "-p", fmt.Sprintf("%d", sshPort))
	}
	sshArgs = append(sshArgs, "-T", userHost, remoteBin, "--server")

	cmd := exec.Command(parts[0], sshArgs...)
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("failed to start external ssh: %w", err)
	}
	return NewConn(stdout, stdin), cmd.Wait, nil
}

func runRemotePush(localSrc string, remoteDst Endpoint, keyPath string, sshPort int, sshCmd, remoteBin string, blockSize, threads int, verifyAll, deleteExtra, dryRun bool) error {
	srcFiles, singleFile, err := ScanPath(localSrc)
	if err != nil {
		return err
	}

	conn, closeConn, err := openRemoteConnection(remoteDst.UserHost, keyPath, sshPort, sshCmd, remoteBin)
	if err != nil {
		return err
	}
	defer func() { _ = closeConn() }()

	hello := HelloMsg{
		Version:     ProtocolVersion,
		Mode:        ModePush,
		BlockSize:   uint32(blockSize),
		Threads:     uint16(threads),
		VerifyAll:   verifyAll,
		DeleteExtra: deleteExtra,
		TargetPath:  remoteDst.Path,
	}
	if err := conn.SendFrame(MsgHello, hello.Marshal()); err != nil {
		return err
	}

	msgType, payload, err := conn.ReadFrame()
	if err != nil {
		return err
	}
	if msgType == MsgError {
		return fmt.Errorf("remote handshake error: %s", string(payload))
	}
	if msgType != MsgHelloAck {
		return fmt.Errorf("unexpected handshake response: %d", msgType)
	}

	if err := conn.SendFrame(MsgManifest, MarshalManifest(srcFiles)); err != nil {
		return err
	}

	msgType, payload, err = conn.ReadFrame()
	if err != nil {
		return err
	}
	if msgType == MsgError {
		return fmt.Errorf("remote planning error: %s", string(payload))
	}
	if msgType != MsgSyncPlan {
		return fmt.Errorf("expected MsgSyncPlan, got %d", msgType)
	}

	plans, err := UnmarshalSyncPlan(payload)
	if err != nil {
		return err
	}

	if dryRun {
		printDryRun(plans)
		_ = conn.SendFrame(MsgDone, nil)
		_, _, _ = conn.ReadFrame()
		return nil
	}

	return RunSender(conn, localSrc, singleFile, plans, blockSize, threads, printProgress)
}

func runRemotePull(remoteSrc Endpoint, localDst string, keyPath string, sshPort int, sshCmd, remoteBin string, blockSize, threads int, verifyAll, deleteExtra, dryRun bool) error {
	conn, closeConn, err := openRemoteConnection(remoteSrc.UserHost, keyPath, sshPort, sshCmd, remoteBin)
	if err != nil {
		return err
	}
	defer func() { _ = closeConn() }()

	hello := HelloMsg{
		Version:     ProtocolVersion,
		Mode:        ModePull,
		BlockSize:   uint32(blockSize),
		Threads:     uint16(threads),
		VerifyAll:   verifyAll,
		DeleteExtra: deleteExtra,
		TargetPath:  remoteSrc.Path,
	}
	if err := conn.SendFrame(MsgHello, hello.Marshal()); err != nil {
		return err
	}

	msgType, payload, err := conn.ReadFrame()
	if err != nil {
		return err
	}
	if msgType == MsgError {
		return fmt.Errorf("remote handshake error: %s", string(payload))
	}
	if msgType != MsgHelloAck || len(payload) < 1 {
		return fmt.Errorf("unexpected handshake response: %d", msgType)
	}
	singleFile := payload[0] != 0

	msgType, payload, err = conn.ReadFrame()
	if err != nil {
		return err
	}
	if msgType == MsgError {
		return fmt.Errorf("remote manifest error: %s", string(payload))
	}
	if msgType != MsgManifest {
		return fmt.Errorf("expected MsgManifest, got %d", msgType)
	}

	srcFiles, err := UnmarshalManifest(payload)
	if err != nil {
		return err
	}

	plans, err := BuildSyncPlan(localDst, singleFile, srcFiles, blockSize, verifyAll, deleteExtra, threads)
	if err != nil {
		return err
	}

	if dryRun {
		printDryRun(plans)
		_ = conn.SendFrame(MsgSyncPlan, MarshalSyncPlan(nil))
		_, _, _ = conn.ReadFrame()
		return nil
	}

	if err := conn.SendFrame(MsgSyncPlan, MarshalSyncPlan(plans)); err != nil {
		return err
	}

	var totalFiles, totalBytes int64
	for _, p := range plans {
		if !p.IsDir && p.Action != ActionSkip {
			totalFiles++
			totalBytes += p.Size
		}
	}

	return RunReceiver(conn, localDst, singleFile, threads, totalFiles, totalBytes, printProgress)
}

func runLocalSync(localSrc, localDst string, blockSize, threads int, verifyAll, deleteExtra, dryRun bool) error {
	srcFiles, singleFile, err := ScanPath(localSrc)
	if err != nil {
		return err
	}
	plans, err := BuildSyncPlan(localDst, singleFile, srcFiles, blockSize, verifyAll, deleteExtra, threads)
	if err != nil {
		return err
	}
	if dryRun {
		printDryRun(plans)
		return nil
	}

	r1, w1, err := os.Pipe()
	if err != nil {
		return err
	}
	r2, w2, err := os.Pipe()
	if err != nil {
		return err
	}
	senderConn := NewConn(r1, w2)
	receiverConn := NewConn(r2, w1)

	recvErrCh := make(chan error, 1)
	go func() {
		recvErrCh <- RunReceiver(receiverConn, localDst, singleFile, threads, 0, 0, nil)
	}()

	if err := RunSender(senderConn, localSrc, singleFile, plans, blockSize, threads, printProgress); err != nil {
		return err
	}
	return <-recvErrCh
}

func runServer() error {
	conn := NewConn(os.Stdin, os.Stdout)

	msgType, payload, err := conn.ReadFrame()
	if err != nil {
		return err
	}
	if msgType != MsgHello {
		return fmt.Errorf("expected MsgHello, got %d", msgType)
	}

	hello, err := UnmarshalHello(payload)
	if err != nil {
		_ = conn.SendFrame(MsgError, []byte(err.Error()))
		return err
	}
	if hello.Version != ProtocolVersion {
		errMsg := fmt.Sprintf("protocol version mismatch: local=%d remote=%d", ProtocolVersion, hello.Version)
		_ = conn.SendFrame(MsgError, []byte(errMsg))
		return errors.New(errMsg)
	}

	threads := int(hello.Threads)
	if threads < 1 {
		threads = runtime.NumCPU()
	}
	blockSize := int(hello.BlockSize)

	if hello.Mode == ModePush {
		if err := conn.SendFrame(MsgHelloAck, []byte{0}); err != nil {
			return err
		}

		msgType, payload, err := conn.ReadFrame()
		if err != nil {
			return err
		}
		if msgType != MsgManifest {
			return fmt.Errorf("expected MsgManifest, got %d", msgType)
		}
		srcFiles, err := UnmarshalManifest(payload)
		if err != nil {
			_ = conn.SendFrame(MsgError, []byte(err.Error()))
			return err
		}

		singleFile := false
		if len(srcFiles) == 1 && !srcFiles[0].IsDir {
			if st, statErr := os.Stat(hello.TargetPath); statErr == nil && !st.IsDir() {
				singleFile = true
			} else if !strings.HasSuffix(hello.TargetPath, "/") && !strings.HasSuffix(hello.TargetPath, `\`) {
				if _, statErr := os.Stat(hello.TargetPath); errors.Is(statErr, os.ErrNotExist) {
					singleFile = true
				}
			}
		}

		plans, err := BuildSyncPlan(hello.TargetPath, singleFile, srcFiles, blockSize, hello.VerifyAll, hello.DeleteExtra, threads)
		if err != nil {
			_ = conn.SendFrame(MsgError, []byte(err.Error()))
			return err
		}

		if err := conn.SendFrame(MsgSyncPlan, MarshalSyncPlan(plans)); err != nil {
			return err
		}

		return RunReceiver(conn, hello.TargetPath, singleFile, threads, 0, 0, nil)
	}

	// ModePull: server acts as sender.
	srcFiles, singleFile, err := ScanPath(hello.TargetPath)
	if err != nil {
		_ = conn.SendFrame(MsgError, []byte(err.Error()))
		return err
	}

	singleFlag := byte(0)
	if singleFile {
		singleFlag = 1
	}
	if err := conn.SendFrame(MsgHelloAck, []byte{singleFlag}); err != nil {
		return err
	}
	if err := conn.SendFrame(MsgManifest, MarshalManifest(srcFiles)); err != nil {
		return err
	}

	msgType, payload, err = conn.ReadFrame()
	if err != nil {
		return err
	}
	if msgType != MsgSyncPlan {
		return fmt.Errorf("expected MsgSyncPlan, got %d", msgType)
	}
	plans, err := UnmarshalSyncPlan(payload)
	if err != nil {
		return err
	}
	if len(plans) == 0 {
		return conn.SendFrame(MsgDoneAck, nil)
	}

	return RunSender(conn, hello.TargetPath, singleFile, plans, blockSize, threads, nil)
}

func printDryRun(plans []FilePlan) {
	for _, p := range plans {
		if p.IsDir {
			continue
		}
		switch p.Action {
		case ActionFull:
			fmt.Printf("[FULL ] %s (%d bytes)\n", p.RelPath, p.Size)
		case ActionDelta:
			fmt.Printf("[DELTA] %s (%d bytes)\n", p.RelPath, p.Size)
		}
	}
}

func formatBytes(b int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/GB)
	case b >= MB:
		return fmt.Sprintf("%.2f MB", float64(b)/MB)
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/KB)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func formatSpeed(bps float64) string {
	const (
		KB = 1024.0
		MB = 1024.0 * KB
		GB = 1024.0 * MB
	)
	switch {
	case bps >= GB:
		return fmt.Sprintf("%.2f GB/s", bps/GB)
	case bps >= MB:
		return fmt.Sprintf("%.1f MB/s", bps/MB)
	case bps >= KB:
		return fmt.Sprintf("%.1f KB/s", bps/KB)
	default:
		return fmt.Sprintf("%.0f B/s", bps)
	}
}

func formatETA(d time.Duration) string {
	if d <= 0 {
		return "--:--"
	}
	sec := int(d.Seconds())
	h := sec / 3600
	m := (sec % 3600) / 60
	s := sec % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm", h, m)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}

func truncateName(name string, maxLen int) string {
	if len(name) <= maxLen {
		return name
	}
	if maxLen <= 3 {
		return name[:maxLen]
	}
	return "..." + name[len(name)-(maxLen-3):]
}

func printProgress(s TransferStats) {
	var pct float64
	if s.BytesTotal > 0 {
		pct = float64(s.BytesProcessed) * 100.0 / float64(s.BytesTotal)
	} else if s.FilesTotal > 0 {
		pct = float64(s.FilesCompleted) * 100.0 / float64(s.FilesTotal)
	}
	if pct > 100 {
		pct = 100
	}

	const barWidth = 20
	filled := int(pct / 100.0 * barWidth)
	if filled > barWidth {
		filled = barWidth
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	reusedPart := ""
	if s.BytesReused > 0 {
		reusedPart = fmt.Sprintf(" | Reused %s", formatBytes(s.BytesReused))
	}

	fmt.Fprintf(os.Stderr, "\r[%s] %5.1f%% | %s/%s | %s%s | ETA %s | (%d/%d) %s\033[K",
		bar,
		pct,
		formatBytes(s.BytesProcessed),
		formatBytes(s.BytesTotal),
		formatSpeed(s.SpeedBps),
		reusedPart,
		formatETA(s.ETA),
		s.FilesCompleted,
		s.FilesTotal,
		truncateName(s.CurrentFile, 24),
	)
}
