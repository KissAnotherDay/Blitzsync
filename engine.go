package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// TransferStats holds live progress and network throughput metrics.
type TransferStats struct {
	FilesCompleted int64
	FilesTotal     int64
	BytesProcessed int64
	BytesTotal     int64
	BytesSent      int64
	BytesReused    int64
	SpeedBps       float64       // Real-time connection speed in bytes/sec
	ETA            time.Duration // Estimated time remaining
	CurrentFile    string
}

type speedSample struct {
	at        time.Time
	wireBytes int64
	procBytes int64
}

// progressTracker emits live stats on a 150ms ticker using a 1.5s sliding window for smooth speed calculation.
type progressTracker struct {
	stats       *TransferStats
	currentFile atomic.Value
	wireCounter func() int64
	onProgress  func(TransferStats)
	stopCh      chan struct{}
	doneCh      chan struct{}
	stopOnce    sync.Once
}

func newProgressTracker(stats *TransferStats, wireCounter func() int64, onProgress func(TransferStats)) *progressTracker {
	if onProgress == nil {
		return nil
	}
	pt := &progressTracker{
		stats:       stats,
		wireCounter: wireCounter,
		onProgress:  onProgress,
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
	}
	pt.currentFile.Store("")

	go func() {
		defer close(pt.doneCh)
		ticker := time.NewTicker(150 * time.Millisecond)
		defer ticker.Stop()

		samples := []speedSample{{
			at:        time.Now(),
			wireBytes: wireCounter(),
			procBytes: atomic.LoadInt64(&stats.BytesProcessed),
		}}

		emit := func(now time.Time) {
			curWire := wireCounter()
			curProc := atomic.LoadInt64(&stats.BytesProcessed)
			samples = append(samples, speedSample{
				at:        now,
				wireBytes: curWire,
				procBytes: curProc,
			})

			// Retain ~1.5s window while keeping at least one baseline sample.
			cutoff := now.Add(-1500 * time.Millisecond)
			for len(samples) > 2 && samples[1].at.Before(cutoff) {
				samples = samples[1:]
			}

			dt := now.Sub(samples[0].at).Seconds()
			var speedBps, procBps float64
			if dt > 0 {
				if dw := curWire - samples[0].wireBytes; dw >= 0 {
					speedBps = float64(dw) / dt
				}
				if dp := curProc - samples[0].procBytes; dp >= 0 {
					procBps = float64(dp) / dt
				}
			}

			var eta time.Duration
			remaining := stats.BytesTotal - curProc
			if remaining > 0 && procBps > 0 {
				eta = time.Duration(float64(remaining)/procBps) * time.Second
			}

			curName, _ := pt.currentFile.Load().(string)
			onProgress(TransferStats{
				FilesCompleted: atomic.LoadInt64(&stats.FilesCompleted),
				FilesTotal:     stats.FilesTotal,
				BytesProcessed: curProc,
				BytesTotal:     stats.BytesTotal,
				BytesSent:      atomic.LoadInt64(&stats.BytesSent),
				BytesReused:    atomic.LoadInt64(&stats.BytesReused),
				SpeedBps:       speedBps,
				ETA:            eta,
				CurrentFile:    curName,
			})
		}

		for {
			select {
			case <-pt.stopCh:
				return
			case now := <-ticker.C:
				emit(now)
			}
		}
	}()

	return pt
}

func (pt *progressTracker) SetCurrentFile(name string) {
	if pt != nil {
		pt.currentFile.Store(name)
	}
}

func (pt *progressTracker) Stop(emitFinal bool) {
	if pt == nil {
		return
	}
	pt.stopOnce.Do(func() {
		close(pt.stopCh)
		<-pt.doneCh
		if emitFinal {
			curName, _ := pt.currentFile.Load().(string)
			pt.onProgress(TransferStats{
				FilesCompleted: atomic.LoadInt64(&pt.stats.FilesCompleted),
				FilesTotal:     pt.stats.FilesTotal,
				BytesProcessed: atomic.LoadInt64(&pt.stats.BytesProcessed),
				BytesTotal:     pt.stats.BytesTotal,
				BytesSent:      atomic.LoadInt64(&pt.stats.BytesSent),
				BytesReused:    atomic.LoadInt64(&pt.stats.BytesReused),
				SpeedBps:       0,
				ETA:            0,
				CurrentFile:    curName,
			})
		}
	})
}

// SafeJoin resolves a relative slash-separated path inside root and blocks directory traversal.
func SafeJoin(root, relSlashPath string) (string, error) {
	if relSlashPath == "" || relSlashPath == "." {
		return filepath.Clean(root), nil
	}
	cleaned := filepath.Clean(filepath.FromSlash(relSlashPath))
	if filepath.IsAbs(cleaned) || strings.HasPrefix(cleaned, "..") {
		return "", fmt.Errorf("unsafe path detected: %q", relSlashPath)
	}
	full := filepath.Join(root, cleaned)
	relCheck, err := filepath.Rel(root, full)
	if err != nil || strings.HasPrefix(relCheck, "..") {
		return "", fmt.Errorf("path traversal blocked: %q", relSlashPath)
	}
	return full, nil
}

// ScanPath walks a single file or directory tree and produces normalized FileMeta entries.
func ScanPath(root string) ([]FileMeta, bool, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, false, err
	}

	if !info.IsDir() {
		return []FileMeta{{
			RelPath: filepath.Base(root),
			Size:    info.Size(),
			ModTime: info.ModTime().UnixNano(),
			Mode:    uint32(info.Mode().Perm()),
			IsDir:   false,
		}}, true, nil
	}

	var files []FileMeta
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		// Ignore leftover temporary files from interrupted runs.
		if strings.HasSuffix(d.Name(), ".blitzsync.tmp") {
			return nil
		}
		// Skip symlinks for cross-platform safety.
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, FileMeta{
			RelPath: filepath.ToSlash(rel),
			Size:    fi.Size(),
			ModTime: fi.ModTime().UnixNano(),
			Mode:    uint32(fi.Mode().Perm()),
			IsDir:   d.IsDir(),
		})
		return nil
	})
	if err != nil {
		return nil, false, err
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].RelPath < files[j].RelPath
	})
	return files, false, nil
}

// ComputeBlockHashes computes parallel SHA-256 digests for every block of an existing file.
func ComputeBlockHashes(path string, blockSize int, workers int) ([][32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	if size == 0 {
		return nil, nil
	}

	numBlocks := int((size + int64(blockSize) - 1) / int64(blockSize))
	hashes := make([][32]byte, numBlocks)

	if workers < 1 {
		workers = 1
	}
	if workers > numBlocks {
		workers = numBlocks
	}

	var nextIdx atomic.Int64
	var firstErr atomic.Value
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, blockSize)
			for {
				if firstErr.Load() != nil {
					return
				}
				idx := int(nextIdx.Add(1) - 1)
				if idx >= numBlocks {
					return
				}
				offset := int64(idx) * int64(blockSize)
				toRead := blockSize
				if offset+int64(toRead) > size {
					toRead = int(size - offset)
				}
				n, readErr := f.ReadAt(buf[:toRead], offset)
				if readErr != nil && !errors.Is(readErr, io.EOF) {
					firstErr.CompareAndSwap(nil, readErr)
					return
				}
				hashes[idx] = sha256.Sum256(buf[:n])
			}
		}()
	}

	wg.Wait()
	if v := firstErr.Load(); v != nil {
		return nil, v.(error)
	}
	return hashes, nil
}

// BuildSyncPlan compares source metadata against local destination files and computes delta block hashes in parallel.
func BuildSyncPlan(destRoot string, singleFileMode bool, srcFiles []FileMeta, blockSize int, verifyAll bool, deleteExtra bool, workers int) ([]FilePlan, error) {
	if !singleFileMode {
		if err := os.MkdirAll(destRoot, 0o755); err != nil {
			return nil, err
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(destRoot), 0o755); err != nil {
			return nil, err
		}
	}

	plans := make([]FilePlan, len(srcFiles))
	expectedSet := make(map[string]struct{}, len(srcFiles))

	type deltaJob struct {
		planIdx  int
		destPath string
	}
	var deltaJobs []deltaJob

	for i, sf := range srcFiles {
		expectedSet[sf.RelPath] = struct{}{}
		destPath := destRoot
		if !singleFileMode {
			var err error
			destPath, err = SafeJoin(destRoot, sf.RelPath)
			if err != nil {
				return nil, err
			}
		}

		plan := FilePlan{
			FileID:  uint32(i + 1),
			RelPath: sf.RelPath,
			Size:    sf.Size,
			ModTime: sf.ModTime,
			Mode:    sf.Mode,
			IsDir:   sf.IsDir,
		}

		if sf.IsDir {
			if err := os.MkdirAll(destPath, 0o755); err != nil {
				return nil, err
			}
			plan.Action = ActionSkip
			plans[i] = plan
			continue
		}

		dfInfo, err := os.Stat(destPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				plan.Action = ActionFull
				plans[i] = plan
				continue
			}
			return nil, err
		}

		// Quick metadata match (tolerance 1ms for cross-filesystem timestamp rounding).
		timeDiff := sf.ModTime - dfInfo.ModTime().UnixNano()
		if timeDiff < 0 {
			timeDiff = -timeDiff
		}
		if !verifyAll && dfInfo.Size() == sf.Size && timeDiff <= int64(time.Millisecond) {
			plan.Action = ActionSkip
			plans[i] = plan
			continue
		}

		if dfInfo.Size() > 0 && sf.Size > 0 {
			plan.Action = ActionDelta
			plans[i] = plan
			deltaJobs = append(deltaJobs, deltaJob{planIdx: i, destPath: destPath})
		} else {
			plan.Action = ActionFull
			plans[i] = plan
		}
	}

	// Compute destination block hashes concurrently for candidate delta files.
	if len(deltaJobs) > 0 {
		var jobIdx atomic.Int64
		var firstErr atomic.Value
		var wg sync.WaitGroup
		numWorkers := workers
		if numWorkers > len(deltaJobs) {
			numWorkers = len(deltaJobs)
		}
		subWorkers := workers / numWorkers
		if subWorkers < 1 {
			subWorkers = 1
		}

		for w := 0; w < numWorkers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					if firstErr.Load() != nil {
						return
					}
					idx := int(jobIdx.Add(1) - 1)
					if idx >= len(deltaJobs) {
						return
					}
					job := deltaJobs[idx]
					hashes, err := ComputeBlockHashes(job.destPath, blockSize, subWorkers)
					if err != nil {
						firstErr.CompareAndSwap(nil, err)
						return
					}
					plans[job.planIdx].BlockHashes = hashes
				}
			}()
		}
		wg.Wait()
		if v := firstErr.Load(); v != nil {
			return nil, v.(error)
		}
	}

	// Optional deletion of extraneous files at destination.
	if deleteExtra && !singleFileMode {
		var dirsToRemove []string
		_ = filepath.WalkDir(destRoot, func(path string, d fs.DirEntry, err error) error {
			if err != nil || path == destRoot {
				return nil
			}
			rel, relErr := filepath.Rel(destRoot, path)
			if relErr != nil {
				return nil
			}
			relSlash := filepath.ToSlash(rel)
			if _, keep := expectedSet[relSlash]; !keep {
				if d.IsDir() {
					dirsToRemove = append(dirsToRemove, path)
				} else {
					_ = os.Remove(path)
				}
			}
			return nil
		})
		for i := len(dirsToRemove) - 1; i >= 0; i-- {
			_ = os.Remove(dirsToRemove[i])
		}
	}

	return plans, nil
}

// RunSender streams required files and blocks to the peer using a multi-threaded read/hash pipeline.
func RunSender(conn *Conn, srcRoot string, singleFileMode bool, plans []FilePlan, blockSize int, workers int, onProgress func(TransferStats)) error {
	var totalFiles, totalBytes int64
	for _, p := range plans {
		if !p.IsDir && p.Action != ActionSkip {
			totalFiles++
			totalBytes += p.Size
		}
	}

	stats := TransferStats{
		FilesTotal: totalFiles,
		BytesTotal: totalBytes,
	}

	tracker := newProgressTracker(&stats, conn.BytesWritten, onProgress)
	defer tracker.Stop(false)

	ackCh := make(chan FileAckMsg, 64)
	errCh := make(chan error, 1)

	// Reader goroutine for incoming FileAck / MsgDoneAck frames.
	go func() {
		for {
			msgType, payload, err := conn.ReadFrame()
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
			switch msgType {
			case MsgFileAck:
				ack, err := UnmarshalFileAck(payload)
				if err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
				ackCh <- *ack
			case MsgError:
				select {
				case errCh <- fmt.Errorf("remote error: %s", string(payload)):
				default:
				}
				return
			case MsgDoneAck:
				close(ackCh)
				return
			}
		}
	}()

	var ackWg sync.WaitGroup
	var ackErr atomic.Value

	ackWg.Add(1)
	go func() {
		defer ackWg.Done()
		for ack := range ackCh {
			if ack.Err != "" {
				ackErr.CompareAndSwap(nil, fmt.Errorf("remote verification failed for file %d: %s", ack.FileID, ack.Err))
			}
			atomic.AddInt64(&stats.FilesCompleted, 1)
		}
	}()

	for _, plan := range plans {
		if plan.IsDir || plan.Action == ActionSkip {
			continue
		}
		if v := ackErr.Load(); v != nil {
			return v.(error)
		}
		select {
		case err := <-errCh:
			return err
		default:
		}

		srcPath := srcRoot
		if !singleFileMode {
			var err error
			srcPath, err = SafeJoin(srcRoot, plan.RelPath)
			if err != nil {
				return err
			}
		}

		tracker.SetCurrentFile(plan.RelPath)
		if err := sendSingleFile(conn, srcPath, plan, blockSize, workers, &stats); err != nil {
			return err
		}
	}

	if err := conn.SendFrame(MsgDone, nil); err != nil {
		return err
	}

	doneWait := make(chan struct{})
	go func() {
		ackWg.Wait()
		close(doneWait)
	}()

	select {
	case err := <-errCh:
		return err
	case <-doneWait:
	}

	if v := ackErr.Load(); v != nil {
		return v.(error)
	}

	tracker.Stop(true)
	return nil
}

func sendSingleFile(conn *Conn, srcPath string, plan FilePlan, blockSize int, workers int, stats *TransferStats) error {
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()

	openMsg := FileOpenMsg{
		FileID:  plan.FileID,
		RelPath: plan.RelPath,
		Size:    plan.Size,
		ModTime: plan.ModTime,
		Mode:    plan.Mode,
		IsDir:   false,
		IsDelta: plan.Action == ActionDelta,
	}
	if err := conn.SendFrame(MsgFileOpen, openMsg.Marshal()); err != nil {
		return err
	}

	fullHasher := sha256.New()
	if plan.Size == 0 {
		var emptyHash [32]byte
		copy(emptyHash[:], fullHasher.Sum(nil))
		commit := FileCommitMsg{FileID: plan.FileID, FullSHA256: emptyHash}
		return conn.SendFrame(MsgFileCommit, commit.Marshal())
	}

	numBlocks := int((plan.Size + int64(blockSize) - 1) / int64(blockSize))
	if workers < 1 {
		workers = 1
	}
	if workers > numBlocks {
		workers = numBlocks
	}

	type blockResult struct {
		idx       int
		offset    int64
		data      []byte
		hash      [32]byte
		identical bool
		err       error
	}

	sem := make(chan struct{}, workers*2)
	resCh := make(chan blockResult, workers*2)

	// Dispatch parallel block readers & hashers.
	go func() {
		var wg sync.WaitGroup
		for i := 0; i < numBlocks; i++ {
			sem <- struct{}{}
			wg.Add(1)
			go func(blockIdx int) {
				defer wg.Done()
				defer func() { <-sem }()

				offset := int64(blockIdx) * int64(blockSize)
				toRead := blockSize
				if offset+int64(toRead) > plan.Size {
					toRead = int(plan.Size - offset)
				}

				buf := make([]byte, toRead)
				n, readErr := f.ReadAt(buf, offset)
				if readErr != nil && !errors.Is(readErr, io.EOF) {
					resCh <- blockResult{idx: blockIdx, err: readErr}
					return
				}
				buf = buf[:n]
				h := sha256.Sum256(buf)

				identical := false
				if plan.Action == ActionDelta && blockIdx < len(plan.BlockHashes) && plan.BlockHashes[blockIdx] == h {
					identical = true
				}

				resCh <- blockResult{
					idx:       blockIdx,
					offset:    offset,
					data:      buf,
					hash:      h,
					identical: identical,
				}
			}(i)
		}
		wg.Wait()
		close(resCh)
	}()

	// Reorder completed blocks in-flight so fullHasher computes exact sequential SHA-256 while streaming blocks.
	pending := make(map[int]blockResult)
	nextExpected := 0

	for res := range resCh {
		if res.err != nil {
			return res.err
		}
		pending[res.idx] = res

		for {
			ready, ok := pending[nextExpected]
			if !ok {
				break
			}
			delete(pending, nextExpected)
			nextExpected++

			fullHasher.Write(ready.data)
			blockLen := int64(len(ready.data))

			if ready.identical {
				copyMsg := BlockCopyMsg{
					FileID: plan.FileID,
					Offset: ready.offset,
					Length: int32(blockLen),
				}
				if err := conn.SendFrame(MsgBlockCopy, copyMsg.Marshal()); err != nil {
					return err
				}
				atomic.AddInt64(&stats.BytesReused, blockLen)
			} else {
				dataMsg := BlockDataMsg{
					FileID:  plan.FileID,
					Offset:  ready.offset,
					SHA256:  ready.hash,
					Payload: ready.data,
				}
				if err := conn.SendFrame(MsgBlockData, dataMsg.Marshal()); err != nil {
					return err
				}
				atomic.AddInt64(&stats.BytesSent, blockLen)
			}
			atomic.AddInt64(&stats.BytesProcessed, blockLen)
		}
	}

	var fullHash [32]byte
	copy(fullHash[:], fullHasher.Sum(nil))
	commit := FileCommitMsg{
		FileID:     plan.FileID,
		FullSHA256: fullHash,
	}
	return conn.SendFrame(MsgFileCommit, commit.Marshal())
}

// RunReceiver receives streamed blocks, verifies SHA-256 per block & per file, and commits atomically.
func RunReceiver(conn *Conn, destRoot string, singleFileMode bool, workers int, totalFiles int64, totalBytes int64, onProgress func(TransferStats)) error {
	if workers < 1 {
		workers = runtime.NumCPU()
	}

	stats := TransferStats{
		FilesTotal: totalFiles,
		BytesTotal: totalBytes,
	}
	tracker := newProgressTracker(&stats, conn.BytesRead, onProgress)
	defer tracker.Stop(false)

	type activeFile struct {
		finalPath string
		tmpPath   string
		tmpFile   *os.File
		oldFile   *os.File
		modTime   int64
		mode      uint32
		wg        sync.WaitGroup
		blockErr  atomic.Value
	}

	var filesMu sync.Mutex
	activeFiles := make(map[uint32]*activeFile)

	cleanupAll := func() {
		filesMu.Lock()
		defer filesMu.Unlock()
		for _, af := range activeFiles {
			af.wg.Wait()
			if af.oldFile != nil {
				_ = af.oldFile.Close()
			}
			if af.tmpFile != nil {
				_ = af.tmpFile.Close()
			}
			_ = os.Remove(af.tmpPath)
		}
	}

	type writeTask struct {
		af       *activeFile
		isCopy   bool
		offset   int64
		length   int32
		expected [32]byte
		payload  []byte
	}

	taskCh := make(chan writeTask, workers*4)
	var poolWg sync.WaitGroup

	for w := 0; w < workers; w++ {
		poolWg.Add(1)
		go func() {
			defer poolWg.Done()
			for task := range taskCh {
				func(t writeTask) {
					defer t.af.wg.Done()
					if t.af.blockErr.Load() != nil {
						return
					}
					if t.isCopy {
						if t.af.oldFile == nil {
							t.af.blockErr.CompareAndSwap(nil, errors.New("delta copy requested without existing base file"))
							return
						}
						buf := make([]byte, t.length)
						n, err := t.af.oldFile.ReadAt(buf, t.offset)
						if err != nil && !errors.Is(err, io.EOF) {
							t.af.blockErr.CompareAndSwap(nil, err)
							return
						}
						if _, err := t.af.tmpFile.WriteAt(buf[:n], t.offset); err != nil {
							t.af.blockErr.CompareAndSwap(nil, err)
							return
						}
						atomic.AddInt64(&stats.BytesReused, int64(n))
						atomic.AddInt64(&stats.BytesProcessed, int64(n))
						return
					}

					actual := sha256.Sum256(t.payload)
					if actual != t.expected {
						t.af.blockErr.CompareAndSwap(nil, fmt.Errorf("block SHA-256 mismatch at offset %d", t.offset))
						return
					}
					if _, err := t.af.tmpFile.WriteAt(t.payload, t.offset); err != nil {
						t.af.blockErr.CompareAndSwap(nil, err)
						return
					}
					blockLen := int64(len(t.payload))
					atomic.AddInt64(&stats.BytesSent, blockLen)
					atomic.AddInt64(&stats.BytesProcessed, blockLen)
				}(task)
			}
		}()
	}

	var commitWg sync.WaitGroup

	for {
		msgType, payload, err := conn.ReadFrame()
		if err != nil {
			close(taskCh)
			poolWg.Wait()
			commitWg.Wait()
			cleanupAll()
			return err
		}

		switch msgType {
		case MsgFileOpen:
			openMsg, err := UnmarshalFileOpen(payload)
			if err != nil {
				close(taskCh)
				poolWg.Wait()
				cleanupAll()
				return err
			}
			finalPath := destRoot
			if !singleFileMode {
				finalPath, err = SafeJoin(destRoot, openMsg.RelPath)
				if err != nil {
					close(taskCh)
					poolWg.Wait()
					cleanupAll()
					return err
				}
			}
			if err := os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
				close(taskCh)
				poolWg.Wait()
				cleanupAll()
				return err
			}

			tmpPath := fmt.Sprintf("%s.%d.blitzsync.tmp", finalPath, openMsg.FileID)
			tmpF, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o644)
			if err != nil {
				close(taskCh)
				poolWg.Wait()
				cleanupAll()
				return err
			}
			if openMsg.Size > 0 {
				if err := tmpF.Truncate(openMsg.Size); err != nil {
					_ = tmpF.Close()
					_ = os.Remove(tmpPath)
					close(taskCh)
					poolWg.Wait()
					cleanupAll()
					return err
				}
			}

			var oldF *os.File
			if openMsg.IsDelta {
				oldF, _ = os.Open(finalPath)
			}

			tracker.SetCurrentFile(openMsg.RelPath)

			filesMu.Lock()
			activeFiles[openMsg.FileID] = &activeFile{
				finalPath: finalPath,
				tmpPath:   tmpPath,
				tmpFile:   tmpF,
				oldFile:   oldF,
				modTime:   openMsg.ModTime,
				mode:      openMsg.Mode,
			}
			filesMu.Unlock()

		case MsgBlockData:
			bd, err := UnmarshalBlockData(payload)
			if err != nil {
				close(taskCh)
				poolWg.Wait()
				cleanupAll()
				return err
			}
			filesMu.Lock()
			af, ok := activeFiles[bd.FileID]
			filesMu.Unlock()
			if !ok {
				continue
			}
			af.wg.Add(1)
			taskCh <- writeTask{
				af:       af,
				isCopy:   false,
				offset:   bd.Offset,
				expected: bd.SHA256,
				payload:  bd.Payload,
			}

		case MsgBlockCopy:
			bc, err := UnmarshalBlockCopy(payload)
			if err != nil {
				close(taskCh)
				poolWg.Wait()
				cleanupAll()
				return err
			}
			filesMu.Lock()
			af, ok := activeFiles[bc.FileID]
			filesMu.Unlock()
			if !ok {
				continue
			}
			af.wg.Add(1)
			taskCh <- writeTask{
				af:     af,
				isCopy: true,
				offset: bc.Offset,
				length: bc.Length,
			}

		case MsgFileCommit:
			cm, err := UnmarshalFileCommit(payload)
			if err != nil {
				close(taskCh)
				poolWg.Wait()
				cleanupAll()
				return err
			}
			filesMu.Lock()
			af, ok := activeFiles[cm.FileID]
			delete(activeFiles, cm.FileID)
			filesMu.Unlock()
			if !ok {
				continue
			}

			commitWg.Add(1)
			go func(fileID uint32, f *activeFile, expectedFull [32]byte) {
				defer commitWg.Done()
				f.wg.Wait()

				if f.oldFile != nil {
					_ = f.oldFile.Close()
				}

				if v := f.blockErr.Load(); v != nil {
					_ = f.tmpFile.Close()
					_ = os.Remove(f.tmpPath)
					_ = conn.SendFrame(MsgFileAck, (&FileAckMsg{FileID: fileID, Err: v.(error).Error()}).Marshal())
					return
				}

				if err := f.tmpFile.Sync(); err != nil {
					_ = f.tmpFile.Close()
					_ = os.Remove(f.tmpPath)
					_ = conn.SendFrame(MsgFileAck, (&FileAckMsg{FileID: fileID, Err: err.Error()}).Marshal())
					return
				}

				// End-to-end full-file SHA-256 verification directly from disk before atomic rename.
				if _, err := f.tmpFile.Seek(0, io.SeekStart); err != nil {
					_ = f.tmpFile.Close()
					_ = os.Remove(f.tmpPath)
					_ = conn.SendFrame(MsgFileAck, (&FileAckMsg{FileID: fileID, Err: err.Error()}).Marshal())
					return
				}

				h := sha256.New()
				if _, err := io.CopyBuffer(h, f.tmpFile, make([]byte, 1024*1024)); err != nil {
					_ = f.tmpFile.Close()
					_ = os.Remove(f.tmpPath)
					_ = conn.SendFrame(MsgFileAck, (&FileAckMsg{FileID: fileID, Err: err.Error()}).Marshal())
					return
				}

				var actualFull [32]byte
				copy(actualFull[:], h.Sum(nil))
				if actualFull != expectedFull {
					_ = f.tmpFile.Close()
					_ = os.Remove(f.tmpPath)
					_ = conn.SendFrame(MsgFileAck, (&FileAckMsg{
						FileID: fileID,
						Err:    "full-file SHA-256 verification mismatch after disk write",
					}).Marshal())
					return
				}

				if err := f.tmpFile.Close(); err != nil {
					_ = os.Remove(f.tmpPath)
					_ = conn.SendFrame(MsgFileAck, (&FileAckMsg{FileID: fileID, Err: err.Error()}).Marshal())
					return
				}

				// On Windows, os.Rename fails if target exists unless removed first.
				if runtime.GOOS == "windows" {
					_ = os.Remove(f.finalPath)
				}
				if err := os.Rename(f.tmpPath, f.finalPath); err != nil {
					_ = os.Remove(f.tmpPath)
					_ = conn.SendFrame(MsgFileAck, (&FileAckMsg{FileID: fileID, Err: err.Error()}).Marshal())
					return
				}

				if f.mode != 0 && runtime.GOOS != "windows" {
					_ = os.Chmod(f.finalPath, os.FileMode(f.mode))
				}
				mtime := time.Unix(0, f.modTime)
				_ = os.Chtimes(f.finalPath, mtime, mtime)

				atomic.AddInt64(&stats.FilesCompleted, 1)
				_ = conn.SendFrame(MsgFileAck, (&FileAckMsg{FileID: fileID}).Marshal())
			}(cm.FileID, af, cm.FullSHA256)

		case MsgDone:
			close(taskCh)
			poolWg.Wait()
			commitWg.Wait()
			cleanupAll()
			tracker.Stop(true)
			return conn.SendFrame(MsgDoneAck, nil)
		}
	}
}
