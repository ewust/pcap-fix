package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/gopacket/pcap"
	"github.com/klauspost/compress/zstd"
)

// GlobalHeader is the 24-byte pcap file header
type GlobalHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     int32
	SigFigs      uint32
	SnapLen      uint32
	Network      uint32
}

// PacketHeader is the 16-byte per-packet header
type PacketHeader struct {
	TsSec   uint32
	TsUsec  uint32
	CapLen  uint32
	OrigLen uint32
}

// wraps io.Writer, counts bytes written
type CountingWriter struct {
	w     io.Writer
	count int64
}

func (cw *CountingWriter) Write(p []byte) (n int, err error) {
	n, err = cw.w.Write(p)
	cw.count += int64(n)
	return n, err
}

// clampCapLen ensures we never write/read beyond snaplen or buffer size.
func clampCapLen(capLen uint32, snapLen uint32, bufLen int) uint32 {
	if capLen > snapLen {
		capLen = snapLen
	}
	if capLen > uint32(bufLen) {
		capLen = uint32(bufLen)
	}
	return capLen
}

// validity checks: avoid unsigned underflow and enforce usec range
func validHeader(lastHdr, curHdr PacketHeader, allowedDelta uint) bool {
	if curHdr.TsUsec >= 1_000_000 {
		return false
	}
	// allow up to 1s backward (avoid uint underflow)
	if curHdr.TsSec+1 < lastHdr.TsSec {
		return false
	}
	// and up to allowedDelta seconds forward
	if curHdr.TsSec > lastHdr.TsSec+uint32(allowedDelta) {
		return false
	}
	return true
}

type result struct {
	inPath         string
	outPath        string
	bytesRead      int64
	bytesWrote     int64
	fixes          int // -1 on failure
	stillCorrupted int // 1 if verify failed or on error; else 0
	err            error
}

// derive output filename: <outdir>/<base>.<suffix>
func deriveOutPath(inPath, suffix, outdir string) string {
	base := filepath.Base(inPath)
	ext := filepath.Ext(base)
	baseNoExt := strings.TrimSuffix(base, ext)
	if baseNoExt == "" {
		baseNoExt = base // just in case
	}
	return filepath.Join(outdir, baseNoExt+"."+suffix)
}

// choose a unique temp path alongside final path
func uniqueTempPath(finalPath string) string {
	p := finalPath + ".tmp"
	if _, err := os.Stat(p); os.IsNotExist(err) {
		return p
	}
	for i := 1; ; i++ {
		cand := fmt.Sprintf("%s.tmp.%d", finalPath, i)
		if _, err := os.Stat(cand); os.IsNotExist(err) {
			return cand
		}
	}
}

// Decompress a zstd file to a temp file; return temp path and decompressed size.
func decompressZstdToTemp(inPath string) (string, int64, error) {
	f, err := os.Open(inPath)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	dec, err := zstd.NewReader(f)
	if err != nil {
		return "", 0, fmt.Errorf("zstd: %w", err)
	}
	defer dec.Close()

	tmp, err := os.CreateTemp("", "pcapfix-decompressed-*.pcap")
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = tmp.Close() }()

	n, err := io.Copy(tmp, dec)
	if err != nil {
		_ = os.Remove(tmp.Name())
		return "", 0, err
	}
	if err := tmp.Sync(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", 0, err
	}
	return tmp.Name(), n, nil
}

// Verify a pcap by opening it with libpcap and reading to EOF.
// Returns 0 if OK, 1 if any error occurs.
func verifyPcap(path string) (int, error) {
	h, err := pcap.OpenOffline(path)
	if err != nil {
		return 1, err
	}
	defer h.Close()

	for {
		_, _, err := h.ReadPacketData()
		if err == io.EOF {
			return 0, nil
		}
		if err != nil {
			return 1, err
		}
	}
}

// processOne repairs a single PCAP, returning stats.
// If compression == "zstd", it first decompresses to a temp file and parses that.
// Writes to a temp output; promotes to final only when fixes > 0.
// If verify==true and fixes>0, verifies the fixed file; sets stillCorrupted accordingly.
// On any error, fixes = -1 and stillCorrupted = 1. Output is discarded.
func processOne(inPath, suffix, outdir, compression string, allowedDelta uint, verify bool) result {
	res := result{inPath: inPath, outPath: deriveOutPath(inPath, suffix, outdir)}
	tmpOut := uniqueTempPath(res.outPath)

	var wrote int64
	var read int64
	fixes := 0

	// open source for reading/seeking
	var srcPath string
	var decompTmp string
	var totalSize int64

	// Choose input path: decompressed temp or original
	if compression == "zstd" {
		tmp, n, err := decompressZstdToTemp(inPath)
		if err != nil {
			res.err = err
			res.fixes = -1
			res.stillCorrupted = 1 // error path → mark corrupted
			return res
		}
		decompTmp = tmp
		srcPath = decompTmp
		totalSize = n
		fmt.Printf("[%s] Decompressed (zstd) to %s, %d bytes\n", inPath, decompTmp, totalSize)
	} else {
		srcPath = inPath
		fi, err := os.Stat(srcPath)
		if err != nil {
			res.err = err
			res.fixes = -1
			res.stillCorrupted = 1
			return res
		}
		totalSize = fi.Size()
	}

	// Ensure decompressed temp is cleaned up
	defer func() {
		if decompTmp != "" {
			_ = os.Remove(decompTmp)
		}
	}()

	// Open input (possibly decompressed)
	f, err := os.Open(srcPath)
	if err != nil {
		res.err = err
		res.fixes = -1
		res.stillCorrupted = 1
		return res
	}
	defer f.Close()

	fmt.Printf("[%s] File is %d bytes\n", inPath, totalSize)
	reader := bufio.NewReader(f)

	// Create temp output (always write temp; decide later to keep)
	outf, err := os.Create(tmpOut)
	if err != nil {
		res.err = err
		res.fixes = -1
		res.stillCorrupted = 1
		return res
	}
	defer outf.Close()
	countingWriter := &CountingWriter{w: outf}
	writer := bufio.NewWriter(countingWriter)
	defer writer.Flush()

	// Detect endianness via peeked magic
	peek4, err := reader.Peek(4)
	if err != nil {
		res.err = fmt.Errorf("unable to read magic number: %w", err)
		res.fixes = -1
		res.stillCorrupted = 1
		_ = os.Remove(tmpOut)
		return res
	}
	magicLE := binary.LittleEndian.Uint32(peek4)
	magicBE := binary.BigEndian.Uint32(peek4)
	const (
		magicUsec = 0xa1b2c3d4
		magicNsec = 0xa1b23c4d
	)
	var byteOrder binary.ByteOrder
	switch {
	case magicLE == magicUsec || magicLE == magicNsec:
		byteOrder = binary.LittleEndian
		fmt.Printf("[%s] Little endian\n", inPath)
	case magicBE == magicUsec || magicBE == magicNsec:
		byteOrder = binary.BigEndian
		fmt.Printf("[%s] Big endian\n", inPath)
	default:
		res.err = fmt.Errorf("unknown magic number bytes: % x", peek4)
		res.fixes = -1
		res.stillCorrupted = 1
		_ = os.Remove(tmpOut)
		return res
	}

	// Read global header
	var gh GlobalHeader
	if err := binary.Read(reader, byteOrder, &gh); err != nil {
		res.err = err
		res.fixes = -1
		res.stillCorrupted = 1
		_ = os.Remove(tmpOut)
		return res
	}
	fmt.Printf("[%s] PCAP Version %d.%d, SnapLen=%d, Network=%d\n",
		inPath, gh.VersionMajor, gh.VersionMinor, gh.SnapLen, gh.Network)

	// Write global header to output
	if err := binary.Write(writer, byteOrder, gh); err != nil {
		res.err = err
		res.fixes = -1
		res.stillCorrupted = 1
		_ = os.Remove(tmpOut)
		return res
	}

	first := true
	var lastHdr PacketHeader
	lastPkt := make([]byte, int(gh.SnapLen)) // safe buffer sized to SnapLen

	read = 24 // sizeof(GlobalHeader)

	// Iterate over packets
	for {
		var ph PacketHeader
		if err := binary.Read(reader, byteOrder, &ph); err != nil {
			if err == io.EOF {
				// write final cached packet if any
				if !first {
					capToWrite := clampCapLen(lastHdr.CapLen, gh.SnapLen, len(lastPkt))
					lastHdr.CapLen = capToWrite
					if err := binary.Write(writer, byteOrder, lastHdr); err != nil {
						res.err = err
						res.fixes = -1
						res.stillCorrupted = 1
						_ = os.Remove(tmpOut)
						return res
					}
					if _, err := writer.Write(lastPkt[:capToWrite]); err != nil {
						res.err = err
						res.fixes = -1
						res.stillCorrupted = 1
						_ = os.Remove(tmpOut)
						return res
					}
					if err := writer.Flush(); err != nil {
						res.err = err
						res.fixes = -1
						res.stillCorrupted = 1
						_ = os.Remove(tmpOut)
						return res
					}
				}
				// success EOF
				wrote = countingWriter.count
				fmt.Printf("[%s] Finished, read %d bytes, wrote %d bytes (%.5f%%), fixed %d corruptions\n",
					inPath, read, wrote, 100*float64(wrote)/float64(read), fixes)

				// Decide whether to keep
				if fixes > 0 {
					_ = os.Remove(res.outPath) // best-effort (Windows)
					if err := os.Rename(tmpOut, res.outPath); err != nil {
						res.err = fmt.Errorf("rename failed: %w", err)
						res.fixes = -1
						res.stillCorrupted = 1
						_ = os.Remove(tmpOut)
						return res
					}
					// Verify fixed file if requested
					if verify {
						sc, vErr := verifyPcap(res.outPath)
						res.stillCorrupted = sc
						if vErr != nil {
							fmt.Fprintf(os.Stderr, "[%s] verify error: %v\n", inPath, vErr)
						}
					}
				} else {
					_ = os.Remove(tmpOut) // zero fixes → discard
					// No fixes → per spec, skip verification; mark 0
					res.stillCorrupted = 0
				}

				res.bytesRead = read
				res.bytesWrote = wrote
				res.fixes = fixes
				return res
			}
			// other read error
			res.err = err
			res.fixes = -1
			res.stillCorrupted = 1
			_ = os.Remove(tmpOut)
			return res
		}

		// plausibility check
		if !first && !validHeader(lastHdr, ph, allowedDelta) {
			fmt.Printf("[%s] bad header, %d bytes in (%.3f%%) Ts=%d, Us=%d\n",
				inPath, read, (100 * float64(read) / float64(totalSize)),
				ph.TsSec, ph.TsUsec)

			// rewind to start of previous payload
			read -= int64(lastHdr.CapLen)
			if _, err := f.Seek(read, io.SeekStart); err != nil {
				res.err = err
				res.fixes = -1
				res.stillCorrupted = 1
				_ = os.Remove(tmpOut)
				return res
			}
			reader = bufio.NewReader(f)

			// walk forward
			walked := 0
			for {
				if _, err := reader.ReadByte(); err != nil {
					res.err = err
					res.fixes = -1
					res.stillCorrupted = 1
					_ = os.Remove(tmpOut)
					return res
				}
				walked++

				peekData, err := reader.Peek(16) // sizeof(PacketHeader)
				if err != nil {
					res.err = err
					res.fixes = -1
					res.stillCorrupted = 1
					_ = os.Remove(tmpOut)
					return res
				}
				peekReader := bytes.NewReader(peekData)
				if err = binary.Read(peekReader, byteOrder, &ph); err != nil {
					res.err = err
					res.fixes = -1
					res.stillCorrupted = 1
					_ = os.Remove(tmpOut)
					return res
				}

				if validHeader(lastHdr, ph, allowedDelta) {
					fmt.Printf("[%s] Back on track, skipped %d bytes (was %d).\n",
						inPath, walked, lastHdr.CapLen)

					if _, err := reader.Discard(16); err != nil {
						res.err = err
						res.fixes = -1
						res.stillCorrupted = 1
						_ = os.Remove(tmpOut)
						return res
					}

					// Cap previous packet length to walked bytes, then to snaplen/buf
					newCap := uint32(walked)
					if newCap > lastHdr.CapLen {
						newCap = lastHdr.CapLen
					}
					newCap = clampCapLen(newCap, gh.SnapLen, len(lastPkt))
					lastHdr.CapLen = newCap

					read += int64(walked)
					fixes++
					break
				}

				if walked > 10000 {
					fmt.Printf("[%s] Didn't re-align, giving up...\n", inPath)
					res.err = fmt.Errorf("realignment exceeded 10000 bytes")
					res.fixes = -1
					res.stillCorrupted = 1
					_ = os.Remove(tmpOut)
					return res
				}
			}
		}

		if !first {
			// write cached previous packet (clamped)
			capToWrite := clampCapLen(lastHdr.CapLen, gh.SnapLen, len(lastPkt))
			lastHdr.CapLen = capToWrite
			if err := binary.Write(writer, byteOrder, lastHdr); err != nil {
				res.err = err
				res.fixes = -1
				res.stillCorrupted = 1
				_ = os.Remove(tmpOut)
				return res
			}
			if _, err := writer.Write(lastPkt[:capToWrite]); err != nil {
				res.err = err
				res.fixes = -1
				res.stillCorrupted = 1
				_ = os.Remove(tmpOut)
				return res
			}
		}

		// read current packet payload
		read += 16 // sizeof(PacketHeader)

		// only keep up to snaplen in memory; discard the rest
		keep := clampCapLen(ph.CapLen, gh.SnapLen, len(lastPkt))
		if keep > 0 {
			if _, err := io.ReadFull(reader, lastPkt[:keep]); err != nil {
				res.err = err
				res.fixes = -1
				res.stillCorrupted = 1
				_ = os.Remove(tmpOut)
				return res
			}
		}
		if extra := int64(ph.CapLen) - int64(keep); extra > 0 {
			if _, err := io.CopyN(io.Discard, reader, extra); err != nil {
				res.err = err
				res.fixes = -1
				res.stillCorrupted = 1
				_ = os.Remove(tmpOut)
				return res
			}
		}

		first = false
		lastHdr = ph // retain original header; we clamp on write
		// lastPkt already holds up to 'keep' bytes
		read += int64(ph.CapLen)
	}
}

// -------- TSV LOGGING (single goroutine) --------

type logLine struct {
	in             string
	out            string
	read           int64
	wrote          int64
	fixes          int
	stillCorrupted int
}

func logger(logPath string, lines <-chan logLine, wg *sync.WaitGroup) {
	defer wg.Done()

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to open log %q: %v\n", logPath, err)
		for range lines {
		}
		return
	}
	defer f.Close()

	needHeader := false
	if fi, err := f.Stat(); err == nil && fi.Size() == 0 {
		needHeader = true
	}
	if needHeader {
		if _, err := fmt.Fprintln(f, "origin_pcap_filename\tfixed_pcap_filename\tbytes_read\tbytes_wrote\tfixes\tstill_corrupted"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to write header to %q: %v\n", logPath, err)
		}
	}

	for ln := range lines {
		if _, err := fmt.Fprintf(f, "%s\t%s\t%d\t%d\t%d\t%d\n", ln.in, ln.out, ln.read, ln.wrote, ln.fixes, ln.stillCorrupted); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to append to %q: %v\n", logPath, err)
		}
	}
}

// -------- glob expansion --------

func expandArgs(args []string) ([]string, error) {
	var files []string
	for _, a := range args {
		matches, err := filepath.Glob(a)
		if err != nil {
			return nil, fmt.Errorf("bad glob %q: %w", a, err)
		}
		if len(matches) == 0 {
			// literal file path is allowed
			if _, err := os.Stat(a); err == nil {
				files = append(files, a)
			} else {
				fmt.Fprintf(os.Stderr, "warning: pattern %q matched nothing and is not a file\n", a)
			}
			continue
		}
		files = append(files, matches...)
	}
	return files, nil
}

func main() {
	var suffix string
	flag.StringVar(&suffix, "suffix", "fixed.pcap", "Suffix for output files (produces <base>.<suffix>)")

	var outdir string
	flag.StringVar(&outdir, "outdir", ".", "Directory for output files (will be created if missing)")

	var allowedDelta uint
	flag.UintVar(&allowedDelta, "delta", 10, "Allowed time difference between subsequent packets, in seconds")

	var logfn string
	flag.StringVar(&logfn, "log", "pcap-fix.log", "Append TSV summary to this log file")

	var workers int
	flag.IntVar(&workers, "worker", 20, "Number of concurrent workers")

	var compression string
	flag.StringVar(&compression, "compression", "", `Compression of inputs (supported: "zstd"). Leave empty for none.`)

	// Verification flag (default true). Also accept misspelled alias --verfiy.
	var verify bool
	flag.BoolVar(&verify, "verify", true, "Verify fixed files with pcap library; only when fixes>0 or on error")
	flag.BoolVar(&verify, "verfiy", true, "Alias for --verify")

	flag.Parse()

	// positional args are inputs
	pos := flag.Args()
	if len(pos) == 0 {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] <pcap paths or globs...>\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
		os.Exit(1)
	}

	// validate compression
	switch compression {
	case "", "zstd":
	default:
		fmt.Fprintf(os.Stderr, "unsupported --compression=%q (only \"zstd\" or empty)\n", compression)
		os.Exit(1)
	}

	// ensure outdir exists
	if err := os.MkdirAll(outdir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create outdir %q: %v\n", outdir, err)
		os.Exit(1)
	}

	inputs, err := expandArgs(pos)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "no input files found")
		os.Exit(1)
	}
	fmt.Printf("Discovered %d input file(s)\n", len(inputs))

	// logger
	lines := make(chan logLine, len(inputs))
	var logWG sync.WaitGroup
	logWG.Add(1)
	go logger(logfn, lines, &logWG)

	// jobs/results
	jobs := make(chan string, len(inputs))
	var wg sync.WaitGroup

	// spawn workers
	if workers < 1 {
		workers = 1
	}
	if workers > len(inputs) {
		workers = len(inputs)
	}
	fmt.Printf("Starting %d worker(s); outdir=%s; suffix=%s; compression=%s; verify=%v\n", workers, outdir, suffix, compression, verify)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				res := processOne(path, suffix, outdir, compression, allowedDelta, verify)

				// send log line
				lines <- logLine{
					in:             res.inPath,
					out:            res.outPath, // may not exist if fixes<=0 or failed
					read:           res.bytesRead,
					wrote:          res.bytesWrote,
					fixes:          res.fixes,
					stillCorrupted: res.stillCorrupted,
				}

				if res.err != nil {
					fmt.Fprintf(os.Stderr, "[%s] ERROR: %v\n", path, res.err)
				} else if res.fixes == 0 {
					fmt.Printf("[%s] No fixes; output discarded.\n", path)
				} else {
					// fixes > 0
					if res.stillCorrupted == 0 {
						fmt.Printf("[%s] Wrote fixed file: %s (fixes=%d, verified OK)\n", path, res.outPath, res.fixes)
					} else {
						fmt.Printf("[%s] Wrote fixed file: %s (fixes=%d) BUT verification failed\n", path, res.outPath, res.fixes)
					}
				}
			}
		}()
	}

	// enqueue
	for _, f := range inputs {
		jobs <- f
	}
	close(jobs)

	// wait for workers
	wg.Wait()

	// finalize logger
	close(lines)
	logWG.Wait()

	fmt.Println("All done.")
}
