package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
    "bufio"
    "bytes"
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

func validHeader(lastHdr, curHdr PacketHeader) bool {

    // A valid header (relative to the last one)
    // is one that is within +/- 1 second of the last header,
    // and whose usecs are less than 1 million
    return (curHdr.TsSec > (lastHdr.TsSec - 1) && 
        curHdr.TsSec <= (lastHdr.TsSec + 1) &&
        curHdr.TsUsec < 1000000)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go file.pcap")
		return
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()

    // Read file info
    fileInfo, err := f.Stat()
    if err != nil {
        panic(err)
    }
    totalSize := fileInfo.Size()
    fmt.Printf("File is %d bytes\n", totalSize)

    reader := bufio.NewReader(f)

    // Create a writer (for the corrected pcap)
    w, err := os.Create("output.pcap")
    if err != nil {
        panic(err)
    }
    defer w.Close()
    writer := bufio.NewWriter(w)
    defer writer.Flush()


	// Read global header
	var gh GlobalHeader
	if err := binary.Read(reader, binary.LittleEndian, &gh); err != nil {
		panic(err)
	}

	// Detect endianness based on magic number
	var byteOrder binary.ByteOrder
	switch gh.MagicNumber {
	case 0xa1b2c3d4:
		byteOrder = binary.LittleEndian
        fmt.Println("Little endian")
	case 0xd4c3b2a1:
		byteOrder = binary.BigEndian
        fmt.Println("Big endian")
	default:
		panic(fmt.Sprintf("Unknown magic number: 0x%x", gh.MagicNumber))
	}

	fmt.Printf("PCAP Version %d.%d, SnapLen=%d, Network=%d\n",
		gh.VersionMajor, gh.VersionMinor, gh.SnapLen, gh.Network)

    // Write the header to our output, too
    if err := binary.Write(writer, byteOrder, gh); err != nil {
        panic(err)
    }
    

    var first = true
    var lastHdr PacketHeader
    lastPkt := make([]byte, gh.SnapLen)
    fixed := 0

    read := int64(24)  // Sizeof(GlobalHeader)
	// Iterate over packets
	for {

        //fmt.Printf("Offset: %d (%.3f%%) fixed: %d ",
        //            read, 100*float64(read)/float64(totalSize), fixed)
	

        // Try parsing this header
		var ph PacketHeader
        if err := binary.Read(reader, byteOrder, &ph); err != nil {
            if err == io.EOF {
                // Need to write lastHdr/lastPkt
                binary.Write(writer, byteOrder, lastHdr)
                writer.Write(lastPkt[:lastHdr.CapLen])

                fmt.Printf("Finished, read %d bytes\n", read)
                break
            }
            panic(err)
        }

        //fmt.Printf("read a packet, TsSec: %d read: %d\n", ph.TsSec, read)
        // Check if it's valid
        // maybe faster?
        //(ph.TsSec > (lastHdr.TsSec + 2) || ph.TsSec < lastHdr.TsSec) {
        if !first && !validHeader(lastHdr, ph) {

            // Not valid
            fmt.Printf("bad header, %d bytes in (%.3f%%) Ts=%d, Us=%d\n",
                        read, (100*float64(read)/float64(totalSize)),
                        ph.TsSec, ph.TsUsec)

            // Set file back to just after last header
            // which is where we are minus the last packet's payload length
            read -= int64(lastHdr.CapLen)
            _, err = f.Seek(read, os.SEEK_SET)
            if err != nil {
                panic(err)
            }
            // Restart our reader from here
            reader = bufio.NewReader(f)

            // Walk forward one byte at a time until we find a valid header
            walked := 0
            for {
                if _, err := reader.ReadByte(); err != nil {
                    panic(err)
                }
                walked += 1

                // Try parsing again from here
                peekData, err := reader.Peek(16) // Sizeof(PacketHeader)
                if err != nil {
                    panic(err)
                }
                peekReader := bytes.NewReader(peekData)
		        if err = binary.Read(peekReader, byteOrder, &ph); err != nil {
                    panic(err)
                }
	  
                // check if the header looks valid
                if validHeader(lastHdr, ph) {
                    // Valid
                    fmt.Printf("Back on track, skipped %d bytes (was %d).\n",
                            walked, lastHdr.CapLen)

                    reader.Discard(16)  // Skip this peeked (corrected) header

                    // Update lastHdr to have a CapLen = walked, since
                    // that's what it actually had. origLen can remain
                    lastHdr.CapLen = min(uint32(walked), lastHdr.CapLen)

                    //lastPkt = lastPkt[:walked]
                    copy(lastPkt, lastPkt[:walked])

                    // update what we've read (packet payload)
                    read += int64(walked)

                    fixed += 1

                    break
                }

                // Not valid...
                //fmt.Printf("%02x ts=%d offset=%d\n",
                //        b, ph.TsSec, read+int64(walked))

                if walked > 10000 {
                    fmt.Printf("\nDidn't re-align, giving up...\n")
                    return
                }
            }
        }


        if !first {
            // write lastHdr + lastPkt
            binary.Write(writer, byteOrder, lastHdr)
            writer.Write(lastPkt[:lastHdr.CapLen])
        }


        // Read ph
        read += 16  // sizeof(PacketHeader)

		packet := make([]byte, ph.CapLen)
		if _, err := io.ReadFull(reader, packet); err != nil {
			panic(err)
		}

        // Update lastHdr / lastPkt
        first = false
        lastHdr = ph

        copy(lastPkt, packet)

        read += int64(ph.CapLen)
	}
}

func handlePacket(hdr *PacketHeader, data []byte) {
	fmt.Printf("Packet: ts=%d.%06d caplen=%d origlen=%d\n",
		hdr.TsSec, hdr.TsUsec, hdr.CapLen, hdr.OrigLen)
	// For example, just print first few bytes
	/*if len(data) > 16 {
		fmt.Printf("  Data (first 16B): % x\n", data[:16])
	} else {
		fmt.Printf("  Data: % x\n", data)
	}*/
}

