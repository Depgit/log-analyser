package wireshark

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// IsPcap returns true if the first 4 bytes match a pcap or pcapng magic number.
func IsPcap(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	magic := string(data[:4])
	return magic == PcapMagicLE || magic == PcapMagicBE || magic == PcapngMagic
}

// FindTshark returns the path to tshark if it is installed, or an empty string.
func FindTshark() string {
	for _, candidate := range []string{"tshark", "/usr/bin/tshark", "/usr/local/bin/tshark", "/opt/homebrew/bin/tshark"} {
		if path, err := exec.LookPath(candidate); err == nil {
			return path
		}
	}
	return ""
}

// ParsePcapViaTshark converts a pcap/pcapng byte slice to Packets by shelling
// out to tshark and parsing its PDML output.
//
// tshark must be installed (ships with Wireshark).
// Install it with:
//
//	macOS:  brew install wireshark
//	Ubuntu: sudo apt install tshark
func ParsePcapViaTshark(data []byte) ([]Packet, error) {
	tshark := FindTshark()
	if tshark == "" {
		return nil, fmt.Errorf(
			"tshark not found — please install Wireshark (brew install wireshark) " +
				"so the server can convert .pcap/.pcapng files")
	}

	// We pipe the raw bytes into tshark's stdin using "-r -"
	// and ask it to emit PDML on stdout.
	cmd := exec.Command(tshark,
		"-r", "-", // read from stdin
		"-T", "pdml", // output as PDML
	)
	cmd.Stdin = bytes.NewReader(data)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("tshark failed: %s", msg)
	}

	return ParsePDML(&stdout)
}
