package main

import (
	"bufio"
	"bytes"
	"flag"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// Config parameters
type Config struct {
	PcapFile string
	SrcIp    string
	SrcPort  int
	DstIp    string
	DstPort  int
}

// Datagram struct (each UDP packet)
type datagram struct {
	len_bytes     int
	buf           []byte
	next_interval time.Duration
}

// Parse command-line args
func parse_config(cfg *Config) {
	flag.StringVar(
		&cfg.PcapFile,
		"pcap_file",
		"",
		"path to pcap file",
	)

	flag.StringVar(
		&cfg.SrcIp,
		"src_ip",
		"",
		"source IP address",
	)

	flag.IntVar(
		&cfg.SrcPort,
		"src_port",
		0,
		"source port",
	)

	flag.StringVar(
		&cfg.DstIp,
		"dst_ip",
		"",
		"destination IP address",
	)

	flag.IntVar(
		&cfg.DstPort,
		"dst_port",
		0,
		"destination port",
	)

	// Parse flags
	flag.Parse()
}

func main() {
	// Parse config
	var cfg Config
	parse_config(&cfg)

	// Run tshark
	// Extract: unix timestamp, UDP length
	x := []string{
		"-r",
		cfg.PcapFile,
		"-T",
		"fields",
		"-e",
		"frame.time_epoch",
		"-e",
		"udp.length",
		"-E",
		"separator=,",
	}
	cmd := exec.Command("/usr/bin/tshark", x...)
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil {
		log.Fatalf("Error running tshark %v: %v", x, err)
	}

	// Parse output and load packets into array
	var datagrams []datagram
	scanner := bufio.NewScanner(&outb)
	var prev_timestamp time.Time
	for scanner.Scan() {
		// Parse line
		line := scanner.Text()
		x := strings.Split(line, ",")
		t := strings.Split(x[0], ".")
		unix_sec, _ := strconv.ParseInt(t[0], 10, 64)
		unix_ns, _ := strconv.ParseInt(t[1], 10, 64)
		timestamp := time.Unix(unix_sec, unix_ns)
		len_bytes, _ := strconv.ParseInt(x[1], 10, 64)

		// Add data
		var dg datagram
		dg.len_bytes = int(len_bytes)
		dg.buf = make([]byte, dg.len_bytes)
		if !prev_timestamp.IsZero() {
			dg.next_interval = timestamp.Sub(prev_timestamp)
		}
		datagrams = append(datagrams, dg)

		// Save timestamp for next datagram
		prev_timestamp = timestamp
	}

	log.Printf("Parsed %v packets", len(datagrams))

	// Start UDP server
	src := &net.UDPAddr{Port: cfg.SrcPort, IP: net.ParseIP(cfg.SrcIp)}
	dst := &net.UDPAddr{Port: cfg.DstPort, IP: net.ParseIP(cfg.DstIp)}
	conn, err := net.DialUDP("udp", src, dst)
	if err != nil {
		log.Fatalf("Error creating connection to client %v: %v", dst, err)
	}

	// Push bytes
	for _, dg := range datagrams {
		start := time.Now()
		conn.Write(dg.buf)
		sleep_time := dg.next_interval - time.Since(start)
		log.Printf("Sleeping %v --> %v", dg.next_interval, sleep_time)
		time.Sleep(sleep_time)
	}

}
