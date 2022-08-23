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
	"encoding/binary"

	log "github.com/sirupsen/logrus"
)

// Config parameters
type Config struct {
	PcapFile    string
	SrcIp       string
	SrcPort     int
	DstIp       string
	DstPort     int
	SrcIpFilter string
	DurationSec int
	Verbose     bool
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

	flag.StringVar(
		&cfg.SrcIpFilter,
		"src_ip_filter",
		"",
		"ip.src filter",
	)

	flag.IntVar(
		&cfg.DurationSec,
		"duration_sec",
		0,
		"duration to run app",
	)

	flag.BoolVar(
		&cfg.Verbose,
		"verbose",
		false,
		"print summary",
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
		// fmt.Sprintf("ip.src == %s", cfg.SrcIpFilter),
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
		if dg.len_bytes>1400 {
			dg.len_bytes=1400
		}
		dg.buf = make([]byte, dg.len_bytes)
		if !prev_timestamp.IsZero() {
			dg.next_interval = timestamp.Sub(prev_timestamp)
		}
		datagrams = append(datagrams, dg)

		// Save timestamp for next datagram
		prev_timestamp = timestamp
	}

	if cfg.Verbose {
		log.Printf("Parsed %v packets", len(datagrams))
	}

	// Start UDP server
	src := &net.UDPAddr{Port: cfg.SrcPort, IP: net.ParseIP(cfg.SrcIp)}
	dst := &net.UDPAddr{Port: cfg.DstPort, IP: net.ParseIP(cfg.DstIp)}
	conn, err := net.DialUDP("udp", src, dst)
	if err != nil {
		log.Fatalf("Error creating connection to client %v: %v", dst, err)
	}

	// Push bytes
	var packets_sent int
	var num_slow_packets int
	var sleep_time time.Duration
	var slow_time time.Duration
	send_start := time.Now()
	for _, dg := range datagrams {
		// if time.Since(send_start) >= time.Duration(cfg.DurationSec)*time.Second {
		// 	break
		// }
		start := time.Now()
		binary.LittleEndian.PutUint32(dg.buf, uint32(packets_sent))
		conn.Write(dg.buf)
		packets_sent++
		if sleep_time < 0 {
			sleep_time = dg.next_interval - time.Since(start) + sleep_time
		} else {
			sleep_time = dg.next_interval - time.Since(start)
		}
		if sleep_time < 0 {
			num_slow_packets++
			slow_time += -sleep_time
		}
		time.Sleep(sleep_time)
	}

	if cfg.Verbose {
		log.Printf("Sent %d/%d packets in %v", packets_sent, len(datagrams), time.Since(send_start))
		log.Printf("%d/%d slow packets; %v delay", num_slow_packets, packets_sent, slow_time)
	}
}