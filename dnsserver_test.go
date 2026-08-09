package main

import (
	"net"
	"testing"
)

// startFakeDNS runs a minimal UDP DNS server that answers every A query with
// answerIP and every other qtype with an empty (NOERROR, 0 answers) response.
// It exists so resolver tests can prove which server was actually queried
// without depending on the machine's real DNS. Returns its "host:port" and
// a channel receiving the qname of each query it served.
func startFakeDNS(t *testing.T, answerIP string) (string, <-chan string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	queries := make(chan string, 16)
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return // closed by cleanup
			}
			resp, qname := buildDNSResponse(buf[:n], answerIP)
			if resp == nil {
				continue
			}
			select {
			case queries <- qname:
			default:
			}
			pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String(), queries
}

// buildDNSResponse parses just enough of a DNS query to echo it back as an
// answer. Returns the response bytes and the queried name.
func buildDNSResponse(q []byte, answerIP string) ([]byte, string) {
	if len(q) < 12 {
		return nil, ""
	}
	// Walk the QNAME labels to find where the question ends.
	name := ""
	i := 12
	for i < len(q) && q[i] != 0 {
		l := int(q[i])
		if i+1+l > len(q) {
			return nil, ""
		}
		if name != "" {
			name += "."
		}
		name += string(q[i+1 : i+1+l])
		i += 1 + l
	}
	i++ // the zero-length root label
	if i+4 > len(q) {
		return nil, ""
	}
	qtype := int(q[i])<<8 | int(q[i+1])
	questionEnd := i + 4

	resp := make([]byte, 0, 64)
	resp = append(resp, q[0], q[1]) // transaction ID
	resp = append(resp, 0x81, 0x80) // QR=1, RD=1, RA=1, NOERROR
	resp = append(resp, 0x00, 0x01) // QDCOUNT=1
	if qtype == 1 {                 // A
		resp = append(resp, 0x00, 0x01) // ANCOUNT=1
	} else {
		resp = append(resp, 0x00, 0x00) // ANCOUNT=0 — e.g. the parallel AAAA probe
	}
	resp = append(resp, 0x00, 0x00, 0x00, 0x00) // NSCOUNT, ARCOUNT
	resp = append(resp, q[12:questionEnd]...)   // echo the question

	if qtype == 1 {
		ip := net.ParseIP(answerIP).To4()
		if ip == nil {
			return nil, ""
		}
		resp = append(resp, 0xc0, 0x0c)             // name pointer to offset 12
		resp = append(resp, 0x00, 0x01)             // TYPE=A
		resp = append(resp, 0x00, 0x01)             // CLASS=IN
		resp = append(resp, 0x00, 0x00, 0x00, 0x3c) // TTL=60
		resp = append(resp, 0x00, 0x04)             // RDLENGTH=4
		resp = append(resp, ip...)
	}
	return resp, name
}
