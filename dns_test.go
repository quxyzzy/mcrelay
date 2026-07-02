package main

import (
	"testing"

	"github.com/miekg/dns"
)

func TestParseMDNS_ValidQuery(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("_googlecast._tcp.local.", dns.TypePTR)
	packed, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseMDNS(packed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(parsed.Question) != 1 {
		t.Fatalf("expected 1 question, got %d", len(parsed.Question))
	}
}

func TestParseMDNS_TooShort(t *testing.T) {
	_, err := parseMDNS([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for short payload")
	}
}

func TestMdnsServiceTypes_PTRQuery(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("_androidtvremote2._tcp.local.", dns.TypePTR)
	packed, _ := msg.Pack()
	parsed, _ := parseMDNS(packed)
	types := mdnsServiceTypes(parsed)
	for _, st := range types {
		if st == "_androidtvremote2._tcp" {
			return
		}
	}
	t.Fatalf("expected _androidtvremote2._tcp in %v", types)
}

func TestMdnsServiceTypes_SRVAnswer(t *testing.T) {
	msg := new(dns.Msg)
	msg.Response = true
	msg.Answer = []dns.RR{
		&dns.SRV{
			Hdr: dns.RR_Header{
				Name:   "MyTV._googlecast._tcp.local.",
				Rrtype: dns.TypeSRV,
				Class:  dns.ClassINET,
				Ttl:    120,
			},
			Target: "mytv.local.",
			Port:   8009,
		},
	}
	types := mdnsServiceTypes(msg)
	for _, st := range types {
		if st == "_googlecast._tcp" {
			return
		}
	}
	t.Fatalf("expected _googlecast._tcp in %v", types)
}

func TestMdnsServiceTypes_Deduplicated(t *testing.T) {
	msg := new(dns.Msg)
	msg.Question = []dns.Question{
		{Name: "_matter._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET},
		{Name: "_matter._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET},
	}
	types := mdnsServiceTypes(msg)
	if len(types) != 1 {
		t.Fatalf("expected 1 deduplicated entry, got %d: %v", len(types), types)
	}
}

func TestIsGoodbye_True(t *testing.T) {
	msg := new(dns.Msg)
	msg.Response = true
	msg.Answer = []dns.RR{
		&dns.PTR{
			Hdr: dns.RR_Header{
				Name:   "_googlecast._tcp.local.",
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			Ptr: "MyDevice._googlecast._tcp.local.",
		},
	}
	if !isGoodbye(msg) {
		t.Fatal("expected isGoodbye to return true")
	}
}

func TestIsGoodbye_False(t *testing.T) {
	msg := new(dns.Msg)
	msg.Response = true
	msg.Answer = []dns.RR{
		&dns.PTR{
			Hdr: dns.RR_Header{
				Name:   "_googlecast._tcp.local.",
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Ptr: "MyDevice._googlecast._tcp.local.",
		},
	}
	if isGoodbye(msg) {
		t.Fatal("expected isGoodbye to return false")
	}
}

func TestHasQUBit_True(t *testing.T) {
	msg := new(dns.Msg)
	msg.Question = []dns.Question{
		{Name: "_googlecast._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET | (1 << 15)},
	}
	if !hasQUBit(msg) {
		t.Fatal("expected hasQUBit to return true")
	}
}

func TestHasQUBit_False(t *testing.T) {
	msg := new(dns.Msg)
	msg.Question = []dns.Question{
		{Name: "_googlecast._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET},
	}
	if hasQUBit(msg) {
		t.Fatal("expected hasQUBit to return false")
	}
}
