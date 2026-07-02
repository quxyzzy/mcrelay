package main

import (
	"testing"

	"github.com/miekg/dns"
)

func TestFilterBlocksPacket(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("_matter._tcp.local.", dns.TypePTR)
	packed, _ := msg.Pack()
	parsed, err := parseMDNS(packed)
	if err != nil {
		t.Fatal(err)
	}
	types := mdnsServiceTypes(parsed)
	found := false
	for _, st := range types {
		if st == "_matter._tcp" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected _matter._tcp in service types, got %v", types)
	}
	f := newServiceFilter(defaultBlockedServices)
	for _, st := range types {
		if f.isBlocked(st) {
			return
		}
	}
	t.Fatal("expected filter to block _matter._tcp")
}

func TestFilterAllowsPacket(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("_googlecast._tcp.local.", dns.TypePTR)
	packed, _ := msg.Pack()
	parsed, err := parseMDNS(packed)
	if err != nil {
		t.Fatal(err)
	}
	types := mdnsServiceTypes(parsed)
	f := newServiceFilter(defaultBlockedServices)
	for _, st := range types {
		if f.isBlocked(st) {
			t.Fatalf("_googlecast._tcp should not be blocked")
		}
	}
}

func TestGoodbyeBypassesDedup(t *testing.T) {
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
	packed, _ := msg.Pack()
	parsed, err := parseMDNS(packed)
	if err != nil {
		t.Fatal(err)
	}
	if !isGoodbye(parsed) {
		t.Fatal("expected isGoodbye true for TTL=0 response")
	}
}

func TestQUBitDetection(t *testing.T) {
	msg := new(dns.Msg)
	msg.Question = []dns.Question{
		{
			Name:   "_androidtvremote2._tcp.local.",
			Qtype:  dns.TypePTR,
			Qclass: dns.ClassINET | (1 << 15),
		},
	}
	packed, _ := msg.Pack()
	parsed, err := parseMDNS(packed)
	if err != nil {
		t.Fatal(err)
	}
	if !hasQUBit(parsed) {
		t.Fatal("expected hasQUBit true")
	}
}
