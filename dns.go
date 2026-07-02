package main

import (
	"strings"

	"github.com/miekg/dns"
)

func parseMDNS(payload []byte) (*dns.Msg, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(payload); err != nil {
		return nil, err
	}
	return msg, nil
}

func mdnsServiceTypes(msg *dns.Msg) []string {
	seen := make(map[string]struct{})

	addFromName := func(name string) {
		st := extractServiceType(name)
		if st != "" {
			seen[st] = struct{}{}
		}
	}

	for _, q := range msg.Question {
		if q.Qtype == dns.TypePTR {
			addFromName(q.Name)
		}
	}

	for _, rrs := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range rrs {
			switch r := rr.(type) {
			case *dns.PTR:
				addFromName(r.Hdr.Name)
			case *dns.SRV:
				addFromName(r.Hdr.Name)
			case *dns.TXT:
				addFromName(r.Hdr.Name)
			}
		}
	}

	out := make([]string, 0, len(seen))
	for st := range seen {
		out = append(out, st)
	}
	return out
}

// extractServiceType pulls a service type like "_googlecast._tcp" from an
// mDNS name. Handles both bare service names ("_googlecast._tcp.local.")
// and instance names ("MyDevice._googlecast._tcp.local.").
func extractServiceType(name string) string {
	name = strings.TrimSuffix(name, ".")
	name = strings.TrimSuffix(name, ".local")
	parts := strings.Split(name, ".")
	// Find two consecutive labels both starting with '_'
	for i := 0; i < len(parts)-1; i++ {
		if strings.HasPrefix(parts[i], "_") && strings.HasPrefix(parts[i+1], "_") {
			return strings.ToLower(parts[i] + "." + parts[i+1])
		}
	}
	// Single underscore label (e.g. "_matter._tcp" where tcp has no underscore)
	for i := 0; i < len(parts)-1; i++ {
		if strings.HasPrefix(parts[i], "_") {
			return strings.ToLower(parts[i] + "." + parts[i+1])
		}
	}
	return ""
}

func isGoodbye(msg *dns.Msg) bool {
	if !msg.Response {
		return false
	}
	for _, rr := range msg.Answer {
		if rr.Header().Ttl == 0 {
			return true
		}
	}
	return false
}

func hasQUBit(msg *dns.Msg) bool {
	for _, q := range msg.Question {
		if q.Qclass&(1<<15) != 0 {
			return true
		}
	}
	return false
}

func isMDNSQuery(msg *dns.Msg) bool {
	return !msg.Response
}

func isMDNSResponse(msg *dns.Msg) bool {
	return msg.Response
}
