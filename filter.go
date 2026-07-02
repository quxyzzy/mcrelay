package main

import "strings"

var defaultBlockedServices = []string{
	"_matter._tcp",
	"_matterc._udp",
	"_meshcop._udp",
	"_srp-tls._tcp",
	"_trel._udp",
}

type serviceFilter struct {
	blocked map[string]struct{}
}

func newServiceFilter(blocked []string) *serviceFilter {
	m := make(map[string]struct{}, len(blocked))
	for _, s := range blocked {
		m[strings.ToLower(s)] = struct{}{}
	}
	return &serviceFilter{blocked: m}
}

func (f *serviceFilter) isBlocked(serviceType string) bool {
	if f == nil || len(f.blocked) == 0 {
		return false
	}
	_, ok := f.blocked[strings.ToLower(serviceType)]
	return ok
}
