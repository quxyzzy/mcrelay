package main

import "testing"

func TestServiceFilter_BlockedMatch(t *testing.T) {
	f := newServiceFilter([]string{"_matter._tcp"})
	if !f.isBlocked("_matter._tcp") {
		t.Fatal("expected _matter._tcp to be blocked")
	}
}

func TestServiceFilter_CaseInsensitive(t *testing.T) {
	f := newServiceFilter([]string{"_matter._tcp"})
	if !f.isBlocked("_Matter._TCP") {
		t.Fatal("expected case-insensitive match")
	}
}

func TestServiceFilter_NotBlocked(t *testing.T) {
	f := newServiceFilter([]string{"_matter._tcp"})
	if f.isBlocked("_googlecast._tcp") {
		t.Fatal("expected _googlecast._tcp to not be blocked")
	}
}

func TestServiceFilter_NilFilter(t *testing.T) {
	var f *serviceFilter
	if f.isBlocked("_matter._tcp") {
		t.Fatal("nil filter should not block anything")
	}
}

func TestServiceFilter_EmptyBlocklist(t *testing.T) {
	f := newServiceFilter([]string{})
	if f.isBlocked("_matter._tcp") {
		t.Fatal("empty blocklist should not block anything")
	}
}

func TestDefaultBlockedServices(t *testing.T) {
	expected := map[string]bool{
		"_matter._tcp":  true,
		"_matterc._udp": true,
		"_meshcop._udp": true,
		"_srp-tls._tcp": true,
		"_trel._udp":    true,
	}
	for _, svc := range defaultBlockedServices {
		if !expected[svc] {
			t.Errorf("unexpected entry in defaultBlockedServices: %s", svc)
		}
		delete(expected, svc)
	}
	for svc := range expected {
		t.Errorf("missing entry in defaultBlockedServices: %s", svc)
	}
}
