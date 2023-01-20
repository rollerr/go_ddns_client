package main

import (
	"fmt"
	"net"
	"testing"
)

func TestParseWANIP(t *testing.T) {
	testCases := []struct {
		input string
		want  string
	}{
		{"    inet 70.106.247.115/24 brd 70.106.247.255 scope global eth0", "70.106.247.115"},
	}
	for _, tc := range testCases {
		got := parseWANIPFromOutput(tc.input)
		if got != tc.want {
			t.Errorf("parseWANIPFromOutput(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

var lookupHost = net.LookupHost

func TestCheckIfDNSRecordNeedsUpdate(t *testing.T) {
	expectedAddresses := []string{"1.1.1.2"}
	// mock lookup
	lookupHost = func(domain string) ([]string, error) {
		return expectedAddresses, nil
	}
	testCases := []struct {
		currentIP string
		domain    string
		want      bool
	}{
		{currentIP: "1.1.1.1", domain: "google.com", want: false},
	}
	for _, tc := range testCases {
		expectedAddresses, err := lookupHost(tc.domain)
		if err != nil {
			fmt.Print(err)
		}

		got := checkIfDNSRecordNeedsUpdate(tc.currentIP, tc.domain)
		if got != tc.want {
			t.Errorf("Test failed")
		}
	}
}
