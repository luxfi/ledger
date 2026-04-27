// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ledger

import (
	"strings"
	"testing"
)

func TestChains_RegistryShape(t *testing.T) {
	chains := Chains()
	if len(chains) < 4 {
		t.Fatalf("Chains() returned %d entries, want at least 4 (lux, hanzo, zoo, pars)", len(chains))
	}
	// Sorted ascending by name — invariant we rely on for deterministic
	// output in audit + test artifacts.
	for i := 1; i < len(chains); i++ {
		if chains[i-1].Name >= chains[i].Name {
			t.Fatalf("Chains() not sorted: %q before %q", chains[i-1].Name, chains[i].Name)
		}
	}
}

func TestChains_LookupKnown(t *testing.T) {
	cases := []struct {
		name           string
		wantSLIP44     uint32
		wantEVMChainID uint64
		wantHRP        string
		wantCLA        uint8
	}{
		{"lux", 9000, EVMChainIDLuxMainnet, "lux", CLALux},
		{"hanzo", 60, EVMChainIDHanzoMainnet, "", CLAEVM},
		{"zoo", 60, EVMChainIDZooMainnet, "", CLAEVM},
		{"pars", 60, EVMChainIDParsMainnet, "", CLAEVM},
		// Case-insensitive lookup.
		{"LUX", 9000, EVMChainIDLuxMainnet, "lux", CLALux},
		{" Hanzo ", 60, EVMChainIDHanzoMainnet, "", CLAEVM},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Lookup(tc.name)
			if err != nil {
				t.Fatalf("Lookup(%q): %v", tc.name, err)
			}
			if c.SLIP44 != tc.wantSLIP44 {
				t.Errorf("SLIP44 = %d, want %d", c.SLIP44, tc.wantSLIP44)
			}
			if c.EVMChainID != tc.wantEVMChainID {
				t.Errorf("EVMChainID = %d, want %d", c.EVMChainID, tc.wantEVMChainID)
			}
			if c.HRP != tc.wantHRP {
				t.Errorf("HRP = %q, want %q", c.HRP, tc.wantHRP)
			}
			if c.CLA != tc.wantCLA {
				t.Errorf("CLA = %#x, want %#x", c.CLA, tc.wantCLA)
			}
		})
	}
}

func TestChains_LookupUnknown(t *testing.T) {
	cases := []string{"", "   ", "bitcoin", "ethereum", "liquidity"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Lookup(name); err == nil {
				t.Fatalf("Lookup(%q) returned nil error, want unknown-chain error", name)
			}
		})
	}
}

func TestBIP44Path_EVMCompatChains(t *testing.T) {
	cases := []struct {
		chainName string
		want      string
	}{
		{"hanzo", "m/44'/60'/0'/0/0"},
		{"zoo", "m/44'/60'/0'/0/0"},
		{"pars", "m/44'/60'/0'/0/0"},
	}
	for _, tc := range cases {
		t.Run(tc.chainName, func(t *testing.T) {
			c, err := Lookup(tc.chainName)
			if err != nil {
				t.Fatalf("Lookup(%q): %v", tc.chainName, err)
			}
			got := BIP44Path(c, 0, 0, 0)
			if got != tc.want {
				t.Fatalf("BIP44Path(%q) = %q, want %q", tc.chainName, got, tc.want)
			}
		})
	}
}

func TestBIP44Path_Lux(t *testing.T) {
	c, err := Lookup("lux")
	if err != nil {
		t.Fatalf("Lookup(lux): %v", err)
	}
	if got, want := BIP44Path(c, 0, 0, 0), "m/44'/9000'/0'/0/0"; got != want {
		t.Fatalf("BIP44Path(lux 0/0/0) = %q, want %q", got, want)
	}
	if got, want := BIP44Path(c, 1, 0, 5), "m/44'/9000'/1'/0/5"; got != want {
		t.Fatalf("BIP44Path(lux 1/0/5) = %q, want %q", got, want)
	}
}

func TestBIP44PathForName(t *testing.T) {
	got, err := BIP44PathForName("hanzo", 0, 0, 7)
	if err != nil {
		t.Fatal(err)
	}
	if want := "m/44'/60'/0'/0/7"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if _, err := BIP44PathForName("nope", 0, 0, 0); err == nil {
		t.Fatal("BIP44PathForName(nope): want unknown-chain error, got nil")
	}
}

func TestLuxNativePath(t *testing.T) {
	cases := []struct {
		account uint32
		want    string
	}{
		{0, "m/44'/9000'/0'"},
		{5, "m/44'/9000'/5'"},
	}
	for _, tc := range cases {
		got := LuxNativePath(tc.account)
		if got != tc.want {
			t.Errorf("LuxNativePath(%d) = %q, want %q", tc.account, got, tc.want)
		}
	}
}

func TestEVMPath(t *testing.T) {
	got := EVMPath(0, 0, 0)
	if want := "m/44'/60'/0'/0/0"; got != want {
		t.Fatalf("EVMPath(0,0,0) = %q, want %q", got, want)
	}
	got = EVMPath(2, 1, 17)
	if want := "m/44'/60'/2'/1/17"; got != want {
		t.Fatalf("EVMPath(2,1,17) = %q, want %q", got, want)
	}
}

func TestBIP44Path_RejectsZeroSLIP44(t *testing.T) {
	// A Chain with SLIP44=0 is not a real chain; deriving a path off it
	// would produce m/44'/0'/... which collides with the Bitcoin
	// reservation. Refuse silently — caller will fail closed.
	zero := Chain{Name: "broken", SLIP44: 0}
	if got := BIP44Path(zero, 0, 0, 0); got != "" {
		t.Fatalf("BIP44Path(zero) = %q, want empty (refused)", got)
	}
}

func TestEVMSiblingsShareKey(t *testing.T) {
	// All EVM-compat chains derive the *same* address from the *same*
	// hardware key — replay is prevented by chain_id in the EIP-155
	// payload, not by the derivation path. This invariant is load-
	// bearing: if we ever break it, multi-chain UX (a single Ledger
	// device serving all EVMs) regresses.
	hPath, err := BIP44PathForName("hanzo", 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	zPath, err := BIP44PathForName("zoo", 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	pPath, err := BIP44PathForName("pars", 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if hPath != zPath || zPath != pPath {
		t.Fatalf("EVM-compat siblings derived divergent paths: hanzo=%q zoo=%q pars=%q", hPath, zPath, pPath)
	}
	if !strings.HasPrefix(hPath, "m/44'/60'/") {
		t.Fatalf("EVM-compat path should start with m/44'/60'/, got %q", hPath)
	}
}

func TestEVMChainIDsDistinct(t *testing.T) {
	// EIP-155 replay protection requires distinct chain_ids per network.
	ids := []uint64{
		EVMChainIDLuxMainnet,
		EVMChainIDHanzoMainnet,
		EVMChainIDZooMainnet,
		EVMChainIDParsMainnet,
	}
	seen := map[uint64]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate EVM chain_id %d in registry", id)
		}
		seen[id] = true
	}
}

func TestSupportedNamesSorted(t *testing.T) {
	got := supportedNames()
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Fatalf("supportedNames() not sorted: %v", got)
		}
	}
}
