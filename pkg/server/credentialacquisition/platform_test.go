package credentialacquisition

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// recordedRule is the platform rule the Server applied in the recorded runs:
// Milan, Genoa and
// Turin with their TCB floors, the mitigation bits AMD names in its bulletins
// with bit 4 waived for Milan, ALIAS_CHECK_COMPLETE, SMT with the microcode
// floor, and the TD attributes refused.
func recordedRule() *PlatformRule {
	return &PlatformRule{
		SEVSNP: &SNPRule{
			AllowedProducts: []string{"Milan", "Genoa", "Turin"},
			TCBFloors: map[string]map[string]int{
				"Milan": {"bl": 4, "snp": 29, "ucode": 222},
				"Genoa": {"snp": 28, "ucode": 86},
				"Turin": {"snp": 5, "ucode": 81},
			},
			CheckCommittedTCB: true,
			SMT:               "allow-with-microcode-floor",
			RequiredMitigationBits: map[string]map[string]string{
				"Milan": {"1": "AMD-SB-3020 (CVE-2025-0033)", "4": "AMD-SB-3034 (CVE-2025-54510)"},
				"Genoa": {"1": "AMD-SB-3020 (CVE-2025-0033)"},
				"Turin": {"0": "AMD-SB-3020 (CVE-2025-0033)"},
			},
			RequiredPlatformInfoBits: map[string]map[string]string{
				"Milan": {"5": "AMD-SB-3015 (BadRAM, CVE-2024-21944): ALIAS_CHECK_COMPLETE"},
				"Genoa": {"5": "AMD-SB-3015 (BadRAM, CVE-2024-21944): ALIAS_CHECK_COMPLETE"},
			},
			MitigationWaivers: map[string]map[string]string{"Milan": {"4": "admitted without bit 4, AMD-SB-3034"}},
		},
		TDX: &TDXRule{AttributesRefused: "0x2000fff0"},
	}
}

func snpResult(h snpHost) *earResult {
	chip := h.chipID
	class := classByChip
	if h.byCSP {
		class = classByCSP
	}
	return &earResult{Submod: "SEVSNP", Measurement: h.measurement, SNP: &snpClaims{
		class: class, measurement: h.measurement, policy: h.policy, platformInfo: h.platformInfo,
		reportedTCB: h.reportedTCB, committedTCB: h.committedTCB, hasCPUID: !h.noCPUID, family: h.family, model: h.model,
		chipID: chip, launchMitVector: h.launchMit, currentMitVector: h.currentMit, hasMitVectors: !h.noMitVectors,
	}}
}

func TestPlatformRuleSEVSNP(t *testing.T) {
	rule := recordedRule()

	t.Run("the Milan host of the records, under the waiver of bit 4", func(t *testing.T) {
		waived, err := rule.Check(snpResult(gcpMilan()))
		require.NoError(t, err)
		require.Len(t, waived, 1)
		require.Contains(t, waived[0], "admitted without bit 4, AMD-SB-3034: Milan mitigation bit 4")
	})
	t.Run("a host with every bit set needs no waiver", func(t *testing.T) {
		h := gcpMilan()
		h.launchMit, h.currentMit = 0x1b, 0x1b
		waived, err := rule.Check(snpResult(h))
		require.NoError(t, err)
		require.Empty(t, waived)
	})
	for _, tt := range []struct {
		name   string
		mutate func(h *snpHost)
		rule   func(r *PlatformRule)
		err    string
	}{
		{name: "DEBUG", mutate: func(h *snpHost) { h.policy |= 1 << 19 }, err: "POLICY.DEBUG is set"},
		{name: "MIGRATE_MA", mutate: func(h *snpHost) { h.policy |= 1 << 18 }, err: "POLICY.MIGRATE_MA is set"},
		{name: "reserved policy bit", mutate: func(h *snpHost) { h.policy = 0x10000 }, err: "bit 17 must be one"},
		{name: "no CPUID", mutate: func(h *snpHost) { h.noCPUID = true }, err: "carries no CPUID"},
		{name: "product not admitted", mutate: func(h *snpHost) { h.family, h.model = 0x19, 0xA0 }, err: `product line "Siena"`},
		{name: "unknown product", mutate: func(h *snpHost) { h.family, h.model = 0x17, 0x00 }, err: "is not admitted"},
		{name: "reported TCB below the floor", mutate: func(h *snpHost) { h.reportedTCB = 0xDE1D000000000003 }, err: "REPORTED_TCB bl 3 is below the floor 4"},
		{name: "committed TCB below the floor", mutate: func(h *snpHost) { h.committedTCB = 0xDD1D000000000004 }, err: "COMMITTED_TCB ucode 221 is below the floor 222"},
		{name: "mitigation bit 1 missing at launch", mutate: func(h *snpHost) { h.launchMit = 0x9 }, err: "mitigation bit 1 (AMD-SB-3020 (CVE-2025-0033)) is not set in LAUNCH_MIT_VECTOR 0x9"},
		{name: "mitigation bit 1 missing now", mutate: func(h *snpHost) { h.currentMit = 0x9 }, err: "is not set in CURRENT_MIT_VECTOR 0x9"},
		{name: "no mitigation vectors", mutate: func(h *snpHost) { h.noMitVectors = true }, err: "carries no mitigation vector"},
		{name: "ALIAS_CHECK_COMPLETE not set", mutate: func(h *snpHost) { h.platformInfo = 0x05 }, err: "PLATFORM_INFO bit 5"},
		{name: "SMT forbidden", mutate: func(*snpHost) {}, rule: func(r *PlatformRule) { r.SEVSNP.SMT = "forbid" }, err: "SMT is enabled on the platform"},
		{name: "machine identity required", mutate: func(h *snpHost) { h.byCSP, h.chipID = true, nil }, rule: func(r *PlatformRule) { r.SEVSNP.RequireMachineIdentity = true }, err: "names no machine"},
		{name: "machine not listed", mutate: func(*snpHost) {}, rule: func(r *PlatformRule) {
			r.SEVSNP.AllowedChipIDs = []string{"ff" + string(make([]byte, 0)) + "ff" + repeatHex("00", 62)}
		}, err: "is not a listed machine"},
		{name: "no floor for the product", mutate: func(*snpHost) {}, rule: func(r *PlatformRule) { delete(r.SEVSNP.TCBFloors, "Milan") }, err: "no TCB floor is configured for Milan"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := gcpMilan()
			tt.mutate(&h)
			r := recordedRule()
			if tt.rule != nil {
				tt.rule(r)
			}
			_, err := r.Check(snpResult(h))
			require.ErrorIs(t, err, ErrPlatform)
			require.ErrorContains(t, err, tt.err)
		})
	}
	t.Run("no rule for the submodule", func(t *testing.T) {
		r := &PlatformRule{TDX: &TDXRule{}}
		_, err := r.Check(snpResult(gcpMilan()))
		require.ErrorContains(t, err, "no platform rule for SEV-SNP")
	})
	t.Run("no claims", func(t *testing.T) {
		_, err := rule.Check(&earResult{Submod: "SEVSNP"})
		require.ErrorContains(t, err, "no SEV-SNP claims")
	})
}

func repeatHex(s string, n int) string {
	out := ""
	for range n {
		out += s
	}
	return out
}

func TestPlatformRuleTDX(t *testing.T) {
	rule := recordedRule()
	ok := &earResult{Submod: "TDX", TDX: map[string]string{"td_attributes": "0000000010000000"}}
	_, err := rule.Check(ok)
	require.NoError(t, err)

	for _, tt := range []struct {
		name string
		attr string
		err  string
	}{
		{name: "debug", attr: "0000000010000001", err: "under debug"},
		{name: "refused bits", attr: "0000000020000000", err: "bits 20000000 are refused"},
		{name: "not hex", attr: "zz", err: "TD ATTRIBUTES"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := rule.Check(&earResult{Submod: "TDX", TDX: map[string]string{"td_attributes": tt.attr}})
			require.ErrorIs(t, err, ErrPlatform)
			require.ErrorContains(t, err, tt.err)
		})
	}
	_, err = rule.Check(&earResult{Submod: "TDX", TDX: map[string]string{}})
	require.ErrorContains(t, err, "annotated no TD ATTRIBUTES")
	_, err = rule.Check(&earResult{Submod: "OTHER"})
	require.ErrorContains(t, err, `no platform rule for submodule "OTHER"`)
}

func TestPlatformRuleLoadAndValidate(t *testing.T) {
	dir := t.TempDir()
	raw, err := json.Marshal(recordedRule())
	require.NoError(t, err)
	path := filepath.Join(dir, "rule.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	rule, err := loadPlatformRule(path)
	require.NoError(t, err)
	require.Equal(t, recordedRule(), rule)

	for _, tt := range []struct {
		name   string
		mutate func(r *PlatformRule)
		err    string
	}{
		{name: "smt", mutate: func(r *PlatformRule) { r.SEVSNP.SMT = "maybe" }, err: "sevsnp.smt"},
		{name: "unknown product floor", mutate: func(r *PlatformRule) { r.SEVSNP.TCBFloors["Rome"] = map[string]int{"snp": 1} }, err: "no TCB layout"},
		{name: "bad component", mutate: func(r *PlatformRule) { r.SEVSNP.TCBFloors["Milan"]["gpu"] = 1 }, err: "tcb_floors[Milan]"},
		{name: "bad bit", mutate: func(r *PlatformRule) { r.SEVSNP.RequiredMitigationBits["Milan"]["x"] = "?" }, err: "bit \"x\""},
		{name: "waiver of a bit not required", mutate: func(r *PlatformRule) { r.SEVSNP.MitigationWaivers["Milan"]["7"] = "no" }, err: "waived but not required"},
		{name: "chip id not hex", mutate: func(r *PlatformRule) { r.SEVSNP.AllowedChipIDs = []string{"zz"} }, err: "not 64 octets of hex"},
		{name: "td mask", mutate: func(r *PlatformRule) { r.TDX.AttributesRefused = "0xzz" }, err: "td_attributes_refused"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := recordedRule()
			tt.mutate(r)
			require.ErrorContains(t, r.Validate(), tt.err)
		})
	}
	_, err = loadPlatformRule(filepath.Join(dir, "missing.json"))
	require.Error(t, err)
}
