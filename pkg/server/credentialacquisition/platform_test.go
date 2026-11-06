package credentialacquisition

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// recordedSNPRule is the SEV-SNP entry of the platform rule the Server applied
// in the recorded runs: Milan, Genoa and Turin with their TCB floors, the
// mitigation bits AMD names in its bulletins with bit 4 waived for Milan,
// ALIAS_CHECK_COMPLETE, SMT with the microcode floor.
func recordedSNPRule() *SNPRule {
	return &SNPRule{
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
	}
}

// recordedTDXRule is the TDX entry of the recorded runs: the TD attributes
// refused.
func recordedTDXRule() *TDXRule { return &TDXRule{AttributesRefused: "0x2000fff0"} }

// testModules are the platform modules with the product data SPIRE ships.
func testModules(t *testing.T) []platformModule {
	modules, err := platformModules(&Config{})
	require.NoError(t, err)
	return modules
}

// ruleJSON writes the entries as the rule file holds them.
func ruleJSON(t *testing.T, snp *SNPRule, tdx *TDXRule) []byte {
	entries := map[string]any{}
	if snp != nil {
		entries["sevsnp"] = snp
	}
	if tdx != nil {
		entries["tdx"] = tdx
	}
	raw, err := json.Marshal(entries)
	require.NoError(t, err)
	return raw
}

// platformRuleOf parses the entries the way the rule file is read.
func platformRuleOf(t *testing.T, snp *SNPRule, tdx *TDXRule) *PlatformRule {
	rule, err := parsePlatformRule(ruleJSON(t, snp, tdx), testModules(t))
	require.NoError(t, err)
	return rule
}

// recordedRule is the platform rule of the recorded runs.
func recordedRule(t *testing.T) *PlatformRule {
	return platformRuleOf(t, recordedSNPRule(), recordedTDXRule())
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
	rule := recordedRule(t)

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
		rule   func(r *SNPRule)
		err    string
	}{
		{name: "DEBUG", mutate: func(h *snpHost) { h.policy |= 1 << 19 }, err: "POLICY.DEBUG is set"},
		{name: "MIGRATE_MA", mutate: func(h *snpHost) { h.policy |= 1 << 18 }, err: "POLICY.MIGRATE_MA is set"},
		{name: "reserved policy bit", mutate: func(h *snpHost) { h.policy = 0x10000 }, err: "bit 17 must be one"},
		{name: "no CPUID", mutate: func(h *snpHost) { h.noCPUID = true }, err: "carries no CPUID"},
		{name: "product not admitted", mutate: func(h *snpHost) { h.family, h.model = 0x19, 0xA0 }, err: `product line "Siena"`},
		{name: "product not in the product data", mutate: func(h *snpHost) { h.family, h.model = 0x17, 0x00 }, err: "names no product line of the product data"},
		{name: "reported TCB below the floor", mutate: func(h *snpHost) { h.reportedTCB = 0xDE1D000000000003 }, err: "REPORTED_TCB bl 3 is below the floor 4"},
		{name: "committed TCB below the floor", mutate: func(h *snpHost) { h.committedTCB = 0xDD1D000000000004 }, err: "COMMITTED_TCB ucode 221 is below the floor 222"},
		{name: "mitigation bit 1 missing at launch", mutate: func(h *snpHost) { h.launchMit = 0x9 }, err: "mitigation bit 1 (AMD-SB-3020 (CVE-2025-0033)) is not set in LAUNCH_MIT_VECTOR 0x9"},
		{name: "mitigation bit 1 missing now", mutate: func(h *snpHost) { h.currentMit = 0x9 }, err: "is not set in CURRENT_MIT_VECTOR 0x9"},
		{name: "no mitigation vectors", mutate: func(h *snpHost) { h.noMitVectors = true }, err: "carries no mitigation vector"},
		{name: "ALIAS_CHECK_COMPLETE not set", mutate: func(h *snpHost) { h.platformInfo = 0x05 }, err: "PLATFORM_INFO bit 5"},
		{name: "SMT forbidden", mutate: func(*snpHost) {}, rule: func(r *SNPRule) { r.SMT = "forbid" }, err: "SMT is enabled on the platform"},
		{name: "machine identity required", mutate: func(h *snpHost) { h.byCSP, h.chipID = true, nil }, rule: func(r *SNPRule) { r.RequireMachineIdentity = true }, err: "names no machine"},
		{name: "machine not listed", mutate: func(*snpHost) {}, rule: func(r *SNPRule) {
			r.AllowedChipIDs = []string{"ffff" + repeatHex("00", 62)}
		}, err: "is not a listed machine"},
		{name: "no floor for the product", mutate: func(*snpHost) {}, rule: func(r *SNPRule) { delete(r.TCBFloors, "Milan") }, err: "no TCB floor is configured for Milan"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := gcpMilan()
			tt.mutate(&h)
			snp := recordedSNPRule()
			if tt.rule != nil {
				tt.rule(snp)
			}
			_, err := platformRuleOf(t, snp, recordedTDXRule()).Check(snpResult(h))
			require.ErrorIs(t, err, ErrPlatform)
			require.ErrorContains(t, err, tt.err)
		})
	}
	t.Run("no entry for the family", func(t *testing.T) {
		_, err := platformRuleOf(t, nil, recordedTDXRule()).Check(snpResult(gcpMilan()))
		require.ErrorIs(t, err, ErrPlatform)
		require.ErrorContains(t, err, `no platform rule for submodule "SEVSNP"`)
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
	rule := recordedRule(t)
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
	modules := testModules(t)
	path := filepath.Join(dir, "rule.json")
	require.NoError(t, os.WriteFile(path, ruleJSON(t, recordedSNPRule(), recordedTDXRule()), 0o600))
	rule, err := loadPlatformRule(path, modules)
	require.NoError(t, err)
	require.Len(t, rule.bySubmodule, 2)
	snp, ok := rule.bySubmodule["SEVSNP"].(*SNPRule)
	require.True(t, ok)
	require.Equal(t, recordedSNPRule().TCBFloors, snp.TCBFloors)
	require.Equal(t, recordedTDXRule(), rule.bySubmodule["TDX"])

	for _, tt := range []struct {
		name   string
		mutate func(r *SNPRule)
		err    string
	}{
		{name: "smt", mutate: func(r *SNPRule) { r.SMT = "maybe" }, err: "sevsnp.smt"},
		{name: "a product line not in the product data", mutate: func(r *SNPRule) { r.AllowedProducts = append(r.AllowedProducts, "Rome") }, err: `allowed_products: "Rome" is not a product line`},
		{name: "a floor for a product line not in the product data", mutate: func(r *SNPRule) { r.TCBFloors["Rome"] = map[string]int{"snp": 1} }, err: `tcb_floors: "Rome" is not a product line`},
		{name: "a floor for a product line without a layout", mutate: func(r *SNPRule) { r.TCBFloors["Venice"] = map[string]int{"snp": 1} }, err: `no TCB layout for "Venice"`},
		{name: "bad component", mutate: func(r *SNPRule) { r.TCBFloors["Milan"]["gpu"] = 1 }, err: "tcb_floors[Milan]"},
		{name: "bad bit", mutate: func(r *SNPRule) { r.RequiredMitigationBits["Milan"]["x"] = "?" }, err: `bit "x"`},
		{name: "bits of a product line not in the product data", mutate: func(r *SNPRule) { r.RequiredPlatformInfoBits["Rome"] = map[string]string{"5": "?"} }, err: `required_platform_info_bits: "Rome" is not a product line`},
		{name: "waiver of a bit not required", mutate: func(r *SNPRule) { r.MitigationWaivers["Milan"]["7"] = "no" }, err: "waived but not required"},
		{name: "chip id not hex", mutate: func(r *SNPRule) { r.AllowedChipIDs = []string{"zz"} }, err: "not 64 octets of hex"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			snp := recordedSNPRule()
			tt.mutate(snp)
			_, err := parsePlatformRule(ruleJSON(t, snp, recordedTDXRule()), modules)
			require.ErrorContains(t, err, tt.err)
		})
	}
	t.Run("td mask", func(t *testing.T) {
		_, err := parsePlatformRule(ruleJSON(t, recordedSNPRule(), &TDXRule{AttributesRefused: "0xzz"}), modules)
		require.ErrorContains(t, err, "td_attributes_refused")
	})
	t.Run("a family without a module", func(t *testing.T) {
		_, err := parsePlatformRule([]byte(`{"cca": {}}`), modules)
		require.ErrorContains(t, err, `no platform module for "cca"`)
	})
	t.Run("a field no module knows", func(t *testing.T) {
		_, err := parsePlatformRule([]byte(`{"tdx": {"td_attributes_refuse": "0x0"}}`), modules)
		require.ErrorContains(t, err, "td_attributes_refuse")
	})
	t.Run("a null entry is no entry", func(t *testing.T) {
		rule, err := parsePlatformRule([]byte(`{"sevsnp": null, "tdx": {"td_attributes_refused": "0x0"}}`), modules)
		require.NoError(t, err)
		_, err = rule.Check(snpResult(gcpMilan()))
		require.ErrorContains(t, err, `no platform rule for submodule "SEVSNP"`)
	})
	t.Run("not JSON", func(t *testing.T) {
		_, err := parsePlatformRule([]byte(`{`), modules)
		require.ErrorContains(t, err, "platform rule")
	})
	_, err = loadPlatformRule(filepath.Join(dir, "missing.json"), modules)
	require.Error(t, err)
}

func TestSNPProducts(t *testing.T) {
	t.Run("the product data SPIRE ships", func(t *testing.T) {
		d, err := loadSNPProducts("")
		require.NoError(t, err)
		for _, tt := range []struct {
			family, model byte
			name          string
		}{
			{0x19, 0x01, "Milan"}, {0x19, 0x11, "Genoa"}, {0x19, 0xA0, "Siena"},
			{0x1A, 0x02, "Turin"}, {0x1A, 0x11, "Turin"}, {0x1A, 0x50, "Venice"},
		} {
			p, ok := d.product(tt.family, tt.model)
			require.True(t, ok, tt.name)
			require.Equal(t, tt.name, p.Name)
		}
		_, ok := d.product(0x17, 0x31)
		require.False(t, ok)
		require.Equal(t, uint(7), d.byName["Milan"].TCBLayout["ucode"])
		require.Equal(t, uint(0), d.byName["Turin"].TCBLayout["fmc"])
		require.Empty(t, d.byName["Venice"].TCBLayout)
	})
	t.Run("the file of the operator", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "products.json")
		require.NoError(t, os.WriteFile(path, []byte(`{"products": [{"name": "Venice", "cpuid": [{"family": "0x1A", "extended_model": "0x5"}], "tcb_layout": {"fmc": 0, "bl": 1, "tee": 2, "snp": 3, "ucode": 7}}]}`), 0o600))
		d, err := loadSNPProducts(path)
		require.NoError(t, err)
		require.Equal(t, uint(3), d.byName["Venice"].TCBLayout["snp"])
		_, ok := d.product(0x19, 0x01)
		require.False(t, ok, "the file replaces the copy SPIRE ships")
		_, err = loadSNPProducts(filepath.Join(t.TempDir(), "missing.json"))
		require.ErrorContains(t, err, "sevsnp_products_path")
	})
	for _, tt := range []struct {
		name, raw, err string
	}{
		{name: "no products", raw: `{"products": []}`, err: "no products"},
		{name: "a field the data does not have", raw: `{"product": []}`, err: "product"},
		{name: "name required", raw: `{"products": [{"cpuid": [{"family": "0x19", "extended_model": "0x0"}]}]}`, err: "name is required"},
		{name: "listed twice", raw: `{"products": [{"name": "Milan", "cpuid": [{"family": "0x19", "extended_model": "0x0"}]}, {"name": "Milan", "cpuid": [{"family": "0x19", "extended_model": "0x1"}]}]}`, err: "listed twice"},
		{name: "cpuid required", raw: `{"products": [{"name": "Milan"}]}`, err: "cpuid is required"},
		{name: "family not hex", raw: `{"products": [{"name": "Milan", "cpuid": [{"family": "0x1g", "extended_model": "0x0"}]}]}`, err: "cpuid family"},
		{name: "extended model above a nibble", raw: `{"products": [{"name": "Milan", "cpuid": [{"family": "0x19", "extended_model": "0x10"}]}]}`, err: "extended_model"},
		{name: "one CPUID value, two product lines", raw: `{"products": [{"name": "Milan", "cpuid": [{"family": "0x19", "extended_model": "0x0"}]}, {"name": "Genoa", "cpuid": [{"family": "0x19", "extended_model": "0x0"}]}]}`, err: `names both "Milan" and "Genoa"`},
		{name: "layout byte above 7", raw: `{"products": [{"name": "Milan", "cpuid": [{"family": "0x19", "extended_model": "0x0"}], "tcb_layout": {"bl": 8}}]}`, err: "the byte must be 0 to 7"},
		{name: "two components, one byte", raw: `{"products": [{"name": "Milan", "cpuid": [{"family": "0x19", "extended_model": "0x0"}], "tcb_layout": {"bl": 0, "tee": 0}}]}`, err: "share byte 0"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseSNPProducts([]byte(tt.raw))
			require.ErrorContains(t, err, tt.err)
		})
	}
}
