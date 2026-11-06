package credentialacquisition

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
)

// ErrPlatform is wrapped by every refusal of the platform rule. The Attestation
// Results are verified and affirming; what they report about the platform,
// the machine the Workload runs on, its product line, its TCB, the guest policy
// of SEV-SNP or the TD attributes of TDX, is not what the rule accepts. The
// reason follows the error.
var ErrPlatform = errors.New("refused by the platform rule")

// The platform families, as the platform rule and the Attestation Results
// name them.
const (
	familySEVSNP = "sevsnp"
	familyTDX    = "tdx"
)

// PlatformRule is the rule of the Server on the platform: the machine the
// Workload runs on, as verified, affirming Attestation Results describe it.
// "Affirming" says the Evidence matched the reference values of the Verifier;
// it does not say the platform is one this Server accepts. The rule is read
// from a JSON file (platform_rule_path) with one entry per platform family,
// keyed by the name of the module for the family: sevsnp, tdx. The module
// parses, validates and applies the entry.
type PlatformRule struct {
	byFamily map[string]familyRule
}

// A platformModule is the plug-in of the Server for one platform family, the
// counterpart on the Server side of the platform plug-in of the Attester. It
// parses and validates the entry of the family in the platform rule into the
// rule it applies to the Attestation Results of the family. A new family, CCA
// for example, is a new module in platformModules; the rest of the Server does
// not change.
type platformModule interface {
	// Family is the family: the key of its entry in the platform rule file,
	// and the name verified Attestation Results carry.
	Family() string
	// ParseRule parses and validates the entry of the family.
	ParseRule(raw json.RawMessage) (familyRule, error)
}

// A familyRule is the parsed entry of one family in the platform rule.
type familyRule interface {
	// Check applies the rule to verified Attestation Results of the family.
	// When it admits them, it returns what it admitted them without: one
	// line per waiver applied, naming it and what it waived.
	Check(res *attestationResults) ([]string, error)
}

// platformModules builds the modules the configuration describes: SEV-SNP
// with its product data, and TDX.
func platformModules(c *Config) ([]platformModule, error) {
	products, err := loadSNPProducts(c.SEVSNPProductsPath)
	if err != nil {
		return nil, err
	}
	return []platformModule{&snpModule{products: products}, tdxModule{}}, nil
}

// loadPlatformRule reads the rule file and hands each entry to its module.
func loadPlatformRule(path string, modules []platformModule) (*PlatformRule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parsePlatformRule(raw, modules)
}

// parsePlatformRule parses the rule: each entry by its module. An entry that
// is null is no entry. A key no module answers to is an error, as is a field
// no module knows.
func parsePlatformRule(raw []byte, modules []platformModule) (*PlatformRule, error) {
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("platform rule: %w", err)
	}
	p := &PlatformRule{byFamily: make(map[string]familyRule, len(entries))}
	for family, entry := range entries {
		if bytes.Equal(bytes.TrimSpace(entry), []byte("null")) {
			continue
		}
		i := slices.IndexFunc(modules, func(m platformModule) bool { return m.Family() == family })
		if i < 0 {
			return nil, fmt.Errorf("platform rule: no platform module for %q", family)
		}
		rule, err := modules[i].ParseRule(entry)
		if err != nil {
			return nil, err
		}
		p.byFamily[family] = rule
	}
	return p, nil
}

// Check hands verified Attestation Results to the rule for their family. A
// family the rule has no entry for is refused, not passed.
func (p *PlatformRule) Check(res *attestationResults) ([]string, error) {
	rule, ok := p.byFamily[res.Family]
	if !ok {
		return nil, fmt.Errorf("%w: no platform rule for family %q", ErrPlatform, res.Family)
	}
	return rule.Check(res)
}

// decodeEntry decodes an entry of the rule, refusing a field the entry does
// not have.
func decodeEntry(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// snpModule is the module for SEV-SNP. The claims of the family are the
// fields of the attestation report the Verifier annotated. Reading them needs
// the product data of AMD: which product line a
// CPUID family and extended model names, and where each component sits in
// TCB_VERSION. That data grows with every product line AMD ships, so it is not
// written into the code: it is read from a JSON file under version control,
// the copy SPIRE ships (sevsnp_products.json beside this file) or the file
// sevsnp_products_path names.
type snpModule struct{ products *snpProductData }

func (*snpModule) Family() string { return familySEVSNP }

func (m *snpModule) ParseRule(raw json.RawMessage) (familyRule, error) {
	r := &SNPRule{products: m.products}
	if err := decodeEntry(raw, r); err != nil {
		return nil, fmt.Errorf("platform rule: sevsnp: %w", err)
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	return r, nil
}

//go:embed sevsnp_products.json
var shippedSNPProducts []byte

// snpProductData is the product data of AMD for SEV-SNP: the product lines,
// each with the CPUID values that report it and the layout of its TCB_VERSION.
type snpProductData struct {
	About    string       `json:"about,omitempty"`
	Products []snpProduct `json:"products"`
	byCPUID  map[[2]byte]*snpProduct
	byName   map[string]*snpProduct
}

// snpProduct is one product line of AMD.
type snpProduct struct {
	// Name is the product line as the platform rule names it: Milan, Genoa.
	Name string `json:"name"`
	// CPUID lists the family and extended model, in hex, that report the
	// product line (AMD 57230, Table 4).
	CPUID []snpCPUID `json:"cpuid"`
	// TCBLayout is the byte of each component in the 64-bit TCB_VERSION of
	// the product line (AMD 56860, Table 5; for Turin, Table 4). A product
	// line without a layout is not decoded: its TCB cannot be checked against
	// a floor, so the rule refuses it.
	TCBLayout map[string]uint `json:"tcb_layout,omitempty"`
	// Source names the AMD documents the entry comes from.
	Source string `json:"source,omitempty"`
}

// snpCPUID is a family and an extended model, each a hex value: 0x19, 0xA.
type snpCPUID struct {
	Family        string `json:"family"`
	ExtendedModel string `json:"extended_model"`
}

// loadSNPProducts reads the product data: the file named, or the copy SPIRE
// ships when none is named.
func loadSNPProducts(path string) (*snpProductData, error) {
	raw, source := shippedSNPProducts, "the SEV-SNP product data SPIRE ships"
	if path != "" {
		var err error
		if raw, err = os.ReadFile(path); err != nil {
			return nil, fmt.Errorf("sevsnp_products_path: %w", err)
		}
		source = "sevsnp_products_path"
	}
	d, err := parseSNPProducts(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	return d, nil
}

// parseSNPProducts parses and validates the product data: every product line
// named once, every CPUID value naming one product line, every layout within
// the eight bytes of TCB_VERSION with one component per byte.
func parseSNPProducts(raw []byte) (*snpProductData, error) {
	var d snpProductData
	if err := decodeEntry(raw, &d); err != nil {
		return nil, err
	}
	if len(d.Products) == 0 {
		return nil, errors.New("no products")
	}
	d.byCPUID = make(map[[2]byte]*snpProduct)
	d.byName = make(map[string]*snpProduct, len(d.Products))
	for i := range d.Products {
		p := &d.Products[i]
		if p.Name == "" {
			return nil, fmt.Errorf("products[%d]: name is required", i)
		}
		if _, dup := d.byName[p.Name]; dup {
			return nil, fmt.Errorf("product line %q is listed twice", p.Name)
		}
		if len(p.CPUID) == 0 {
			return nil, fmt.Errorf("product line %q: cpuid is required", p.Name)
		}
		for _, c := range p.CPUID {
			family, err := hexValue(c.Family, 0xFF)
			if err != nil {
				return nil, fmt.Errorf("product line %q: cpuid family: %w", p.Name, err)
			}
			model, err := hexValue(c.ExtendedModel, 0xF)
			if err != nil {
				return nil, fmt.Errorf("product line %q: cpuid extended_model: %w", p.Name, err)
			}
			key := [2]byte{family, model}
			if other, dup := d.byCPUID[key]; dup {
				return nil, fmt.Errorf("CPUID family %s, extended model %s names both %q and %q", c.Family, c.ExtendedModel, other.Name, p.Name)
			}
			d.byCPUID[key] = p
		}
		used := make(map[uint]string, len(p.TCBLayout))
		for component, b := range p.TCBLayout {
			if component == "" || b > 7 {
				return nil, fmt.Errorf("product line %q: tcb_layout %q: the byte must be 0 to 7", p.Name, component)
			}
			if other, dup := used[b]; dup {
				return nil, fmt.Errorf("product line %q: tcb_layout: %q and %q share byte %d", p.Name, other, component, b)
			}
			used[b] = component
		}
		d.byName[p.Name] = p
	}
	return &d, nil
}

// hexValue parses a hex value, with or without 0x, up to limit.
func hexValue(s string, limit uint64) (byte, error) {
	v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(s), "0x"), 16, 8)
	if err != nil || v > limit {
		return 0, fmt.Errorf("%q is not a hex value up to %#x", s, limit)
	}
	return byte(v), nil
}

// product is the product line a report names by its CPUID family and model
// byte: the extended model is the high nibble of the model byte.
func (d *snpProductData) product(family, model byte) (*snpProduct, bool) {
	p, ok := d.byCPUID[[2]byte{family, model >> 4}]
	return p, ok
}

// SNPRule is the entry for SEV-SNP.
type SNPRule struct {
	// A machine must be named: a VLEK-signed report (the key of the cloud provider) or
	// one without CHIP_ID is refused.
	RequireMachineIdentity bool `json:"require_machine_identity"`
	// The machines admitted, by CHIP_ID (hex); empty admits any named machine.
	AllowedChipIDs []string `json:"allowed_chip_ids,omitempty"`
	// The product lines admitted, named from the CPUID family and extended
	// model of the report by the product data.
	AllowedProducts []string `json:"allowed_products"`
	// The minimum of each TCB component, per product line; a product line
	// without a floor is refused.
	TCBFloors map[string]map[string]int `json:"tcb_floors"`
	// Apply the floors to COMMITTED_TCB as well as REPORTED_TCB.
	CheckCommittedTCB bool `json:"check_committed_tcb"`
	// "forbid", or "allow-with-microcode-floor": SMT only when the floor of the
	// product line names a microcode level, met.
	SMT string `json:"smt"`
	// Per product line, the mitigation bits that must be set in both
	// mitigation vectors, the one verified at the launch of the guest and the one
	// verified now (report version 5), each with the reason the refusal
	// gives, e.g. {"Milan": {"4": "AMD-SB-3034"}}.
	RequiredMitigationBits map[string]map[string]string `json:"required_mitigation_bits,omitempty"`
	// Per product line, required mitigation bits this Server admits Evidence
	// without, each under a named waiver recorded whenever it applies, e.g.
	// {"Milan": {"4": "admitted without bit 4, AMD-SB-3034"}}. A bit waived
	// must be one required.
	MitigationWaivers map[string]map[string]string `json:"mitigation_waivers,omitempty"`
	// Per product line, the PLATFORM_INFO bits that must be set, each with
	// its reason, e.g. {"Milan": {"5": "AMD-SB-3015: ALIAS_CHECK_COMPLETE"}}.
	RequiredPlatformInfoBits map[string]map[string]string `json:"required_platform_info_bits,omitempty"`

	products *snpProductData // the product data the entry is read with
}

// validate checks the entry against the product data: every product line it
// names is in the data, every product line with a floor has a TCB layout, the
// components of each floor are in the layout, the bits are bit numbers, every
// waived bit is required, every CHIP_ID is 64 octets of hex.
func (s *SNPRule) validate() error {
	if s.SMT != "forbid" && s.SMT != "allow-with-microcode-floor" {
		return fmt.Errorf("platform rule: sevsnp.smt %q: forbid or allow-with-microcode-floor", s.SMT)
	}
	for _, name := range s.AllowedProducts {
		if _, ok := s.products.byName[name]; !ok {
			return fmt.Errorf("platform rule: sevsnp.allowed_products: %q is not a product line of the product data", name)
		}
	}
	for name, floor := range s.TCBFloors {
		p, ok := s.products.byName[name]
		if !ok {
			return fmt.Errorf("platform rule: sevsnp.tcb_floors: %q is not a product line of the product data", name)
		}
		if len(p.TCBLayout) == 0 {
			return fmt.Errorf("platform rule: sevsnp.tcb_floors: no TCB layout for %q in the product data", name)
		}
		for component, v := range floor {
			if _, ok := p.TCBLayout[component]; !ok || v < 0 || v > 255 {
				return fmt.Errorf("platform rule: sevsnp.tcb_floors[%s]: %s=%d", name, component, v)
			}
		}
	}
	for field, m := range map[string]map[string]map[string]string{"required_mitigation_bits": s.RequiredMitigationBits,
		"required_platform_info_bits": s.RequiredPlatformInfoBits} {
		for name, bits := range m {
			if _, ok := s.products.byName[name]; !ok {
				return fmt.Errorf("platform rule: sevsnp.%s: %q is not a product line of the product data", field, name)
			}
			if _, err := bitsOf(bits); err != nil {
				return fmt.Errorf("platform rule: sevsnp.%s[%s]: %w", field, name, err)
			}
		}
	}
	for name, bits := range s.MitigationWaivers {
		waived, err := bitsOf(bits)
		if err != nil {
			return fmt.Errorf("platform rule: sevsnp.mitigation_waivers[%s]: %w", name, err)
		}
		for _, b := range waived {
			if _, ok := s.RequiredMitigationBits[name][strconv.Itoa(b)]; !ok {
				return fmt.Errorf("platform rule: sevsnp.mitigation_waivers[%s]: bit %d is waived but not required", name, b)
			}
		}
	}
	for _, c := range s.AllowedChipIDs {
		if b, err := hex.DecodeString(c); err != nil || len(b) != 64 {
			return fmt.Errorf("platform rule: sevsnp.allowed_chip_ids: %q is not 64 octets of hex", c)
		}
	}
	return nil
}

// bitsOf returns the bit numbers of a map keyed by them ("0" to "63"), in
// ascending order.
func bitsOf(m map[string]string) ([]int, error) {
	bits := make([]int, 0, len(m))
	for k := range m {
		b, err := strconv.Atoi(k)
		if err != nil || b < 0 || b > 63 || strconv.Itoa(b) != k {
			return nil, fmt.Errorf("bit %q: a number from 0 to 63", k)
		}
		bits = append(bits, b)
	}
	slices.Sort(bits)
	return bits, nil
}

// Check applies the entry to the fields of the report the Verifier annotated.
func (s *SNPRule) Check(res *attestationResults) ([]string, error) {
	if res.SNP == nil {
		if res.SNPErr != nil {
			return nil, fmt.Errorf("%w: no SEV-SNP claims in the Attestation Results: %w", ErrPlatform, res.SNPErr)
		}
		return nil, fmt.Errorf("%w: no SEV-SNP claims in the Attestation Results", ErrPlatform)
	}
	return s.check(res.SNP)
}

func (s *SNPRule) check(c *snpClaims) (waived []string, err error) {
	fail := func(format string, a ...any) ([]string, error) {
		return nil, fmt.Errorf("%w: "+format, append([]any{ErrPlatform}, a...)...)
	}
	// The guest policy (AMD 56860 Table 12)
	if c.policy>>19&1 == 1 {
		return fail("POLICY.DEBUG is set")
	}
	if c.policy>>18&1 == 1 {
		return fail("POLICY.MIGRATE_MA is set")
	}
	if c.policy>>17&1 != 1 || c.policy>>26 != 0 {
		return fail("POLICY %#x: bit 17 must be one and bits 63:26 zero", c.policy)
	}
	// The machine
	if s.RequireMachineIdentity && (c.class != classByChip || len(c.chipID) == 0) {
		return fail("the report names no machine (class %s)", c.class)
	}
	if len(s.AllowedChipIDs) > 0 && !slices.ContainsFunc(s.AllowedChipIDs, func(h string) bool {
		b, _ := hex.DecodeString(h)
		return len(c.chipID) > 0 && bytes.Equal(b, c.chipID)
	}) {
		return fail("CHIP_ID %x… is not a listed machine", c.chipID[:min(8, len(c.chipID))])
	}
	// The product line, from the product data
	if !c.hasCPUID {
		return fail("the report carries no CPUID (report version below 3), so its product line is unknown")
	}
	p, ok := s.products.product(c.family, c.model)
	if !ok {
		return fail("CPUID family %#x, model %#x names no product line of the product data", c.family, c.model)
	}
	if !slices.Contains(s.AllowedProducts, p.Name) {
		return fail("product line %q (CPUID family %#x, model %#x) is not admitted", p.Name, c.family, c.model)
	}
	// The TCB, decoded with the layout of the product line
	floor, ok := s.TCBFloors[p.Name]
	if !ok {
		return fail("no TCB floor is configured for %s", p.Name)
	}
	if len(p.TCBLayout) == 0 {
		return fail("the product data has no TCB layout for %s, so its TCB is not decoded", p.Name)
	}
	component := func(tcb uint64, name string) int { return int(tcb >> (8 * p.TCBLayout[name]) & 0xFF) }
	for name, floorValue := range floor {
		if component(c.reportedTCB, name) < floorValue {
			return fail("REPORTED_TCB %s %d is below the floor %d", name, component(c.reportedTCB, name), floorValue)
		}
		if s.CheckCommittedTCB && component(c.committedTCB, name) < floorValue {
			return fail("COMMITTED_TCB %s %d is below the floor %d", name, component(c.committedTCB, name), floorValue)
		}
	}
	// The mitigations AMD attests by a bit of the mitigation vectors:
	// verified at launch and now
	if required := s.RequiredMitigationBits[p.Name]; len(required) > 0 {
		bits, _ := bitsOf(required)
		if !c.hasMitVectors {
			return fail("the report carries no mitigation vector (version below 5), and %s requires mitigation bits %v",
				p.Name, bits)
		}
		for _, b := range bits {
			launch, current := c.launchMitVector>>b&1 == 1, c.currentMitVector>>b&1 == 1
			if launch && current {
				continue
			}
			if w, ok := s.MitigationWaivers[p.Name][strconv.Itoa(b)]; ok {
				waived = append(waived, fmt.Sprintf("%s: %s mitigation bit %d (%s) is not set (LAUNCH_MIT_VECTOR %#x, "+
					"CURRENT_MIT_VECTOR %#x)", w, p.Name, b, required[strconv.Itoa(b)], c.launchMitVector, c.currentMitVector))
				continue
			}
			if !launch {
				return fail("mitigation bit %d (%s) is not set in LAUNCH_MIT_VECTOR %#x", b, required[strconv.Itoa(b)],
					c.launchMitVector)
			}
			return fail("mitigation bit %d (%s) is not set in CURRENT_MIT_VECTOR %#x", b, required[strconv.Itoa(b)],
				c.currentMitVector)
		}
	}
	if required := s.RequiredPlatformInfoBits[p.Name]; len(required) > 0 {
		bits, _ := bitsOf(required)
		for _, b := range bits {
			if c.platformInfo>>b&1 == 0 {
				return fail("PLATFORM_INFO bit %d (%s) is not set (%#x)", b, required[strconv.Itoa(b)], c.platformInfo)
			}
		}
	}
	// SMT (PLATFORM_INFO.SMT_EN, AMD 56860 Table 28)
	if c.platformInfo&1 == 1 {
		if s.SMT == "forbid" {
			return fail("SMT is enabled on the platform")
		}
		if u, ok := floor["ucode"]; !ok || component(c.reportedTCB, "ucode") < u {
			return fail("SMT is enabled and no microcode floor is met")
		}
	}
	return waived, nil
}

// tdxModule is the module for TDX. The claims of the family are the TD
// ATTRIBUTES the Verifier annotated.
type tdxModule struct{}

func (tdxModule) Family() string { return familyTDX }

func (tdxModule) ParseRule(raw json.RawMessage) (familyRule, error) {
	var r TDXRule
	if err := decodeEntry(raw, &r); err != nil {
		return nil, fmt.Errorf("platform rule: tdx: %w", err)
	}
	if _, err := parseMask(r.AttributesRefused); err != nil {
		return nil, err
	}
	return &r, nil
}

// TDXRule is the entry for TDX, on the TD ATTRIBUTES the TDX Verifier
// annotates.
type TDXRule struct {
	// ATTRIBUTES bits refused besides the TUD group (bits 3:0), which is
	// always refused; a hex mask.
	AttributesRefused string `json:"td_attributes_refused"`
}

func parseMask(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	m, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(s), "0x"), 16, 64)
	if err != nil {
		return 0, fmt.Errorf("platform rule: td_attributes_refused %q: %w", s, err)
	}
	return m, nil
}

// Check applies the entry to the TD ATTRIBUTES.
func (t *TDXRule) Check(res *attestationResults) ([]string, error) {
	return nil, t.check(res.TDX)
}

func (t *TDXRule) check(ann map[string]string) error {
	raw, ok := ann["td_attributes"]
	if !ok {
		return fmt.Errorf("%w: the TDX Verifier annotated no TD ATTRIBUTES", ErrPlatform)
	}
	attrs, err := strconv.ParseUint(raw, 16, 64)
	if err != nil {
		return fmt.Errorf("%w: TD ATTRIBUTES %q", ErrPlatform, raw)
	}
	mask, _ := parseMask(t.AttributesRefused)
	if attrs&0xF != 0 {
		return fmt.Errorf("%w: the TD is under debug (ATTRIBUTES %016x)", ErrPlatform, attrs)
	}
	if bad := attrs & mask; bad != 0 {
		return fmt.Errorf("%w: TD ATTRIBUTES bits %x are refused", ErrPlatform, bad)
	}
	return nil
}
