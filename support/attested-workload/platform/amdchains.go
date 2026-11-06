package platform

import (
	"bytes"
	"crypto/x509"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/google/go-sev-guest/kds"
)

//go:embed amdchains/*.pem
var shippedAMDChains embed.FS

// amdChains are the public product chains of AMD, the ASK or ASVK and the ARK
// of each product line, by the common name of the ASK or ASVK, the issuer of
// the VCEK or VLEK it certifies. They are data that grows with every product
// line AMD ships, so they are PEM files under version control, not code: the
// copies this Workload ships, in amdchains with their sources in its README,
// or the files of the directory WithAMDChains names. A file is indexed by the
// subject of its first certificate.
type amdChains struct {
	byIssuer map[string]amdChain
}

// amdChain is one product chain, in DER, and the file it came from.
type amdChain struct {
	ask  []byte // the ASK or ASVK
	ark  []byte
	file string
}

// loadAMDChains reads the chains: the files of dir, or the copies this
// Workload ships when dir is empty.
func loadAMDChains(dir string) (*amdChains, error) {
	var fsys fs.FS = shippedAMDChains
	root, source := "amdchains", "the AMD chains this Workload ships"
	if dir != "" {
		fsys, root, source = os.DirFS(dir), ".", dir
	}
	entries, err := fs.ReadDir(fsys, root)
	if err != nil {
		return nil, fmt.Errorf("platform: %s: %w", source, err)
	}
	c := &amdChains{byIssuer: map[string]amdChain{}}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		raw, err := fs.ReadFile(fsys, path.Join(root, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("platform: %s: %s: %w", source, e.Name(), err)
		}
		// go-sev-guest refuses a bundle that ends with a blank line, as the
		// Turin VLEK bundle does; the blank line carries nothing.
		ask, ark, err := kds.ParseProductCertChain(bytes.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("platform: %s: %s: %w", source, e.Name(), err)
		}
		cert, err := x509.ParseCertificate(ask)
		if err != nil {
			return nil, fmt.Errorf("platform: %s: %s: %w", source, e.Name(), err)
		}
		issuer := cert.Subject.CommonName
		if issuer == "" {
			return nil, fmt.Errorf("platform: %s: %s: the first certificate has no common name", source, e.Name())
		}
		if other, dup := c.byIssuer[issuer]; dup {
			return nil, fmt.Errorf("platform: %s: %s and %s both hold the chain of %q", source, other.file, e.Name(), issuer)
		}
		c.byIssuer[issuer] = amdChain{ask: ask, ark: ark, file: e.Name()}
	}
	if len(c.byIssuer) == 0 {
		return nil, fmt.Errorf("platform: %s: no PEM file", source)
	}
	return c, nil
}

// chain is the product chain whose ASK or ASVK has the common name: the
// issuer of a VCEK or VLEK.
func (c *amdChains) chain(issuer string) (amdChain, bool) {
	ch, ok := c.byIssuer[issuer]
	return ch, ok
}
