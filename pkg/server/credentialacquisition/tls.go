package credentialacquisition

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// clientTLS is the TLS configuration with which this Server calls a Verifier
// or the Secret Vault: the CA that signed their server certificates and, when
// they require mutual TLS, the certificate this Server presents to them, so
// that they answer this Server and no other caller.
func clientTLS(caPath, certPath, keyPath string) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no certificate", caPath)
		}
		tc.RootCAs = pool
	}
	if certPath != "" || keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	return tc, nil
}
