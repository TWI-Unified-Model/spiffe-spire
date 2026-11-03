package credentialacquisition

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// The binding input of TACRA, Binding Credential Keys to Evidence: each value
// preceded by its length as a 32-bit big-endian integer. The expected values
// were computed outside this package from the same octets.
func TestBindingInput(t *testing.T) {
	handle := make([]byte, 32)
	for i := range handle {
		handle[i] = byte(i)
	}
	input := BindingInput(handle, "spiffe://example.org", []byte("csr-der"))
	require.Equal(t,
		"00000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"+
			"000000147370696666653a2f2f6578616d706c652e6f7267"+
			"000000076373722d646572",
		hex.EncodeToString(input))

	require.Equal(t,
		"29192ebebf1eda9a4636eea5331270133c70f10489c2acaac02138045397e61006a9ee8d076e48f32ac1beb985c1a64b8d984d75363667154b94a9ce2043a5af",
		hex.EncodeToString(BindingValue(handle, "spiffe://example.org", []byte("csr-der"))))
}

func TestBindingInputEmptyFreshness(t *testing.T) {
	// absent-none: an empty freshness element, framed with a zero length
	input := BindingInput(nil, "t", []byte("s"))
	require.Equal(t, "00000000"+"00000001"+"74"+"00000001"+"73", hex.EncodeToString(input))
}
