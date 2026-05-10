package stark_ecdsa

import (
	"encoding/base64"
	"sync"

	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/publickey"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/signature"
	"go.k6.io/k6/js/modules"
)

func init() {
	modules.Register("k6/x/stark-ecdsa", new(StarkEcdsa))
}

// StarkEcdsa exposes starkbank/ecdsa-go to k6 JavaScript.
type StarkEcdsa struct {
	cache sync.Map
}

// Sign generates a deterministic RFC 6979 ECDSA signature (base64).
func (se *StarkEcdsa) Sign(message string, pem string) map[string]interface{} {
	privKey, ok := se.getPrivateKey(pem)
	if !ok {
		return map[string]interface{}{
			"error": "failed to parse EC PRIVATE KEY PEM",
			"ok":    false,
		}
	}

	sig := ecdsa.Sign(message, privKey)
	return map[string]interface{}{
		"signature": sig.ToBase64(),
		"ok":        true,
	}
}

// Verify checks a base64 signature against a PEM public key.
func (se *StarkEcdsa) Verify(message string, b64Signature string, pubKeyPem string) map[string]interface{} {
	pubKey := publickey.FromPem(pubKeyPem)

	derBytes, err := base64.StdEncoding.DecodeString(b64Signature)
	if err != nil {
		return map[string]interface{}{"valid": false, "error": err.Error()}
	}

	sig := signature.FromDer(derBytes)
	valid := ecdsa.Verify(message, sig, &pubKey)
	return map[string]interface{}{"valid": valid}
}

// getPrivateKey parses and caches the key by PEM string (safe for concurrent VUs).
func (se *StarkEcdsa) getPrivateKey(pem string) (*privatekey.PrivateKey, bool) {
	if cached, ok := se.cache.Load(pem); ok {
		return cached.(*privatekey.PrivateKey), true
	}

	pk := privatekey.FromPem(pem)
	// starkbank returns a zero-value on invalid PEM.
	// For production, validate your PEM offline once before the test.
	se.cache.Store(pem, &pk)
	return &pk, true
}
