package stark_ecdsa

import (
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
	keyCache sync.Map
}

// Sign generates a deterministic RFC 6979 ECDSA signature (base64) for the given message.
func (se *StarkEcdsa) Sign(message string, pem string) map[string]interface{} {
	privKey, ok := se.getPrivateKey(pem)
	if !ok {
		return map[string]interface{}{
			"error": "failed to parse private key PEM",
			"ok":    false,
		}
	}

	sig := ecdsa.Sign(message, privKey)
	return map[string]interface{}{
		"signature": sig.ToBase64(),
		"ok":        true,
	}
}

// Verify checks if a base64 signature is valid for the message against a PEM public key.
func (se *StarkEcdsa) Verify(message string, b64Signature string, pubKeyPem string) map[string]interface{} {
	pubKey := publickey.FromPem(pubKeyPem)
	sig, err := signature.FromBase64(b64Signature)
	if err != nil {
		return map[string]interface{}{
			"valid": false,
			"error": err.Error(),
		}
	}

	valid := ecdsa.Verify(message, sig, &pubKey)
	return map[string]interface{}{
		"valid": valid,
	}
}

// getPrivateKey parses and caches private keys by PEM string (thread-safe for concurrent VUs).
func (se *StarkEcdsa) getPrivateKey(pem string) (*privatekey.PrivateKey, bool) {
	if cached, ok := se.keyCache.Load(pem); ok {
		return cached.(*privatekey.PrivateKey), true
	}

	pk := privatekey.FromPem(pem)
	// starkbank/ecdsa-go returns a zero-value struct on invalid PEM.
	// Validate your PEM offline; here we cache and return assuming valid input.
	ptr := &pk
	se.keyCache.Store(pem, ptr)
	return ptr, true
}
