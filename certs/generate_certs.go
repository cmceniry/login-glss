package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"time"
)

// generateKeyAndCert produces a private key and a filled out and signed
// certificate for that private key. It takes three arguments:
//   name : the value to be used for the CommonName on the certificate
//   signer : the certificate authority which will attest to this certificate
//   signerkey : the key used to sign the certificate
// It signer or signerkey is nil, it will produce a self-signed certificate
// which can be used directly or as a Certificate Authority
func generateKeyAndCert(name string, signer *x509.Certificate, signerkey *rsa.PrivateKey) (*rsa.PrivateKey, *x509.Certificate) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Truncate(24 * time.Hour),
		NotAfter:              time.Now().Truncate(24 * time.Hour).Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if signer == nil || signerkey == nil {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		signer = template
		signerkey = key
	}
	der, _ := x509.CreateCertificate(
		rand.Reader,
		template,
		signer,
		&key.PublicKey,
		signerkey,
	)
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

func saveKeyAndCert(prefix string, key *rsa.PrivateKey, cert *x509.Certificate) {
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
	ioutil.WriteFile(prefix+".key", keyPem, 0444)
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	ioutil.WriteFile(prefix+".crt", certPem, 0444)
}

func main() {
	caKey, caCert := generateKeyAndCert("glss Root CA", nil, nil)
	saveKeyAndCert("certs/CA", caKey, caCert)
	serverKey, serverCert := generateKeyAndCert("localhost", caCert, caKey)
	saveKeyAndCert("certs/server", serverKey, serverCert)
	clientKey, clientCert := generateKeyAndCert("glss Client A", caCert, caKey)
	saveKeyAndCert("certs/client", clientKey, clientCert)
}
