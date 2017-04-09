package utils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"io/ioutil"
	"os"

	"github.com/jasonwbarnett/gokt/microsoft"
)

// RSAPrivateKeyToEncodedPEM convert *rsa.PrivateKey to a pem block ([]byte)
func RSAPrivateKeyToEncodedPEM(key *rsa.PrivateKey) []byte {
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)
	return pemdata
}

// ReadFileAndParseXMLRSAKey ...
func ReadFileAndParseXMLRSAKey(filename string, base64encoded bool) (*microsoft.RSAParameters, error) {
	var b []byte

	xmlFile, err := os.Open(filename)
	if err != nil {
		return new(microsoft.RSAParameters), err
	}
	defer xmlFile.Close()

	b, _ = ioutil.ReadAll(xmlFile)

	if base64encoded == true {
		b, _ = base64.StdEncoding.DecodeString(string(b))
	}

	msRSA := new(microsoft.RSAParameters)
	xml.Unmarshal(b, &msRSA)

	return msRSA, err
}
