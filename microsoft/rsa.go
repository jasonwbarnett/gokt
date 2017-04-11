package microsoft

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"math/big"
	"strconv"
)

// Microsoft RSA Format
// <RSAKeyValue>
//    <Modulus>…</Modulus>
//    <Exponent>…</Exponent>
//    <P>…</P>
//    <Q>…</Q>
//    <DP>…</DP>
//    <DQ>…</DQ>
//    <InverseQ>…</InverseQ>
//    <D>…</D>
// </RSAKeyValue>

// ASN.1 PKCS#1
// RSAPrivateKey ::= SEQUENCE {
//     version           Version,
//     modulus           INTEGER,  -- n
//     publicExponent    INTEGER,  -- e
//     privateExponent   INTEGER,  -- d
//     prime1            INTEGER,  -- p
//     prime2            INTEGER,  -- q
//     exponent1         INTEGER,  -- d mod (p-1)
//     exponent2         INTEGER,  -- d mod (q-1)
//     coefficient       INTEGER,  -- (inverse of q) mod p
//     otherPrimeInfos   OtherPrimeInfos OPTIONAL
// }

// RSAParameters ...
type RSAParameters struct {
	XMLName  xml.Name `xml:"RSAKeyValue"`
	Modulus  string   `xml:"Modulus,omitempty"`
	Exponent string   `xml:"Exponent,omitempty"`
	D        string   `xml:"D,omitempty"`
	P        string   `xml:"P,omitempty"`
	Q        string   `xml:"Q,omitempty"`
	DP       string   `xml:"DP,omitempty"`
	DQ       string   `xml:"DQ,omitempty"`
	InverseQ string   `xml:"InverseQ,omitempty"`
}

// ToXMLString converts to an XML formatted String
func (r *RSAParameters) ToXMLString() (xmlString string) {
	xmlOutput, err := xml.MarshalIndent(r, "", "  ")
	if err != nil {
		fmt.Printf("error: %v\n", err)
	}
	return string(xmlOutput)
}

// GetRSAPrivateKey converts to an *rsa.PrivateKey
func (r *RSAParameters) GetRSAPrivateKey() *rsa.PrivateKey {
	pk := new(rsa.PrivateKey)

	pk.PublicKey.N = base64ToBigInt(r.Modulus)
	pk.PublicKey.E = base64ToInt(r.Exponent)
	if pk.PublicKey.E == 0 {
		pk.PublicKey.E = 65537
	}
	pk.D = base64ToBigInt(r.D)
	pk.Primes = append(pk.Primes, base64ToBigInt(r.P))
	pk.Primes = append(pk.Primes, base64ToBigInt(r.Q))
	pk.Precomputed.Dp = base64ToBigInt(r.DP)
	pk.Precomputed.Dq = base64ToBigInt(r.DQ)
	pk.Precomputed.Qinv = base64ToBigInt(r.InverseQ)

	return pk
}

// FromRSAPrivateKey will convert a *rsa.PrivateKey to *microsoft.RSAParameters
func FromRSAPrivateKey(pk *rsa.PrivateKey) *RSAParameters {
	var n, e, d, p, q, dp, dq, qinv string

	n = toBase64(pk.PublicKey.N)
	e = toBase64(pk.PublicKey.E)
	d = toBase64(pk.D)

	for i, prime := range pk.Primes {
		if i == 0 {
			p = toBase64(prime)
		} else if i == 1 {
			q = toBase64(prime)
		} else {
			fmt.Println("ERROR: more than 2 primes")
		}
	}

	dp = toBase64(pk.Precomputed.Dp)
	dq = toBase64(pk.Precomputed.Dq)
	qinv = toBase64(pk.Precomputed.Qinv)

	msRSA := &RSAParameters{
		Modulus:  n,
		Exponent: e,
		D:        d,
		P:        p,
		Q:        q,
		DP:       dp,
		DQ:       dq,
		InverseQ: qinv,
	}

	return msRSA
}

func toBase64(i interface{}) (b64 string) {
	switch t := i.(type) {
	case string:
		b64 = base64.StdEncoding.EncodeToString([]byte(t))
	case int:
		bytes := []byte(strconv.Itoa(t))
		b64 = base64.StdEncoding.EncodeToString(bytes)
	case *big.Int:
		b64 = base64.StdEncoding.EncodeToString(t.Bytes())
	default:
		fmt.Printf("unexpected type %+v\n", t) // %T prints whatever type t has
	}

	return b64
}

func base64ToBigInt(b64 string) *big.Int {
	stdDec, _ := base64.StdEncoding.DecodeString(b64)
	i := new(big.Int)
	i.SetBytes(stdDec)
	return i
}

func base64ToInt(b64 string) (i int) {
	stdDec, _ := base64.StdEncoding.DecodeString(b64)
	i, _ = strconv.Atoi(string(stdDec))

	return i
}
