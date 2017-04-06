package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"strconv"

	"github.com/davecgh/go-spew/spew"
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

type rsaParameters struct {
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

func (pkXML *rsaParameters) toString() (xmlString string) {
	xmlOutput, err := xml.MarshalIndent(pkXML, "", "  ")
	if err != nil {
		fmt.Printf("error: %v\n", err)
	}
	return string(xmlOutput)
}

func main() {
	keyBytes, err := ioutil.ReadFile("128.key")
	if err != nil {
		fmt.Println(err)
	}

	block, _ := pem.Decode(keyBytes)

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("priv_key:\n---------\n\n%+v\n\n", privKey)
	fmt.Print(spew.Sdump(privKey))
	pkXML := rsaToXML(privKey)
	fmt.Println(pkXML.toString())

	backToRSA := xmlToRSA(pkXML)
	fmt.Print(spew.Sdump(privKey))
	fmt.Print(spew.Sdump(backToRSA))

	fmt.Println(rsaToPEM(backToRSA))
}

func rsaToPEM(key *rsa.PrivateKey) string {
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)
	return string(pemdata)
}

func xmlToRSA(pkXML *rsaParameters) *rsa.PrivateKey {
	pk := new(rsa.PrivateKey)

	pk.PublicKey = rsa.PublicKey{}
	pk.PublicKey.N = base64ToBigInt(pkXML.Modulus)
	pk.PublicKey.E = base64ToInt(pkXML.Exponent)
	pk.D = base64ToBigInt(pkXML.D)
	pk.Primes = append(pk.Primes, base64ToBigInt(pkXML.P))
	pk.Primes = append(pk.Primes, base64ToBigInt(pkXML.Q))
	pk.Precomputed.Dp = base64ToBigInt(pkXML.DP)
	pk.Precomputed.Dq = base64ToBigInt(pkXML.DQ)
	pk.Precomputed.Qinv = base64ToBigInt(pkXML.InverseQ)

	return pk
}

func rsaToXML(pk *rsa.PrivateKey) (pkXML *rsaParameters) {
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

	fmt.Printf("n: %s\n", n)
	fmt.Printf("e: %s\n", e)
	fmt.Printf("d: %s\n", d)
	fmt.Printf("p: %s\n", p)
	fmt.Printf("q: %s\n", q)
	fmt.Printf("dp: %s\n", dp)
	fmt.Printf("dq: %s\n", dq)
	fmt.Printf("qinv: %s\n", qinv)

	rsaKey := &rsaParameters{
		Modulus:  n,
		Exponent: e,
		D:        d,
		P:        p,
		Q:        q,
		DP:       dp,
		DQ:       dq,
		InverseQ: qinv,
	}
	fmt.Print(spew.Sdump(rsaKey))

	return rsaKey
}

func toBase64(i interface{}) (b64 string) {
	switch t := i.(type) {
	case string:
		b64 = base64.StdEncoding.EncodeToString([]byte(t))
	case int:
		fmt.Println("int:", t)
		bytes := []byte(strconv.Itoa(t))
		fmt.Println("int []bytes:", bytes)
		b64 = base64.StdEncoding.EncodeToString(bytes)
		fmt.Println("int encoded base64:", b64)
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
