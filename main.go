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
	"os"
	"strconv"

	"github.com/davecgh/go-spew/spew"
)

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

type rsaKeyValue struct {
	XMLName  xml.Name `xml:"RSAKeyValue"`
	Modulus  string   `xml:"Modulus,omitempty"`
	Exponent string   `xml:"Exponent,omitempty"`
	P        string   `xml:"P,omitempty"`
	Q        string   `xml:"Q,omitempty"`
	DP       string   `xml:"DP,omitempty"`
	DQ       string   `xml:"DQ,omitempty"`
	InverseQ string   `xml:"InverseQ,omitempty"`
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
	saveXML(privKey)
}

func saveXML(pk *rsa.PrivateKey) {
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

	pk.Precomputed.Dp.Bytes()

	fmt.Printf("n: %s\n", n)
	fmt.Printf("e: %s\n", e)
	fmt.Printf("d: %s\n", d)
	fmt.Printf("p: %s\n", p)
	fmt.Printf("q: %s\n", q)
	fmt.Printf("dp: %s\n", dp)
	fmt.Printf("dq: %s\n", dq)
	fmt.Printf("qinv: %s\n", qinv)

	rsaKey := &rsaKeyValue{
		Modulus:  n,
		Exponent: e,
		P:        p,
		Q:        q,
		DP:       dp,
		DQ:       dq,
		InverseQ: qinv,
	}

	enc := xml.NewEncoder(os.Stdout)
	enc.Indent("", "  ")
	if err := enc.Encode(rsaKey); err != nil {
		fmt.Printf("error: %v\n", err)
	}

	fmt.Print(spew.Sdump(rsaKey))
}

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
