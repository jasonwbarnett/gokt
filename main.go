package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"strconv"

	"github.com/davecgh/go-spew/spew"
)

func main() {
	keyBytes, err := ioutil.ReadFile("test.key")
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
}

func saveXml(pk *rsa.PrivateKey) {
	n := base64.StdEncoding.EncodeToString(pk.PublicKey.N.Bytes())
	e_bytes := []byte(strconv.Itoa(pk.PublicKey.E))
	e := base64.StdEncoding.EncodeToString(e_bytes)

	fmt.Println(e)
	fmt.Println(n)
}
