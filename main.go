package main

import (
	"fmt"
	"io/ioutil"
	"os"

	gokt_utils "github.com/jasonwbarnett/gokt/utils"
	flag "github.com/spf13/pflag"
)

func main() {
	inputFilename := flag.String("in", "", "input file")
	inputFileBase64 := flag.Bool("b64", false, "use this flag if the input file is base64 encoded")
	outputFilename := flag.String("out", "", "the output filename. If this argument is not specified then standard output is used.")
	flag.Parse()

	if *inputFilename == "" {
		fmt.Println("You must provide an input file path, exiting...")
		flag.PrintDefaults()
		os.Exit(1)
	}

	msRSA, err := gokt_utils.ReadFileAndParseXMLRSAKey(*inputFilename, *inputFileBase64)
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}

	RSA := msRSA.GetRSAPrivateKey()

	if *outputFilename == "" {
		os.Stderr.WriteString("Converted " + *inputFilename + ":\n")
		fmt.Print(string(gokt_utils.RSAPrivateKeyToEncodedPEM(RSA)))
		fmt.Print(string(gokt_utils.RSAPublicKeyToEncodedPEM(RSA)))
	} else {
		os.Stderr.WriteString("Saving to " + *outputFilename + "\n")
		ioutil.WriteFile(*outputFilename, gokt_utils.RSAPrivateKeyToEncodedPEM(RSA), 0600)
		ioutil.WriteFile(*outputFilename+".pub", gokt_utils.RSAPublicKeyToEncodedPEM(RSA), 0644)
	}
}
