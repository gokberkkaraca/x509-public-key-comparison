package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

var pathToCertificates = "/Users/gokberkkaraca/workspace/umiacs/certificates/certs_newer_2015/"

type caFilePair struct {
	caName   string
	fileName string
}

func main() {
	list := make(map[string]caFilePair)

	fmt.Println("Starting certificate classifier")
	files, err := ioutil.ReadDir(pathToCertificates)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("All the certificates in the directory are read")
	fmt.Println("Starting to parse certificates")

	count := 0
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		var inputFile *os.File
		var err error
		inputFile, err = os.Open(pathToCertificates + file.Name())
		if err != nil {
			log.Fatalf("unable to open file %s: %s", file.Name(), err)
		}
		cert, err := parseCertificateFromFile(inputFile)
		if err == nil {
			caName := cert.Issuer.Organization[0]
			rawPK := cert.RawSubjectPublicKeyInfo
			strPK := string(rawPK)

			caFilePairInstance, contains := list[strPK]
			if contains {
				fmt.Println("Found duplicate")
				fmt.Println(caName, caFilePairInstance.caName, file.Name(), caFilePairInstance.fileName)
				count++
			} else {
				list[strPK] = caFilePair{caName: caName, fileName: file.Name()}
			}
		}
		inputFile.Close()
	}
	fmt.Println(count)
}

func parseCertificateFromFile(inputFile *os.File) (x509.Certificate, error) {
	var fileFmt = ""
	if strings.HasSuffix(inputFile.Name(), "pem") {
		fileFmt = "pem"
	}
	if strings.HasSuffix(inputFile.Name(), "der") {
		fileFmt = "der"
	}

	fileBytes, err := ioutil.ReadAll(inputFile)
	if err != nil {
		log.Fatalf("unable to read file %s: %s", inputFile.Name(), err)
	}

	var asn1Data []byte
	switch fileFmt {
	case "pem":
		p, _ := pem.Decode(fileBytes)
		if p == nil || p.Type != "CERTIFICATE" {
			log.Fatal("unable to parse PEM")
		}
		asn1Data = p.Bytes
	case "der":
		asn1Data = fileBytes
	default:
		log.Fatalf("unknown input format %s", fileFmt)
	}

	c, err := x509.ParseCertificate(asn1Data)
	if err == nil {
		return *c, err
	}
	fmt.Println("Unable to parse certificate: ", inputFile.Name())
	return x509.Certificate{}, err
}
