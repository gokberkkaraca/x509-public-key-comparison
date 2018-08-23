package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
)

type certInfo struct {
	CaName                string   `json:"CaName"`
	SubjectName           string   `json:"SubjectName"`
	FileName              string   `json:"FileName"`
	SerialNumber          string   `json:"SerialNumber"`
	OCSP                  []string `json:"OCSP"`
	CrlPoints             []string `json:"CrlPoints"`
	IssuingCertificateURL []string `json:"IssuingCertificateURL"`
	Revocation            string   `json:Revocation"`
}

func main() {

	if len(os.Args[1:]) != 1 {
		log.Fatal("Wrong number of arguments")
	}

	pathToCertificates := os.Args[1]

	pkCertMap := extractInfoFromCertificates(pathToCertificates)
	duplicateMap := filterCertMap(pkCertMap)

	jsonData, _ := json.MarshalIndent(duplicateMap, "", "  ")
	fmt.Println(string(jsonData))
}

func filterCertMap(pkCertMap map[string][]certInfo) map[string][]certInfo {
	var filteredMap = make(map[string][]certInfo)
	count := 1
	for _, value := range pkCertMap {
		newKey := "key_" + strconv.Itoa(count)
		if len(value) > 1 {
			filteredMap[newKey] = value
		}
		count++
	}

	return filteredMap
}

func extractInfoFromCertificates(pathToCertificates string) map[string][]certInfo {
	files, err := ioutil.ReadDir(pathToCertificates)
	if err != nil {
		log.Fatal(err)
	}

	pkCertMap := make(map[string][]certInfo)

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
			caName := "null"
			if len(cert.Issuer.Organization) != 0 {
				caName = cert.Issuer.Organization[0]
			}

			subjectName := "null"
			if len(cert.Subject.Organization) != 0 {
				subjectName = cert.Subject.Organization[0]
			}

			rawPK := cert.RawSubjectPublicKeyInfo
			strPK := string(rawPK)

			serialNumber := cert.SerialNumber.String()
			OCSP := cert.OCSPServer
			CrlPoints := cert.CRLDistributionPoints
			IssuingCertificateURL := cert.IssuingCertificateURL
			revocationStatus := "Unknown"

			certList, _ := pkCertMap[strPK]
			pkCertMap[strPK] = append(certList, certInfo{CaName: caName, SubjectName: subjectName, FileName: file.Name(), SerialNumber: serialNumber, OCSP: OCSP, CrlPoints: CrlPoints, IssuingCertificateURL: IssuingCertificateURL, Revocation: revocationStatus})
		}
		inputFile.Close()
	}

	return pkCertMap
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
