package main

import (
    "crypto/x509"
    "encoding/base64"
    "encoding/asn1"
    "encoding/pem"
    "fmt"
    "io/ioutil"
    "log"
    "os"
    "strings"
)

func main() {
    if len(os.Args) < 2 {
        log.Fatalf("Usage: %s <certificate.pem>\n", os.Args[0])
    }

    certPath := os.Args[1]
    pemData, err := ioutil.ReadFile(certPath)
    if err != nil {
        log.Fatalf("Failed to read certificate file: %v", err)
    }

    block, _ := pem.Decode(pemData)
    if block == nil || block.Type != "CERTIFICATE" {
        log.Fatalf("Failed to decode PEM block containing certificate")
    }

    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        log.Fatalf("Failed to parse certificate: %v", err)
    }

    serialNumber := cert.SerialNumber.Bytes()
    base64Serial := base64.StdEncoding.EncodeToString(serialNumber)
    base64Serial = strings.TrimRight(base64Serial, "=")
    // Extract Authority Key Identifier from Extensions
    var authorityKeyID []byte
    for _, ext := range cert.Extensions {
        if ext.Id.Equal([]int{2, 5, 29, 35}) { // OID for Authority Key Identifier
            var akiStruct struct {
                KeyIdentifier []byte `asn1:"optional,tag:0"`
            }
            _, err := asn1.Unmarshal(ext.Value, &akiStruct)
            if err != nil {
                log.Fatalf("Failed to parse Authority Key Identifier: %v", err)
            }
            authorityKeyID = akiStruct.KeyIdentifier
            break
        }
    }

    if authorityKeyID != nil {
        akiBase64 := base64.StdEncoding.EncodeToString(authorityKeyID)
        akiBase64 = strings.TrimRight(akiBase64, "=")
        fmt.Printf("%s.%s\n", akiBase64, base64Serial)
    } else {
        fmt.Println("Authority Key Identifier not found in certificate.")
    }

}
