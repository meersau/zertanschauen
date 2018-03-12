// Alexander Koch <alex@meersau.de>
// 2018-02-14
package main

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	zert := make(chan []byte)
	var reader *os.File
	var err error
	if len(os.Args) == 2 {
		reader, err = os.Open(os.Args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "can't open %s for reading: %s\n", os.Args[1], err)
			os.Exit(1)
		}
		defer reader.Close()
	} else {
		reader = os.Stdin
	}

	go func() {
		buf := new(bytes.Buffer)
		foundzert := false
		scanner := bufio.NewScanner(reader)

		for scanner.Scan() {
			line := scanner.Text()
			if line == "-----BEGIN CERTIFICATE-----" {
				foundzert = true
			}
			if foundzert {
				buf.WriteString(line + "\n")
			}
			if line == "-----END CERTIFICATE-----" {
				zert <- buf.Bytes()
				buf.Reset()
				foundzert = false
			}
		}
		close(zert)
	}()

	for z := range zert {
		block, rest := pem.Decode(z)
		if block == nil {
			fmt.Printf("could not find PEM Block\n%s\n", rest)
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Printf("could parse x509 certificate: %v\n", err)
		}

		fmt.Printf("Subject: %s\n", cert.Subject.CommonName)
		fmt.Printf("Issuer: %s\n", cert.Issuer.Organization)
		fmt.Printf("not after: %s\n", cert.NotAfter.Format("2006-01-02"))
	}

}
