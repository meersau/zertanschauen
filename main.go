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

	go func() {
		buf := new(bytes.Buffer)
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := scanner.Text()
			buf.WriteString(line + "\n")
			if line == "-----END CERTIFICATE-----" {
				zert <- buf.Bytes()
				buf.Reset()
			}
		}
		close(zert)
	}()

	for z := range zert {
		block, _ := pem.Decode(z)
		if block == nil {
			fmt.Print("could not find PEM Block\n")
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
