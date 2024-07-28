package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

func GenCSR() ([]byte, []byte) {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 1024)

	emailAddress := "test@example.com"
	subj := pkix.Name{
		CommonName:         "example.com",
		Country:            []string{"AU"},
		Province:           []string{"Some-State"},
		Locality:           []string{"MyCity"},
		Organization:       []string{"Company Ltd"},
		OrganizationalUnit: []string{"IT"},
	}
	rawSubj := subj.ToRDNSequence()
	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: emailAddress},
	})

	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		EmailAddresses:     []string{emailAddress},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// create CSR
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	// pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	block := pem.Block{
		Type:  "RSA Key",
		Bytes: x509.MarshalPKCS1PrivateKey(keyBytes),
	}
	privKey := pem.EncodeToMemory(&block)
	block = pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}
	return privKey, csrBytes
}

func GetWithCA(ca_file, url string) []byte {
	// Load the CA certificate
	// wget http://testrfc7030.com/dstcax3.pem
	caCert, err := ioutil.ReadFile(ca_file)
	if err != nil {
		fmt.Println("Error reading CA certificate:", err)
	}
	// Create a CA certificate pool
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create a custom Transport with the CA certificate pool
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}

	// Create a custom HTTP client with the transport
	client := &http.Client{
		Transport: transport,
	}
	// url := est_url + "/.well-known/est/cacerts"
	resp, err := client.Get(url)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return body
}

// curl https://testrfc7030.com:8443/.well-known/est/cacerts -o cacerts.p7 --cacert ./dstcax3.pem
// openssl base64 -d -in cacerts.p7m | openssl pkcs7 -inform DER -outform PEM -print_certs
func GetCaCert(est_url string) []byte {
	url := est_url + "/.well-known/est/cacerts"
	return GetWithCA("dstcax3.pem", url)
}

// func SimpleEnroll(csr []bytes) {
// 	url := c.URLPrefix + "/.well-known/est/simpleenroll"
// 	headers := map[string]string{
// 		"Content-Type": "application/pkcs10",
// 	}

// }
