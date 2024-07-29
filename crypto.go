package estclient_go

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"unicode"
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
	csrBytes = pem.EncodeToMemory(&block)
	return privKey, csrBytes
}

// read PKCS7 response
// cat base_pkcs| base64 -d | openssl pkcs7 -inform DER -outform PEM -print_certs
func GetWithCA(ca_file, url string, headers map[string]string, data []byte, method string, username string, password string) []byte {
	// Load the CA certificate
	// wget http://testrfc7030.com/dstcax3.pem
	m := "GET"
	if method != "" {
		m = method
	}
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

	client := &http.Client{
		Transport: transport,
	}
	// Create a new request with custom headers
	req, err := http.NewRequest(m, url, bytes.NewReader(data))
	if err != nil {
		fmt.Println("Error creating request:", err)
	}

	// Add custom headers
	for k, v := range headers {
		req.Header.Add(k, v)
	}

	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
	}
	defer resp.Body.Close()

	// Read and print the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
	}
	// fmt.Println("---------------")
	// fmt.Println(string(body))
	// fmt.Println("---------------")
	// fmt.Println(resp.Status)
	// output, _ := pkcs7ToPem(body)
	// fmt.Println(output)
	// fmt.Println("%v", resp.Header)

	return body
}

// curl https://testrfc7030.com:8443/.well-known/est/cacerts -o cacerts.p7 --cacert ./dstcax3.pem
// openssl base64 -d -in cacerts.p7m | openssl pkcs7 -inform DER -outform PEM -print_certs
func GetCaCert(est_url string) []byte {
	url := est_url + "/.well-known/est/cacerts"
	return GetWithCA("assets/dstcax3.pem", url, nil, nil, "", "", "")
}

func SimpleEnroll(est_url string, csr []byte) []byte {
	url := est_url + "/.well-known/est/simpleenroll"
	headers := map[string]string{
		"Content-Type": "application/pkcs10",
	}
	return GetWithCA("assets/dstcax3.pem", url, headers, csr, "POST", "estuser", "estpwd")
}

func SimpleReEnroll(est_url string, csr []byte) []byte {
	url := est_url + "/.well-known/est/simplereenroll"
	headers := map[string]string{
		"Content-Type": "application/pkcs10",
	}
	return GetWithCA("assets/dstcax3.pem", url, headers, csr, "POST", "estuser", "estpwd")
}

func pkcs7ToPem(pkcs7 []byte) (string, error) {
	var inform string
	var out, err bytes.Buffer

	for _, filetype := range []string{"PEM", "DER"} {
		cmd := exec.Command("openssl", "pkcs7", "-inform", filetype, "-outform", "PEM", "-print_certs")
		cmd.Stdin = bytes.NewReader(pkcs7)

		cmd.Stdout = &out
		cmd.Stderr = &err

		run_err := cmd.Run()
		if run_err == nil {
			inform = filetype
			break
		}
	}

	if inform == "" {
		return "", errors.New("invalid PKCS7 data type")
	}

	return fmt.Sprintf(out.String(), err.String()), nil
}

// curl https://testrfc7030.com:8443/.well-known/est/csrattrs -s --cacert ./dstcax3.pem | openssl base64 -d -A | openssl asn1parse -inform DER
func CSRAttr(est_url string, csr []byte) asn1.RawValue {
	url := est_url + "/.well-known/est/csrattrs"
	bin_data := GetWithCA("assets/dstcax3.pem", url, nil, csr, "", "estuser", "estpwd")
	bin_data_str := removeNonPrintable(string(bin_data))
	data, err := base64.StdEncoding.DecodeString(string(bin_data_str))
	if err != nil {
		log.Fatalf("Error decoding base64 string: %v", err)
	}

	// Parse ASN.1 DER encoded data
	var parsedData asn1.RawValue
	_, err = asn1.Unmarshal(data, &parsedData)
	if err != nil {
		log.Fatalf("Error parsing ASN.1 DER data: %v", err)
	}
	return parsedData
}

func removeNonPrintable(input string) string {
	var result []rune
	for _, r := range input {
		if unicode.IsPrint(r) {
			result = append(result, r)
		}
	}
	return string(result)
}
