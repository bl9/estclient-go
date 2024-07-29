package main

import (
	"fmt"
)

func main() {
	est_server_url := "https://testrfc7030.com:8443"
	fmt.Println(string(GetCaCert(est_server_url)))
	_, c := GenCSR()
	fmt.Println(string(SimpleEnroll(est_server_url, c)))
	fmt.Println(string(SimpleReEnroll(est_server_url, c)))
	parsedData := CSRAttr(est_server_url, c)
	fmt.Println("Parsed ASN.1 Data:")
	fmt.Printf("Tag: %d\n", parsedData.Tag)
	fmt.Printf("Class: %d\n", parsedData.Class)
	fmt.Printf("Is Compound: %v\n", parsedData.IsCompound)
	fmt.Printf("Bytes: %x\n", parsedData.Bytes)

}
