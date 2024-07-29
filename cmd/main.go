package main

import (
	"fmt"

	"github.com/bl9/estclient_go"
)

func main() {
	est_server_url := "https://testrfc7030.com:8443"
	fmt.Println(string(estclient_go.GetCaCert(est_server_url)))
	_, c := estclient_go.GenCSR()
	fmt.Println(string(estclient_go.SimpleEnroll(est_server_url, c)))
	fmt.Println(string(estclient_go.SimpleReEnroll(est_server_url, c)))
	parsedData := estclient_go.CSRAttr(est_server_url, c)
	fmt.Println("Parsed ASN.1 Data:")
	fmt.Printf("Tag: %d\n", parsedData.Tag)
	fmt.Printf("Class: %d\n", parsedData.Class)
	fmt.Printf("Is Compound: %v\n", parsedData.IsCompound)
	fmt.Printf("Bytes: %x\n", parsedData.Bytes)

}
