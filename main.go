package main

import (
	"fmt"
)

func main() {
	// p, c := GenCSR()
	// fmt.Println(string(c))
	// fmt.Println(string(p))
	est_server_url := "https://testrfc7030.com:8443"
	fmt.Println(string(GetCaCert(est_server_url)))
}
