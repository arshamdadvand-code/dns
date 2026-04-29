package main

import (
	"flag"
	"fmt"

	"masterdnsvpn-go/internal/client"
)

func main() {
	var domain string
	var key string
	var method int

	flag.StringVar(&domain, "domain", "", "tunnel domain")
	flag.StringVar(&key, "key", "", "raw key (hex)")
	flag.IntVar(&method, "method", 1, "encryption method id")
	flag.Parse()

	if domain == "" || key == "" {
		fmt.Println("missing args")
		flag.Usage()
		return
	}

	_, err := client.NewInventoryProber(domain, method, key)
	if err != nil {
		fmt.Printf("ERR %v\n", err)
		return
	}
	fmt.Println("OK")
}

