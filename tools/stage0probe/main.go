package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"masterdnsvpn-go/internal/client"
)

func main() {
	var domain string
	var key string
	var ip string
	var port int
	var timeoutSec int

	flag.StringVar(&domain, "domain", "", "tunnel domain (instance domain)")
	flag.StringVar(&key, "key", "", "raw encryption key (hex string)")
	flag.StringVar(&ip, "ip", "", "resolver ip")
	flag.IntVar(&port, "port", 53, "resolver port")
	flag.IntVar(&timeoutSec, "timeout", 4, "probe timeout seconds")
	flag.Parse()

	if domain == "" || key == "" || ip == "" || port <= 0 || port > 65535 {
		fmt.Println("missing/invalid args")
		flag.Usage()
		return
	}

	p, err := client.NewStage0Prober(domain, 1, key)
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec+2)*time.Second)
	defer cancel()

	res, _ := p.Probe(ctx, ip, port, time.Duration(timeoutSec)*time.Second)
	fmt.Printf("domain=%s ep=%s:%d ok=%v fail=%s sub=%s rtt_ms=%.1f\n",
		domain, ip, port, res.OK, res.FailReason, res.SubReason, res.RTTms)
}

