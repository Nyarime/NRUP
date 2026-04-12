package main

import (
	"fmt"
	"os"
	"time"

	"github.com/nyarime/nrup"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run bench.go [server|client] [addr]")
		return
	}

	cfg := &nrup.Config{
		FECData:      5,
		FECParity:    2,
		MaxBandwidthMbps: 1000,
	}

	addr := "127.0.0.1:12345"
	if len(os.Args) > 2 {
		addr = os.Args[2]
	}

	switch os.Args[1] {
	case "server":
		listener, err := nrup.Listen(addr, cfg)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer listener.Close()
		fmt.Printf("Server listening on %s\n", addr)

		for {
			session, err := listener.Accept()
			if err != nil {
				continue
			}
			go func() {
				defer session.Close()
				buf := make([]byte, 4096)
				for {
					n, err := session.Read(buf)
					if err != nil {
						return
					}
					session.Write(buf[:n])
				}
			}()
		}

	case "client":
		count := 1000
		size := 1024

		session, err := nrup.Dial(addr, cfg)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer session.Close()

		data := make([]byte, size)
		start := time.Now()
		sent := 0

		for i := 0; i < count; i++ {
			if _, err := session.Write(data); err == nil {
				sent++
			}
		}

		elapsed := time.Since(start)
		pps := float64(sent) / elapsed.Seconds()
		mbps := float64(sent*size) * 8 / elapsed.Seconds() / 1_000_000

		fmt.Printf("NRUP: %d packets in %v\n", sent, elapsed)
		fmt.Printf("NRUP pps: %.0f\n", pps)
		fmt.Printf("NRUP throughput: %.1f Mbps\n", mbps)
		fmt.Printf("Stats: %+v\n", session.Stats())
	}
}
