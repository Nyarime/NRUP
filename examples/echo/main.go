package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/nyarime/nrup"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go [server|client]")
		return
	}
	cfg := nrup.DefaultConfig()
	switch os.Args[1] {
	case "server":
		listener, err := nrup.Listen(":4000", cfg)
		if err != nil { log.Fatal(err) }
		defer listener.Close()
		log.Println("Listening on :4000")
		for {
			s, err := listener.Accept()
			if err != nil { continue }
			go func() {
				defer s.Close()
				buf := make([]byte, 4096)
				for {
					n, err := s.Read(buf)
					if err != nil { return }
					log.Printf("← %s", buf[:n])
					s.Write(buf[:n])
				}
			}()
		}
	case "client":
		s, err := nrup.Dial("127.0.0.1:4000", cfg)
		if err != nil { log.Fatal(err) }
		defer s.Close()
		for i := 0; i < 5; i++ {
			msg := fmt.Sprintf("Hello #%d", i)
			s.Write([]byte(msg))
			buf := make([]byte, 4096)
			n, _ := s.Read(buf)
			log.Printf("→ %s ← %s", msg, buf[:n])
			time.Sleep(time.Second)
		}
		log.Printf("Stats: %+v", s.Stats())
	}
}
