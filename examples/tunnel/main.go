package main

import (
	"crypto/sha256"
	"flag"
	"log"
	"net"

	"github.com/nyarime/nrup"
)

// nrup-tunnel: UDP端口转发（加密隧道）
//
// 用法:
//   服务端: nrup-tunnel -mode server -listen :4000 -forward 127.0.0.1:53 -password secret
//   客户端: nrup-tunnel -mode client -server 1.2.3.4:4000 -listen :1053 -password secret
//
// 效果: 本地UDP:1053 ← NRUP加密隧道 → 远端UDP:53
//
// 场景:
//   DNS加密转发
//   游戏服务器UDP中继
//   音视频UDP加速
//
// 注意: 仅支持UDP转发。TCP转发请使用 NekoPass Lite。

func main() {
	mode := flag.String("mode", "", "server / client")
	listen := flag.String("listen", "", "监听地址")
	server := flag.String("server", "", "服务端地址 (client模式)")
	forward := flag.String("forward", "", "转发目标 (server模式)")
	password := flag.String("password", "", "密码")
	cipher := flag.String("cipher", "auto", "加密: auto/none")
	disguise := flag.String("disguise", "none", "伪装: anyconnect/quic/none")
	flag.Parse()

	if *password == "" {
		log.Fatal("需要 -password")
	}

	switch *mode {
	case "server":
		if *listen == "" || *forward == "" {
			log.Fatal("server模式需要 -listen 和 -forward")
		}
		runServer(*listen, *forward, *password, *cipher, *disguise)
	case "client":
		if *server == "" || *listen == "" {
			log.Fatal("client模式需要 -server 和 -listen")
		}
		runClient(*server, *listen, *password, *cipher, *disguise)
	default:
		log.Fatal("需要 -mode server 或 -mode client")
	}
}

func makeCfg(password, cipher, disguise string) *nrup.Config {
	cfg := nrup.DefaultConfig()
	h := sha256.Sum256([]byte("nrup-tunnel:" + password))
	cfg.PSK = h[:]
	if cipher == "none" {
		cfg.Cipher = nrup.CipherNone
	}
	cfg.Disguise = disguise
	return cfg
}

// runServer NRUP监听 → 转发到本地UDP服务
func runServer(listenAddr, forwardAddr, password, cipher, disguise string) {
	cfg := makeCfg(password, cipher, disguise)
	listener, err := nrup.Listen(listenAddr, cfg)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("UDP Tunnel Server %s → %s", listenAddr, forwardAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer conn.Close()

			rAddr, err := net.ResolveUDPAddr("udp", forwardAddr)
			if err != nil {
				return
			}
			local, err := net.DialUDP("udp", nil, rAddr)
			if err != nil {
				return
			}
			defer local.Close()

			// NRUP → 本地UDP
			go func() {
				buf := make([]byte, 4096)
				for {
					n, err := conn.Read(buf)
					if err != nil { return }
					local.Write(buf[:n])
				}
			}()

			// 本地UDP → NRUP
			buf := make([]byte, 4096)
			for {
				n, err := local.Read(buf)
				if err != nil { return }
				conn.Write(buf[:n])
			}
		}()
	}
}

// runClient 本地UDP监听 → NRUP连接到远端
func runClient(serverAddr, listenAddr, password, cipher, disguise string) {
	cfg := makeCfg(password, cipher, disguise)

	lAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	local, err := net.ListenUDP("udp", lAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("UDP Tunnel Client %s → %s", listenAddr, serverAddr)

	buf := make([]byte, 4096)
	var clientAddr *net.UDPAddr
	var remote *nrup.Conn

	for {
		n, addr, err := local.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		if remote == nil {
			clientAddr = addr
			remote, err = nrup.Dial(serverAddr, cfg)
			if err != nil {
				log.Printf("NRUP连接失败: %v", err)
				continue
			}
			// 远端 → 本地
			go func() {
				rbuf := make([]byte, 4096)
				for {
					n, err := remote.Read(rbuf)
					if err != nil { return }
					local.WriteToUDP(rbuf[:n], clientAddr)
				}
			}()
		}

		remote.Write(buf[:n])
	}
}
