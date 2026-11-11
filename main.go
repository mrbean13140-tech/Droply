package main

import (
	"fmt"
	"os"
)

// Один бинарник:
//
//	PID 1 в LXC  -> init: сеть, cloudflared, супервизор
//	landrop serve -> HTTP-сервис (запускается init'ом без прав)
func main() {
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		cfg, err := loadConfig()
		if err != nil {
			fmt.Fprintln(os.Stderr, "config:", err)
			os.Exit(1)
		}
		serve(cfg)
		return
	}
	if os.Getpid() == 1 {
		runInit()
		return
	}
	fmt.Println("usage: landrop serve   (или запуск как PID 1 в контейнере)")
}
