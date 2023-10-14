//go:build cgo

package main

import "C"

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kopp0ut/icepick/agent"
	"github.com/kopp0ut/icepick/share/cos"
)

func main() {
	//does nothing
}

//export mainDelegate
func mainDelegate(charargs *C.char) {
	var stringargs string
	stringargs = C.GoString(charargs)
	arrayargs := strings.Fields(stringargs)
	fmt.Println(arrayargs)

	f1 := flag.NewFlagSet("f1", flag.ContinueOnError)

	f1.Usage = func() {}
	f1.Parse(arrayargs)

	args := f1.Args()

	icePick(args)

}

// Agent stuff here.
func icePick(cargs []string) {
	flags := flag.NewFlagSet("client", flag.ContinueOnError)
	config := agent.Config{Headers: http.Header{}}
	flag.StringVar(&config.Fingerprint, "fingerprint", "", "")
	flag.StringVar(&config.Auth, "auth", "", "")
	flag.DurationVar(&config.KeepAlive, "keepalive", 25*time.Second, "")
	flag.IntVar(&config.MaxRetryCount, "max-retry-count", -1, "")
	flag.DurationVar(&config.MaxRetryInterval, "max-retry-interval", 0, "")
	flag.StringVar(&config.Proxy, "proxy", "", "")
	flag.StringVar(&config.TLS.CA, "tls-ca", "", "")
	flag.BoolVar(&config.TLS.SkipVerify, "tls-skip-verify", true, "")
	hostname := flag.String("hostname", "", "")
	sni := flag.String("sni", "", "Sets sni header - set to if domain fronting")
	ua := flag.String("ua", "", "")

	flags.Parse(cargs)
	//pull out options, put back remaining args
	args := flags.Args()
	if len(args) < 2 {
		log.Fatalf("A server and least one remote is required")
	}

	config.Server = args[0]
	config.Remotes = args[1:]
	//default auth
	if config.Auth == "" {
		config.Auth = os.Getenv("AUTH")
	}
	//move hostname onto headers
	if *hostname != "" {
		config.Headers.Set("Host", *hostname)
		config.TLS.ServerName = *hostname
	}

	if *ua != "" {
		config.Headers.Set("User-Agent", *ua)
	}

	if *sni != "" {
		config.TLS.ServerName = *sni
	}

	//ready
	c, err := agent.NewClient(&config)
	if err != nil {
		log.Fatal(err)
	}

	ctx := cos.InterruptContext()
	if err := c.Start(ctx); err != nil {
		log.Fatal(err)
	}
	if err := c.Wait(); err != nil {
		log.Fatal(err)
	}

}
