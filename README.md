# go-proxy-checker

Just another simple package to check proxies concurrently.

## Example

```go
package main

import (
	"time"
	"net/http"
	"io"
	"log"
	"fmt"
	"strings"
	"github.com/15sheeps/go-proxy-checker"
)

func main() {
	checker := &proxychecker.Checker{
		Timeout: time.Duration(5) * time.Second,
		Workers: 6000,
		Endpoint: "https://stackoverflow.com/",
		UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
		Condition: func (r *http.Response) bool {
			defer r.Body.Close()

			body, _ := io.ReadAll(r.Body)

			page := string(body)

			return (strings.Contains(page, "community for developers") || (r.StatusCode == 200))
		},
	}

	data := map[string]proxychecker.ProxyType{
		"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt": proxychecker.TypeSOCKS5,
		"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt": proxychecker.TypeSOCKS4,
		"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt": proxychecker.TypeHTTPS,
	}

	for url, proxyType := range data {
		err := checker.LoadFromURL(url, proxyType)
		if err != nil {
			log.Println("Unable to read", url)
		}
	}
	
	goodProxies := checker.CheckProxies()
	defer checker.ClearProxies()

	for _, proxy := range goodProxies {
		fmt.Println(proxy.String())
	}
}
```
