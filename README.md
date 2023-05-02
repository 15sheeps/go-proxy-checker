
# go-proxy-checker

Just another simple proxy checker.


## Basic code example

```
package main

import (
	"github.com/15sheeps/go-proxy-checker"
	"io"
	"log"
	"net/http"
	"strings"
	"fmt"
)

func main() {
	checker := checker.ProxyChecker{
		Timeout: 5,
		Concurrent: 800,
		Endpoint: "https://stackoverflow.com",
		ProxyType: "http",
	}

	if err := checker.LoadProxies("proxies.txt"); err != nil {
		log.Fatalln(err)
	}
	
	goodProxies := checker.CheckProxies(func (r *http.Response) bool {
		body, _ := io.ReadAll(r.Body)

		page := string(body)

		return (strings.Contains(page, "community for developers") && (r.StatusCode == 200))
	}) 

	for _, proxy := range goodProxies {
		fmt.Println(proxy.String())
	}
}
```