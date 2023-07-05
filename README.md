
# go-proxy-checker

Just another simple proxy checker.


## Usage example

```
func main() {
	checker := Checker{
		Timeout: time.Duration(5) * time.Second,
		Workers: 6000,
		Endpoint: "https://stackoverflow.com/",
		Condition: func (r *http.Response) bool {
			body, _ := io.ReadAll(r.Body)

			page := string(body)

			return (strings.Contains(page, "community for developers") || (r.StatusCode == 200))
		},
	}

	data := map[string]ProxyType{
		"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt": TypeSOCKS5,
		"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt": TypeSOCKS4,
		"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt": TypeHTTP,
		"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt": TypeHTTPS,
		"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt": TypeHTTP,
		"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt": TypeSOCKS4,
		"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt": TypeSOCKS5,
	}

	for url, proxyType := range data {
		err := checker.LoadFromURL(url, proxyType)
		if err != nil {
			log.Println("Unable to read", url)
		}
	}
	
	goodProxies := checker.CheckProxies() 

	for _, proxy := range goodProxies {
		fmt.Println(proxy.HostPort, fmt.Sprintf("%7dms", proxy.RequestTime))
	}
}
```
