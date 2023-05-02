package main

import (
	"net/http"
	"net/url"
	"h12.io/socks"
	"sync"
	"errors"
	"time"
	"bufio"
	"os"
	"fmt"
)

var wg sync.WaitGroup

type ProxyChecker struct {
	Proxies []*url.URL
	Timeout int
	Concurrent int
	Endpoint string
	ProxyType string
}

type ConditionCallback func(r *http.Response) bool

func (p *ProxyChecker) LoadProxies(path string) error {
	switch p.ProxyType {
	case "http", "socks4", "socks5":
		break
	default:
		return errors.New("Invalid type of proxy.")
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		proxyUrl := fmt.Sprintf("%s://%s", p.ProxyType, scanner.Text())
		proxy, err := url.Parse(proxyUrl)
		if err != nil {
			continue
		}

		p.Proxies = append(p.Proxies, proxy)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func (p ProxyChecker) CheckProxies(condition ConditionCallback) (goodProxies []*url.URL) {
	if p.Concurrent <= 0 {
		p.Concurrent = 1
	}

    var limit = make(chan struct{}, p.Concurrent)

	for _, proxy := range p.Proxies {
		wg.Add(1)

        go func(proxy *url.URL) {
        	limit <- struct{}{}
        	if (p.CheckProxy(proxy, condition) == true) {
        		goodProxies = append(goodProxies, proxy)
        	}

        	<- limit
        	wg.Done()
        }(proxy)
	}

    wg.Wait() 

    return goodProxies
}

func (p ProxyChecker) CheckProxy(proxy *url.URL, condition ConditionCallback) bool {
	var transport *http.Transport
	switch p.ProxyType {
	case "socks4", "socks5":
		transport = &http.Transport{
			Dial: socks.Dial(proxy.String()),
		}	
	case "http":
		transport = &http.Transport{
			Proxy: http.ProxyURL(proxy),
		}
	default:
		return false
	}

	client := &http.Client{
		Transport: transport,
		Timeout: time.Duration(p.Timeout) * time.Second,
	}

	response, err := client.Get(p.Endpoint)
	if err != nil {
		return false
	}

	result := condition(response)

	response.Body.Close()

	return result
}