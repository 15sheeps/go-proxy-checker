package proxychecker

import (
	"net/http"
	"net/http/httptrace"
	"net/url"
	"context"
	"h12.io/socks"
	"sync"
	"errors"
	"time"	
	"io/ioutil"
	"crypto/x509"
	"crypto/tls"	
	"log"
	"io"
	"strings"
	"bufio"
	"os"
	"fmt"
)

var ErrInvalidType = errors.New("Invalid proxy type (http(s)/socks4/socks5 are allowed)")
var ErrParsingProxy = errors.New("Unable to parse proxy URL")

type ConditionCallback func(r *http.Response) bool

type ProxyType int
const (
	TypeUnknown ProxyType = iota
	TypeHTTP
	TypeHTTPS
	TypeSOCKS4
	TypeSOCKS4A
	TypeSOCKS5
)

var PossibleTypes = []ProxyType{
	TypeHTTP,
	TypeSOCKS4,
	TypeSOCKS5,
}

type Checker struct {
	Workers int
	Endpoint string
	UserAgent string
	CertificatePath string
	Condition ConditionCallback
	Timeout time.Duration
	proxies []Proxy
	goodProxies []Proxy
	caCertPool *x509.CertPool
}

type Proxy struct {
	HostPort string
	Type ProxyType
	RequestTime int
}

func (checker *Checker) LoadFromURL(url string, proxyType ProxyType) error {
    resp, err := http.Get(url)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    scanner := bufio.NewScanner(resp.Body)

    for scanner.Scan() {
    	var proxy Proxy
        proxy.HostPort = scanner.Text()
        proxy.Type = proxyType

        checker.proxies = append(checker.proxies, proxy)
    }

    if err := scanner.Err(); err != nil {
        return err
    }

    return nil
}

func (checker *Checker) LoadFromFile(path string, proxyType ProxyType) error {
    file, err := os.Open(path)
    if err != nil {
        return err
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)

    for scanner.Scan() {
    	var proxy Proxy
        proxy.HostPort = scanner.Text()
        proxy.Type = proxyType

        checker.proxies = append(checker.proxies, proxy)
    }

    if err := scanner.Err(); err != nil {
        return err
    }

    return nil
}

func (checker *Checker) ClearProxies() {
	checker.proxies = nil
}

func (checker *Checker) check(p Proxy) {
	switch p.Type {
	case TypeUnknown:
		for _, proxyType := range PossibleTypes {
			pTyped := p
			pTyped.Type = proxyType
			checker.checkTyped(pTyped)
		}
	default:
		checker.checkTyped(p)
	}
}

func (checker *Checker) CheckProxies() []Proxy {
	if checker.CertificatePath != "" {
	    caCert, err := ioutil.ReadFile(checker.CertificatePath)
	    if err != nil {
	        log.Fatalln(err)
	    }

	    checker.caCertPool = x509.NewCertPool()
	    checker.caCertPool.AppendCertsFromPEM(caCert)
	}

	checker.goodProxies = nil

	if checker.Workers <= 0 {checker.Workers = 1}

	feeder := make(chan Proxy, checker.Workers)

    var wg sync.WaitGroup
    for i := 0; i < checker.Workers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for proxy := range feeder {
            	checker.check(proxy)
            }
        }()
    }

    for _, proxy := range checker.proxies {
        feeder <- proxy
    }
    close(feeder)
    wg.Wait()

    return checker.goodProxies
}

func (p Proxy) ToURL() (*url.URL, error) {
	var schemedProxy string

	switch p.Type {
	case TypeHTTP, TypeHTTPS:
		schemedProxy = "http://" + p.HostPort
	case TypeSOCKS4, TypeSOCKS4A:
		schemedProxy = "socks4://" + p.HostPort
	case TypeSOCKS5:
		schemedProxy = "socks5://" + p.HostPort
	default:
		return nil, ErrInvalidType
	}	

	proxyURL, err := url.Parse(schemedProxy)
	if err != nil {
		return nil, ErrParsingProxy
	}

	return proxyURL, nil
}

func (checker *Checker) checkTyped(p Proxy) {
	var t0, t1 time.Time

    req, err := http.NewRequest("GET", checker.Endpoint, nil)
    if err != nil {
    	return
    }

    if checker.UserAgent != "" {
		req.Header.Set("User-Agent", checker.UserAgent)
    }

	trace := &httptrace.ClientTrace{
		GetConn: func(_ string) {
			t0 = time.Now()
		},
		GotFirstResponseByte: func() {
			t1 = time.Now()
		},
	}

	req = req.WithContext(httptrace.WithClientTrace(context.Background(), trace))

	proxyURL, err := p.ToURL()
	if err != nil {
		return
	}

	var transport *http.Transport
	switch p.Type {
	case TypeHTTP:
		transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
	case TypeSOCKS4, TypeSOCKS5:
		transport = &http.Transport{
			Dial: socks.Dial(proxyURL.String()),
		}	
	default:
		return
	}

	transport.DisableKeepAlives = true

	transport.TLSClientConfig = &tls.Config{
        RootCAs: checker.caCertPool,
     }

	client := &http.Client{
		Transport: transport,
		Timeout: checker.Timeout,
	}

	response, err := client.Do(req)
	if err != nil {
		return
	}

	if checker.Condition(response) {
		goodProxy := p
		goodProxy.RequestTime = int((t1.Sub(t0)) / time.Millisecond)

		checker.goodProxies = append(checker.goodProxies, goodProxy)
	}

	return
}