package proxychecker

import (
	"net/http"
	"net/url"
	"h12.io/socks"
	"sync"
	"errors"
	"time"	
	"io/ioutil"
	"crypto/x509"
	"crypto/tls"	
	"log"
	"bufio"
	"os"
)

var ErrInvalidType = errors.New("Invalid proxy type [http(s)/socks4(a)/socks5 are allowed]")
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
	proxies []proxy
	goodProxies []*url.URL
	caCertPool *x509.CertPool
}

type proxy struct {
	HostPort string
	Type ProxyType
}

func (checker *Checker) LoadFromURL(url string, proxyType ProxyType) error {
    resp, err := http.Get(url)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    scanner := bufio.NewScanner(resp.Body)

    for scanner.Scan() {
    	var p proxy
        p.HostPort = scanner.Text()
        p.Type = proxyType

        checker.proxies = append(checker.proxies, p)
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
    	var p proxy
        p.HostPort = scanner.Text()
        p.Type = proxyType

        checker.proxies = append(checker.proxies, p)
    }

    if err := scanner.Err(); err != nil {
        return err
    }

    return nil
}

func (checker *Checker) ClearProxies() {
	checker.proxies = nil
}

func (checker *Checker) check(p proxy) {
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

func (checker *Checker) CheckProxies() []*url.URL {
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

	feeder := make(chan proxy, checker.Workers)

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

func (p proxy) ToURL() (*url.URL, error) {
	var schemedProxy string

	switch p.Type {
	case TypeHTTP, TypeHTTPS:
		schemedProxy = "http://" + p.HostPort
	case TypeSOCKS4:
		schemedProxy = "socks4://" + p.HostPort
	case TypeSOCKS4A:
		schemedProxy = "socks4a://" + p.HostPort
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

func (checker *Checker) checkTyped(p proxy) {
    req, err := http.NewRequest("GET", checker.Endpoint, nil)
    if err != nil {
    	return
    }

    if checker.UserAgent != "" {
		req.Header.Set("User-Agent", checker.UserAgent)
    }

	proxyURL, err := p.ToURL()
	if err != nil {
		return
	}

	var transport *http.Transport
	switch p.Type {
	case TypeHTTP, TypeHTTPS:
		transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
	case TypeSOCKS4, TypeSOCKS4A, TypeSOCKS5:
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
		checker.goodProxies = append(checker.goodProxies, proxyURL)
	}

	return
}