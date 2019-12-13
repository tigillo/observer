package main

import (

	"bytes"
	"crypto/tls"
	"crypto/x509"
    "encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/maaydin/mitm"
)

var (
	dir      = path.Join(os.Getenv("HOME"), ".observer")
	keyFile  = path.Join(dir, "ca-key.pem")
	certFile = path.Join(dir, "ca-cert.pem")
 	uriPatterns = []uriPattern{}
	stats = map[string][]mitm.RequestStat{}
	splunkToken = "a872b444-a618-4cb0-bb28-e2b223a417c8"
	url = "https://localhost:8088/services/collector"
    c = &http.Client{Transport: &http.Transport{
    	DialContext: (&net.Dialer{
				Timeout:   90 * time.Second,
				KeepAlive: 90 * time.Second,
				DualStack: true,
			}).DialContext,
		TLSHandshakeTimeout: 30 * time.Second,
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }}
    queue = make(chan mitm.RequestStat, 100000)
)

type uriPattern struct {
    uriDisplay   string
    uriRegex     string
}

func main() {
	allUriPattern := uriPattern{"{all}", ".*"}
	//varUriPattern := uriPattern{"{var}", "[^/]*"}
	uriPatterns = append(uriPatterns, allUriPattern)
	for _, uriPattern := range uriPatterns {
	    stats[uriPattern.uriDisplay] = []mitm.RequestStat{}
	}

	ca, err := loadCA()
	if err != nil {
		log.Fatal("Failed to load CA", err)
	}
	p := &mitm.Proxy{
		CA: &ca,
		TLSServerConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			//CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
		},
		Analyze: analyze,
	}

	go func() {
		for true {
			payload := []byte{}
			for i := 0; i < 50000; i++ {
				select {
					case rr := <- queue:
						event := Testevent{Event: rr, Time: rr.EndTime.UnixNano()/1000000, Sourcetype: "_json"}
						jsonValue, err := json.Marshal(event)
						if err != nil {
							log.Println("Failed to create json data", err)
						}
						payload = append(payload, jsonValue...)
					default:
				}
			}

			if len(payload) != 0 {
				req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
				req.Header.Set("Authorization", "Splunk " + splunkToken)

				resp, err := c.Do(req)
				if err != nil {
					log.Println("Failed to save data", err)
				}

				if resp != nil && resp.Body != nil {
					resp.Body.Close()
				}
			}

			time.Sleep(5*time.Second)
	    }
    }()
	    //Creating sub-domain
    app := http.NewServeMux()
    app.HandleFunc("/api/report", report)
    app.HandleFunc("/api/results", results)

    go func() {
        log.Println("Server starting on: http://localhost:8080")
        if err := http.ListenAndServe(":8080", app); err != nil {
			log.Fatal("Server failed to start up: ", err)
		}
    }()
	defer startProxy(p)
	startProxy(p)
}

func startProxy(p http.Handler) {

	log.Println("Proxy starting on: http://localhost:3128 https://localhost:3128")
	if err := http.ListenAndServe(":3128", p); err != nil {
		log.Printf("Proxy failed: %s", err)
	}
}
func report(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello, %s! This is a variable in the main routine: %s", r.URL.Path[1:], dir)
}

func loadCA() (cert tls.Certificate, err error) {
	// TODO(kr): check file permissions
	cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	if os.IsNotExist(err) {
		log.Fatal("CA Certificate not found on path: ", dir)
	}
	if err == nil {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	}
	return
}

func results(w http.ResponseWriter, r *http.Request) {
    w.Header().Add("Content-Type", "application/json; charset=utf-8")
	fmt.Fprint(w, "{\"stats\": [")
	for index, rr := range stats["{all}"] {
		//fmt.Fprintf(w, "{\"method\": \"%s\", \"scheme\": \"%s\", \"host\": \"%s\", \"path\": \"%s\", \"statusCode\": %d, \"startTime\": \"%s\", \"endTime\": \"%s\", \"elapsedTime\": %d}", rr.Method, rr.Scheme, rr.Host, rr.Path, rr.StatusCode, rr.StartTime.Format(time.RFC3339Nano), rr.EndTime.Format(time.RFC3339Nano), rr.ElapsedTime)
		fmt.Fprintf(w, "{\"statusCode\": %d, \"endTime\": \"%s\", \"elapsedTime\": %d}", rr.StatusCode, rr.EndTime.Format(time.RFC3339Nano), rr.ElapsedTime)
		if index < len(stats["{all}"]) - 1 {
			fmt.Fprint(w, ", ")
		}
	}
	fmt.Fprint(w, "]}")
}

type Testevent struct {
   	Event   		mitm.RequestStat	`json:"event"`
   	Time   			int64				`json:"time"`
    Sourcetype    	string       		`json:"sourcetype"`
}

func analyze(rr mitm.RequestStat) {
	//stats["{all}"] = append(stats["{all}"], rr)
	queue <- rr
}