package main

import (
	"fmt"
	"log"
	"net/rpc"
	"os"

	"crypto/tls"
	"crypto/x509"
	"io/ioutil"

	"github.com/kelseyhightower/gls"
)

func main() {

	// Load client cert
	cert, err := tls.LoadX509KeyPair("certs/client.crt",
		"certs/client.key")
	if err != nil {
		log.Fatal(err)
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile("certs/CA.crt")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	conf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	conn, err := tls.Dial("tcp", "localhost:8080", conf)
	if err != nil {
		log.Fatal(err)
	}
	client := rpc.NewClient(conn)

	files := make(gls.Files, 0)
	err = client.Call("Ls.Ls", os.Args[1], &files)
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range files {
		fmt.Printf("%s %10d %s %s\n", f.Mode, f.Size, f.ModTime, f.Name)
	}
}
