package main

import (
	"log"
	"net"
	"net/rpc"

	"crypto/tls"
	"crypto/x509"
	"io/ioutil"

	"github.com/kelseyhightower/gls"
)

func main() {
	cert, err := tls.LoadX509KeyPair("certs/server.crt",
		"certs/server.key")
	if err != nil {
		log.Println(err)
		return
	}
	caCert, err := ioutil.ReadFile("certs/CA.crt")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	log.Println("Starting glsd..")
	ls := new(gls.Ls)
	rpc.Register(ls)

	l, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Println(err)
		return
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println(err)
		}
		tlsconn := tls.Server(conn, config)
		err = tlsconn.Handshake()
		if err != nil {
			log.Fatal(err)
		}
		tlsclient := tlsconn.ConnectionState().PeerCertificates[0]
		if tlsclient.Subject.CommonName != "glss Client A" {
			log.Fatal("Invalid client")
		}
		log.Printf("user=\"%s\" connect", tlsclient.Subject.CommonName)
		rpc.ServeConn(tlsconn)
		conn.Close()
	}
}
