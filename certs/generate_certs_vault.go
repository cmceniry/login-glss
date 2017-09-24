package main

import (
	"fmt"
	"io/ioutil"

	vaultapi "github.com/hashicorp/vault/api"
)

func main() {
	config := vaultapi.DefaultConfig()
	config.Address = "http://127.0.0.1:8200"
	c, err := vaultapi.NewClient(config)
	if err != nil {
		panic(err)
	}
	c.SetToken("mytoken")

	s, err := c.Logical().Write(
		"myca/issue/powerserver",
		map[string]interface{}{
			"common_name": "localhost",
			"ttl":         "1h",
		},
	)
	if err != nil {
		panic(err)
	}
	key := s.Data["private_key"].(string)
	ioutil.WriteFile("certs/server.key", []byte(key), 0444)
	crt := s.Data["certificate"].(string)
	ioutil.WriteFile("certs/server.crt", []byte(crt), 0444)

	s, err = c.Logical().Write(
		"myca/issue/powerclient",
		map[string]interface{}{
			"common_name": "glss Client A",
			"ttl":         "1h",
		},
	)
	if err != nil {
		panic(err)
	}
	key = s.Data["private_key"].(string)
	ioutil.WriteFile(
		"certs/client.key",
		[]byte(s.Data["private_key"].(string)),
		0444,
	)
	crt = s.Data["certificate"].(string)
	ioutil.WriteFile(
		"certs/client.crt",
		[]byte(s.Data["certificate"].(string)),
		0444,
	)

	fmt.Println("Success!")
}
