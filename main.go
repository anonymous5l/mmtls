package main

import (
	"io/ioutil"
	"mmtls/mars"
	"os"

	"github.com/anonymous5l/console"
)

func SaveSessionToFile(session *mars.Session) error {
	o, err := os.OpenFile("session", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer o.Close()

	o.Write(session.SaveSession())
	return nil
}

func LoadSessionFromFile() (*mars.Session, error) {
	o, err := os.Open("session")
	if err != nil {
		return nil, err
	}
	defer o.Close()
	buf, err := ioutil.ReadAll(o)
	if err != nil {
		return nil, err
	}
	session, err := mars.LoadSession(buf)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func main() {
	client := mars.NewMMTLSClient()

	if session, err := LoadSessionFromFile(); err == nil {
		client.Session = session
	}

	if err := client.Handshake(); err != nil {
		console.Err("%s", err)
		return
	}

	if client.Session != nil {
		SaveSessionToFile(client.Session)
	}
}
