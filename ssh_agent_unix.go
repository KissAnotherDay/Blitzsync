//go:build !windows

package main

import (
	"net"
	"os"

	"golang.org/x/crypto/ssh/agent"
)

func dialSSHAgent() (agent.ExtendedAgent, func()) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, nil
	}
	return agent.NewClient(conn), func() { _ = conn.Close() }
}
