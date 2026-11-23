//go:build windows

package main

import (
	"os"

	"golang.org/x/crypto/ssh/agent"
)

func dialSSHAgent() (agent.ExtendedAgent, func()) {
	f, err := os.OpenFile(`\\.\pipe\openssh-ssh-agent`, os.O_RDWR, 0)
	if err != nil {
		return nil, nil
	}
	return agent.NewClient(f), func() { _ = f.Close() }
}
