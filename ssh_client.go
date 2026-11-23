package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

type resolvedSSH struct {
	HostName      string
	User          string
	Port          int
	IdentityFiles []string
}

// resolveSSHConfig reads ~/.ssh/config and resolves Host aliases, User, Port, and IdentityFile.
func resolveSSHConfig(userHost string, keyOverride string, portOverride int) (resolvedSSH, error) {
	explicitUser := ""
	hostAlias := userHost
	if at := strings.LastIndexByte(userHost, '@'); at != -1 {
		explicitUser = userHost[:at]
		hostAlias = userHost[at+1:]
	}

	res := resolvedSSH{
		HostName: hostAlias,
		User:     explicitUser,
		Port:     22,
	}

	homeDir, err := os.UserHomeDir()
	if err == nil {
		cfgPath := filepath.Join(homeDir, ".ssh", "config")
		parseSSHConfigFile(cfgPath, hostAlias, homeDir, &res)
	}

	if explicitUser != "" {
		res.User = explicitUser
	}
	if res.User == "" {
		if u := os.Getenv("USER"); u != "" {
			res.User = u
		} else if u := os.Getenv("USERNAME"); u != "" {
			res.User = u
		}
	}
	if portOverride > 0 {
		res.Port = portOverride
	}
	if keyOverride != "" {
		res.IdentityFiles = append([]string{expandTilde(keyOverride, homeDir)}, res.IdentityFiles...)
	}

	// Add standard default key paths if none were explicitly configured.
	if len(res.IdentityFiles) == 0 && homeDir != "" {
		for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
			p := filepath.Join(homeDir, ".ssh", name)
			if _, statErr := os.Stat(p); statErr == nil {
				res.IdentityFiles = append(res.IdentityFiles, p)
			}
		}
	}

	return res, nil
}

func parseSSHConfigFile(cfgPath, alias, homeDir string, res *resolvedSSH) {
	f, err := os.Open(cfgPath)
	if err != nil {
		return
	}
	defer f.Close()

	var (
		inMatch     = true
		gotHostName = false
		gotUser     = false
		gotPort     = false
		scanner     = bufio.NewScanner(f)
	)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, val := splitConfigKV(line)
		if key == "" || val == "" {
			continue
		}

		switch strings.ToLower(key) {
		case "host":
			patterns := strings.Fields(val)
			matched := false
			for _, pat := range patterns {
				if pat == alias {
					matched = true
					break
				}
				if ok, _ := filepath.Match(pat, alias); ok {
					matched = true
					break
				}
			}
			inMatch = matched
		case "hostname":
			if inMatch && !gotHostName {
				res.HostName = stripQuotes(val)
				gotHostName = true
			}
		case "user":
			if inMatch && !gotUser {
				res.User = stripQuotes(val)
				gotUser = true
			}
		case "port":
			if inMatch && !gotPort {
				if p, convErr := strconv.Atoi(stripQuotes(val)); convErr == nil && p > 0 {
					res.Port = p
					gotPort = true
				}
			}
		case "identityfile":
			if inMatch {
				res.IdentityFiles = append(res.IdentityFiles, expandTilde(stripQuotes(val), homeDir))
			}
		}
	}
}

func splitConfigKV(line string) (string, string) {
	for i := 0; i < len(line); i++ {
		if line[i] == ' ' || line[i] == '\t' || line[i] == '=' {
			return line[:i], strings.TrimSpace(line[i+1:])
		}
	}
	return "", ""
}

func stripQuotes(s string) string {
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		return s[1 : len(s)-1]
	}
	return s
}

func expandTilde(p, homeDir string) string {
	if homeDir == "" {
		return p
	}
	if p == "~" {
		return homeDir
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		return filepath.Join(homeDir, p[2:])
	}
	return p
}

func loadPrivateKeySigner(keyPath string) (ssh.Signer, error) {
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err == nil {
		return signer, nil
	}

	var passErr *ssh.PassphraseMissingError
	if errors.As(err, &passErr) {
		fmt.Fprintf(os.Stderr, "Enter passphrase for key %q: ", keyPath)
		pw, termErr := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if termErr != nil {
			return nil, termErr
		}
		return ssh.ParsePrivateKeyWithPassphrase(pemBytes, bytes.TrimSpace(pw))
	}
	return nil, err
}

type hostKeyProbe struct {
	wantKeys []knownhosts.KnownKey
	gotKey   ssh.PublicKey
}

func buildHostKeyCallback(probe *hostKeyProbe) (ssh.HostKeyCallback, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	sshDir := filepath.Join(homeDir, ".ssh")
	_ = os.MkdirAll(sshDir, 0o700)
	khPath := filepath.Join(sshDir, "known_hosts")

	if _, statErr := os.Stat(khPath); errors.Is(statErr, os.ErrNotExist) {
		f, createErr := os.OpenFile(khPath, os.O_CREATE|os.O_WRONLY, 0o600)
		if createErr == nil {
			_ = f.Close()
		}
	}

	baseCB, err := knownhosts.New(khPath)
	if err != nil {
		return nil, err
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		cbErr := baseCB(hostname, remote, key)
		if cbErr == nil {
			return nil
		}

		var keyErr *knownhosts.KeyError
		if errors.As(cbErr, &keyErr) {
			if len(keyErr.Want) > 0 {
				if probe != nil {
					probe.wantKeys = keyErr.Want
					probe.gotKey = key
				}
				return fmt.Errorf("HOST KEY VERIFICATION FAILED for %s (possible man-in-the-middle attack): %w", hostname, cbErr)
			}
			// Host not in known_hosts yet: prompt user just like OpenSSH.
			fp := ssh.FingerprintSHA256(key)
			fmt.Fprintf(os.Stderr, "The authenticity of host '%s' can't be established.\n%s key fingerprint is %s.\nAre you sure you want to continue connecting (yes/no)? ",
				hostname, key.Type(), fp)

			reader := bufio.NewReader(os.Stdin)
			ans, _ := reader.ReadString('\n')
			if strings.ToLower(strings.TrimSpace(ans)) != "yes" {
				return errors.New("host key verification aborted by user")
			}

			line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)
			if f, openErr := os.OpenFile(khPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600); openErr == nil {
				_, _ = fmt.Fprintln(f, line)
				_ = f.Close()
			}
			return nil
		}
		return cbErr
	}, nil
}

func algorithmsFromKnownKeys(want []knownhosts.KnownKey, got ssh.PublicKey) []string {
	gotType := ""
	if got != nil {
		gotType = got.Type()
	}

	seen := make(map[string]struct{})
	var algos []string
	add := func(a string) {
		if _, ok := seen[a]; !ok {
			seen[a] = struct{}{}
			algos = append(algos, a)
		}
	}

	hasDifferentType := false
	for _, wk := range want {
		if wk.Key == nil {
			continue
		}
		t := wk.Key.Type()
		if t != gotType {
			hasDifferentType = true
		}
		if t == "ssh-rsa" {
			add("rsa-sha2-512")
			add("rsa-sha2-256")
			add("ssh-rsa")
		} else {
			add(t)
		}
	}

	if !hasDifferentType {
		return nil
	}
	return algos
}

func dialTCPSSH(addr string, sshCfg *ssh.ClientConfig) (*ssh.Client, error) {
	rawTCP, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s failed: %w", addr, err)
	}
	if tcpConn, ok := rawTCP.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetReadBuffer(4 * 1024 * 1024)
		_ = tcpConn.SetWriteBuffer(4 * 1024 * 1024)
	}

	c, chans, reqs, err := ssh.NewClientConn(rawTCP, addr, sshCfg)
	if err != nil {
		_ = rawTCP.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// spawnNativeSSH connects directly via Go's native TCP/SSH stack, bypassing Windows OpenSSH pipe limits.
func spawnNativeSSH(userHost, keyOverride string, portOverride int, remoteBin string) (*Conn, func() error, error) {
	cfg, err := resolveSSHConfig(userHost, keyOverride, portOverride)
	if err != nil {
		return nil, nil, err
	}

	var authMethods []ssh.AuthMethod
	var closeAgent func()

	// 1. Try SSH Agent (Windows OpenSSH Agent or Unix SSH_AUTH_SOCK).
	if ag, closeAg := dialSSHAgent(); ag != nil {
		authMethods = append(authMethods, ssh.PublicKeysCallback(ag.Signers))
		closeAgent = closeAg
	}
	cleanupOnErr := func() {
		if closeAgent != nil {
			closeAgent()
		}
	}

	// 2. Load configured or default private keys.
	var signers []ssh.Signer
	seenKeys := make(map[string]struct{})
	for _, kp := range cfg.IdentityFiles {
		if _, dup := seenKeys[kp]; dup {
			continue
		}
		seenKeys[kp] = struct{}{}
		if s, loadErr := loadPrivateKeySigner(kp); loadErr == nil {
			signers = append(signers, s)
		}
	}
	if len(signers) > 0 {
		authMethods = append(authMethods, ssh.PublicKeys(signers...))
	}

	// 3. Password fallback if no keys/agent succeed.
	authMethods = append(authMethods, ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
		fmt.Fprintf(os.Stderr, "%s@%s's password: ", cfg.User, cfg.HostName)
		pw, termErr := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if termErr != nil {
			return "", termErr
		}
		return string(pw), nil
	}), 2))

	probe := &hostKeyProbe{}
	hkCB, err := buildHostKeyCallback(probe)
	if err != nil {
		cleanupOnErr()
		return nil, nil, err
	}

	sshCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            authMethods,
		HostKeyCallback: hkCB,
		Timeout:         15 * time.Second,
		Config: ssh.Config{
			// Prioritize hardware-accelerated AES-GCM ciphers for maximum throughput.
			Ciphers: []string{
				"aes128-gcm@openssh.com",
				"aes256-gcm@openssh.com",
				"chacha20-poly1305@openssh.com",
				"aes128-ctr",
			},
		},
	}

	addr := net.JoinHostPort(cfg.HostName, strconv.Itoa(cfg.Port))
	client, err := dialTCPSSH(addr, sshCfg)
	if err != nil && len(probe.wantKeys) > 0 {
		// Retry with the exact host key algorithm(s) already stored in known_hosts (matching OpenSSH behavior).
		if preferredAlgos := algorithmsFromKnownKeys(probe.wantKeys, probe.gotKey); len(preferredAlgos) > 0 {
			probe.wantKeys = nil
			probe.gotKey = nil
			sshCfg.HostKeyAlgorithms = preferredAlgos
			client, err = dialTCPSSH(addr, sshCfg)
		}
	}
	if err != nil {
		cleanupOnErr()
		return nil, nil, fmt.Errorf("ssh handshake with %s failed: %w", addr, err)
	}

	session, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		cleanupOnErr()
		return nil, nil, fmt.Errorf("failed to open ssh session: %w", err)
	}
	session.Stderr = os.Stderr

	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		_ = client.Close()
		cleanupOnErr()
		return nil, nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		_ = client.Close()
		cleanupOnErr()
		return nil, nil, err
	}

	remoteCmd := fmt.Sprintf("%s --server", remoteBin)
	if err := session.Start(remoteCmd); err != nil {
		_ = session.Close()
		_ = client.Close()
		cleanupOnErr()
		return nil, nil, fmt.Errorf("failed to start remote command %q: %w", remoteCmd, err)
	}

	cleanup := func() error {
		_ = stdin.Close()
		waitErr := session.Wait()
		_ = session.Close()
		_ = client.Close()
		if closeAgent != nil {
			closeAgent()
		}
		return waitErr
	}

	return NewConn(stdout, stdin), cleanup, nil
}
