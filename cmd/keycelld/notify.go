package main

import (
	"fmt"
	"net"
	"strings"
)

// sdNotify writes state to the systemd notification socket. A path
// starting with "@" is an abstract socket, which Go addresses with a
// leading NUL byte.
func sdNotify(socket, state string) error {
	if strings.HasPrefix(socket, "@") {
		socket = "\x00" + socket[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("sd_notify: %w", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(state)); err != nil {
		return fmt.Errorf("sd_notify: %w", err)
	}
	return nil
}
