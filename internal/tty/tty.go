// Package tty reads passphrases from the controlling terminal without
// echo. Commands take a ReadFunc so tests can feed input instead.
package tty

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var (
	// ErrNoTTY means /dev/tty could not be opened; the message is fixed
	// by the CLI contract.
	ErrNoTTY = errors.New("no TTY for passphrase prompt")
	// ErrEmpty is Confirm rejecting an empty first entry.
	ErrEmpty = errors.New("empty passphrase")
	// ErrMismatch is Confirm rejecting a second entry that differs.
	ErrMismatch = errors.New("passphrases do not match")
	// ErrInterrupted reports a SIGINT, SIGTERM or SIGHUP during the prompt.
	ErrInterrupted = errors.New("interrupted")
)

// ReadFunc prompts for one line and returns it without the line
// ending. The caller owns the returned bytes and zeroes them.
type ReadFunc func(prompt string) ([]byte, error)

// Read opens /dev/tty, writes prompt, reads a line with echo off and
// restores the terminal afterwards, also when the read fails or a
// signal arrives. Without a controlling terminal it returns ErrNoTTY.
func Read(prompt string) ([]byte, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, ErrNoTTY
	}
	defer f.Close()

	saved, err := getTermios(f)
	if err != nil {
		return nil, err
	}
	noEcho := *saved
	noEcho.Lflag &^= unix.ECHO
	if err := setTermios(f, &noEcho); err != nil {
		return nil, err
	}
	restore := func() { _ = setTermios(f, saved) }
	defer restore()

	// A signal while echo is off would leave the shell blind: restore
	// first, then unblock the read so the command can exit.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	done := make(chan struct{})
	defer func() {
		signal.Stop(sigs)
		close(done)
	}()
	go func() {
		select {
		case <-sigs:
			restore()
			_ = f.SetReadDeadline(time.Now())
		case <-done:
		}
	}()

	if _, err := f.WriteString(prompt); err != nil {
		return nil, err
	}
	line, err := readLine(f)
	_, _ = f.WriteString("\n")
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return nil, ErrInterrupted
	}
	return line, err
}

// getTermios and setTermios go through the raw connection because
// f.Fd() would switch the file to blocking mode and disable the read
// deadline the signal path relies on.
func getTermios(f *os.File) (*unix.Termios, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var tio *unix.Termios
	var ioctlErr error
	if err := rc.Control(func(fd uintptr) {
		tio, ioctlErr = unix.IoctlGetTermios(int(fd), unix.TCGETS)
	}); err != nil {
		return nil, err
	}
	return tio, ioctlErr
}

func setTermios(f *os.File, tio *unix.Termios) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var ioctlErr error
	if err := rc.Control(func(fd uintptr) {
		ioctlErr = unix.IoctlSetTermios(int(fd), unix.TCSETS, tio)
	}); err != nil {
		return err
	}
	return ioctlErr
}

// readLine reads up to and excluding the first newline, zeroing every
// intermediate buffer. EOF ends the line like a newline does.
func readLine(r io.Reader) ([]byte, error) {
	var buf [256]byte
	defer clear(buf[:])
	var acc []byte
	defer func() { clear(acc) }()
	for {
		n, err := r.Read(buf[:])
		acc = append(acc, buf[:n]...)
		clear(buf[:n])
		if i := bytes.IndexByte(acc, '\n'); i >= 0 {
			return trimmed(acc[:i]), nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return trimmed(acc), nil
			}
			return nil, err
		}
	}
}

// trimmed copies b without a trailing carriage return.
func trimmed(b []byte) []byte {
	return bytes.Clone(bytes.TrimSuffix(b, []byte("\r")))
}

// Confirm asks twice and returns the passphrase only when both entries
// match and are not empty. The second copy is zeroed before returning.
func (r ReadFunc) Confirm(prompt string) ([]byte, error) {
	first, err := r(prompt)
	if err != nil {
		return nil, err
	}
	if len(first) == 0 {
		return nil, ErrEmpty
	}
	second, err := r("Repeat passphrase: ")
	if err != nil {
		clear(first)
		return nil, err
	}
	defer clear(second)
	if !bytes.Equal(first, second) {
		clear(first)
		return nil, ErrMismatch
	}
	return first, nil
}

// IsTerminal reports whether f is a terminal.
func IsTerminal(f *os.File) bool {
	_, err := getTermios(f)
	return err == nil
}
