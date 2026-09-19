package tty

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("TTY_TEST_CHILD") == "1" {
		_, err := Read("passphrase: ")
		fmt.Println(err)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestReadLine(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"secret\n", "secret"},
		{"secret\r\n", "secret"},
		{"secret", "secret"},
		{"\n", ""},
		{"", ""},
		{"first\nsecond\n", "first"},
		{strings.Repeat("x", 1000) + "\n", strings.Repeat("x", 1000)},
	}
	for _, tt := range tests {
		got, err := readLine(strings.NewReader(tt.in))
		if err != nil {
			t.Errorf("%q: %v", tt.in, err)
			continue
		}
		if string(got) != tt.want {
			t.Errorf("%q: got %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestReadLineZeroesIntermediate(t *testing.T) {
	src := []byte("hunter2\n")
	r := &bytes.Reader{}
	r.Reset(src)
	got, err := readLine(r)
	if err != nil || string(got) != "hunter2" {
		t.Fatalf("got %q, %v", got, err)
	}
	// The returned slice must be its own copy; clearing it must not
	// touch anything the reader handed out.
	clear(got)
	if !bytes.Equal(src, []byte("hunter2\n")) {
		t.Errorf("source aliased: %q", src)
	}
}

// fakeRead returns the answers in order and records the prompts.
func fakeRead(prompts *[]string, answers ...string) ReadFunc {
	return func(prompt string) ([]byte, error) {
		*prompts = append(*prompts, prompt)
		if len(answers) == 0 {
			return nil, errors.New("no more answers")
		}
		a := answers[0]
		answers = answers[1:]
		return []byte(a), nil
	}
}

func TestConfirm(t *testing.T) {
	tests := []struct {
		name    string
		answers []string
		want    string
		err     error
		prompts int
	}{
		{"match", []string{"pw", "pw"}, "pw", nil, 2},
		{"mismatch", []string{"pw", "pq"}, "", ErrMismatch, 2},
		{"empty", []string{"", "x"}, "", ErrEmpty, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var prompts []string
			got, err := fakeRead(&prompts, tt.answers...).Confirm("New passphrase: ")
			if !errors.Is(err, tt.err) {
				t.Fatalf("err %v, want %v", err, tt.err)
			}
			if string(got) != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
			if len(prompts) != tt.prompts {
				t.Errorf("prompts %q, want %d", prompts, tt.prompts)
			}
			if tt.prompts == 2 && prompts[1] != "Repeat passphrase: " {
				t.Errorf("second prompt %q", prompts[1])
			}
		})
	}
}

func TestConfirmZeroesRejected(t *testing.T) {
	first, second := []byte("pw"), []byte("pq")
	handed := [][]byte{first, second}
	read := ReadFunc(func(string) ([]byte, error) {
		b := handed[0]
		handed = handed[1:]
		return b, nil
	})
	if _, err := read.Confirm("p: "); !errors.Is(err, ErrMismatch) {
		t.Fatalf("err %v", err)
	}
	for i, b := range [][]byte{first, second} {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("copy %d not zeroed: %q", i, b)
		}
	}
}

func TestConfirmReadError(t *testing.T) {
	first := []byte("pw")
	calls := 0
	read := ReadFunc(func(string) ([]byte, error) {
		calls++
		if calls == 1 {
			return first, nil
		}
		return nil, ErrNoTTY
	})
	if _, err := read.Confirm("p: "); !errors.Is(err, ErrNoTTY) {
		t.Fatalf("err %v", err)
	}
	if !bytes.Equal(first, []byte{0, 0}) {
		t.Errorf("first not zeroed: %q", first)
	}
}

// TestReadNoTTY runs Read in a child that Setsid detached from any
// controlling terminal, so /dev/tty cannot be opened.
func TestReadNoTTY(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = append(os.Environ(), "TTY_TEST_CHILD=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != ErrNoTTY.Error() {
		t.Errorf("child printed %q, want %q", got, ErrNoTTY.Error())
	}
}
