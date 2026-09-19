package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

var ts = time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

func TestRoundTrip(t *testing.T) {
	info := SecretInfo{Name: "git/github.com", Kind: "git-credential", Attributes: map[string]string{"host": "github.com"}, Created: ts, Updated: ts}
	tests := []struct {
		method   string
		params   any
		wantReq  string
		result   any
		wantResp string
	}{
		{
			MethodGet, GetParams{Name: "git/github.com"},
			`{"id":1,"method":"get","params":{"name":"git/github.com"}}`,
			GetResult{SecretInfo: info, Value: []byte("ghp_secret")},
			`{"id":1,"result":{"name":"git/github.com","kind":"git-credential","attributes":{"host":"github.com"},"created":"2026-09-20T12:00:00Z","updated":"2026-09-20T12:00:00Z","value":"Z2hwX3NlY3JldA=="}}`,
		},
		{
			MethodList, ListParams{Kind: "git-credential", Prefix: "git/", Attributes: map[string]string{"host": "github.com"}},
			`{"id":1,"method":"list","params":{"kind":"git-credential","prefix":"git/","attributes":{"host":"github.com"}}}`,
			ListResult{info},
			`{"id":1,"result":[{"name":"git/github.com","kind":"git-credential","attributes":{"host":"github.com"},"created":"2026-09-20T12:00:00Z","updated":"2026-09-20T12:00:00Z"}]}`,
		},
		{
			MethodStore, StoreParams{Name: "git/github.com", Kind: "git-credential", Attributes: map[string]string{"host": "github.com"}, Value: []byte("ghp_secret")},
			`{"id":1,"method":"store","params":{"name":"git/github.com","kind":"git-credential","attributes":{"host":"github.com"},"value":"Z2hwX3NlY3JldA=="}}`,
			Empty{}, `{"id":1,"result":{}}`,
		},
		{
			MethodDelete, DeleteParams{Name: "git/github.com"},
			`{"id":1,"method":"delete","params":{"name":"git/github.com"}}`,
			Empty{}, `{"id":1,"result":{}}`,
		},
		{
			MethodUnlock, UnlockParams{Identity: []byte("AGE-SECRET-KEY-1"), For: new(int64(3600))},
			`{"id":1,"method":"unlock","params":{"identity":"QUdFLVNFQ1JFVC1LRVktMQ==","for":3600}}`,
			Empty{}, `{"id":1,"result":{}}`,
		},
		{
			MethodUnlock, UnlockParams{Identity: []byte("AGE-SECRET-KEY-1")},
			`{"id":1,"method":"unlock","params":{"identity":"QUdFLVNFQ1JFVC1LRVktMQ=="}}`,
			Empty{}, `{"id":1,"result":{}}`,
		},
		{
			MethodLock, Empty{}, `{"id":1,"method":"lock","params":{}}`,
			Empty{}, `{"id":1,"result":{}}`,
		},
		{
			MethodStatus, Empty{}, `{"id":1,"method":"status","params":{}}`,
			StatusResult{Protocol: Version, Locked: false, LocksAt: new(ts)},
			`{"id":1,"result":{"protocol":1,"locked":false,"locks_at":"2026-09-20T12:00:00Z"}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			var wire bytes.Buffer
			req, err := NewRequest(json.RawMessage("1"), tt.method, tt.params)
			if err != nil {
				t.Fatal(err)
			}
			if err := NewWriter(&wire).WriteRequest(req); err != nil {
				t.Fatal(err)
			}
			if got := strings.TrimSuffix(wire.String(), "\n"); got != tt.wantReq {
				t.Fatalf("request wire drift:\n got %s\nwant %s", got, tt.wantReq)
			}
			got, err := NewReader(&wire).ReadRequest()
			if err != nil {
				t.Fatal(err)
			}
			if got.Method != tt.method || string(got.ID) != "1" {
				t.Fatalf("read %+v", got)
			}
			bound := newParams(tt.method)
			if err := got.Bind(bound); err != nil {
				t.Fatal(err)
			}
			if b, _ := json.Marshal(bound); string(b) != string(req.Params) {
				t.Fatalf("bind drift: got %s want %s", b, req.Params)
			}

			wire.Reset()
			resp, err := NewResult(got.ID, tt.result)
			if err != nil {
				t.Fatal(err)
			}
			if err := NewWriter(&wire).WriteResponse(resp); err != nil {
				t.Fatal(err)
			}
			if got := strings.TrimSuffix(wire.String(), "\n"); got != tt.wantResp {
				t.Fatalf("response wire drift:\n got %s\nwant %s", got, tt.wantResp)
			}
			back, err := NewReader(&wire).ReadResponse()
			if err != nil {
				t.Fatal(err)
			}
			if back.Error != nil || string(back.ID) != "1" || string(back.Result) != string(resp.Result) {
				t.Fatalf("read %+v", back)
			}
		})
	}
}

func newParams(method string) any {
	switch method {
	case MethodGet:
		return &GetParams{}
	case MethodList:
		return &ListParams{}
	case MethodStore:
		return &StoreParams{}
	case MethodDelete:
		return &DeleteParams{}
	case MethodUnlock:
		return &UnlockParams{}
	default:
		return &Empty{}
	}
}

func TestReadRequestProtocolErrors(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		wantID string // "" when the id is unusable
	}{
		{"invalid json", "{\n", ""},
		{"not an object", "[1]\n", ""},
		{"missing id", `{"method":"status"}` + "\n", ""},
		{"null id", `{"id":null,"method":"status"}` + "\n", ""},
		{"unknown method", `{"id":"a","method":"exists"}` + "\n", `"a"`},
		{"missing method", `{"id":7}` + "\n", "7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := NewReader(strings.NewReader(tt.in)).ReadRequest()
			var pe *Error
			if !errors.As(err, &pe) || pe.Code != CodeProtocol {
				t.Fatalf("got %v, want PROTOCOL error", err)
			}
			if tt.wantID == "" && req != nil {
				t.Fatalf("got request %+v, want nil", req)
			}
			if tt.wantID != "" && (req == nil || string(req.ID) != tt.wantID) {
				t.Fatalf("got request %+v, want id %s", req, tt.wantID)
			}
		})
	}
}

func TestReadFraming(t *testing.T) {
	t.Run("eof between messages", func(t *testing.T) {
		_, err := NewReader(strings.NewReader("")).ReadRequest()
		if !errors.Is(err, io.EOF) {
			t.Fatalf("got %v, want io.EOF", err)
		}
	})
	t.Run("eof inside message", func(t *testing.T) {
		_, err := NewReader(strings.NewReader(`{"id":1`)).ReadRequest()
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("got %v, want io.ErrUnexpectedEOF", err)
		}
	})
	t.Run("line too long", func(t *testing.T) {
		in := `{"id":1,"method":"store","params":{"name":"` + strings.Repeat("x", MaxLineLen) + `"}}` + "\n"
		_, err := NewReader(strings.NewReader(in)).ReadRequest()
		if !errors.Is(err, ErrLineTooLong) {
			t.Fatalf("got %v, want ErrLineTooLong", err)
		}
	})
	t.Run("longest allowed line", func(t *testing.T) {
		pad := strings.Repeat(" ", MaxLineLen-len(`{"id":1,"method":"lock"}`))
		_, err := NewReader(strings.NewReader(`{"id":1,"method":"lock"` + pad + "}\n")).ReadRequest()
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("pipelined", func(t *testing.T) {
		r := NewReader(strings.NewReader(`{"id":1,"method":"status"}` + "\n" + `{"id":2,"method":"lock"}` + "\n"))
		for _, want := range []string{"1", "2"} {
			req, err := r.ReadRequest()
			if err != nil || string(req.ID) != want {
				t.Fatalf("got %+v, %v; want id %s", req, err, want)
			}
		}
		if _, err := r.ReadRequest(); !errors.Is(err, io.EOF) {
			t.Fatalf("got %v, want io.EOF", err)
		}
	})
}

func TestBind(t *testing.T) {
	tests := []struct {
		name   string
		params string
		code   string
	}{
		{"absent", "", ""},
		{"null", "null", ""},
		{"empty object", "{}", ""},
		{"unknown field", `{"name":"a","extra":1}`, CodeInvalidArgument},
		{"wrong type", `{"name":1}`, CodeInvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &Request{Params: json.RawMessage(tt.params)}
			err := req.Bind(&GetParams{})
			var pe *Error
			switch {
			case tt.code == "" && err != nil:
				t.Fatalf("got %v, want nil", err)
			case tt.code != "" && (!errors.As(err, &pe) || pe.Code != tt.code):
				t.Fatalf("got %v, want %s", err, tt.code)
			}
		})
	}
}

func TestZeroing(t *testing.T) {
	secret := "QUdFLVNFQ1JFVC1LRVktMQ=="
	line := `{"id":1,"method":"unlock","params":{"identity":"` + secret + `"}}` + "\n"

	r := NewReader(strings.NewReader(line + line))
	if _, err := r.ReadRequest(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(r.buf[r.n:], []byte(secret)) || !bytes.Contains(r.buf[:r.n], []byte(secret)) {
		t.Fatalf("consumed line not zeroed or pending line lost: n=%d", r.n)
	}
	if _, err := r.ReadRequest(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(r.buf, []byte(secret)) || r.n != 0 {
		t.Fatalf("reader buffer not zeroed: n=%d", r.n)
	}

	w := NewWriter(io.Discard)
	req, _ := NewRequest(json.RawMessage("1"), MethodUnlock, UnlockParams{Identity: []byte("AGE-SECRET-KEY-1")})
	if err := w.WriteRequest(req); err != nil {
		t.Fatal(err)
	}
	b := w.buf.Bytes()
	if bytes.Contains(b[:cap(b)], []byte(secret)) {
		t.Fatal("writer buffer not zeroed")
	}
}

func TestNewError(t *testing.T) {
	var wire bytes.Buffer
	if err := NewWriter(&wire).WriteResponse(NewError(nil, Errorf(CodeProtocol, "missing id"))); err != nil {
		t.Fatal(err)
	}
	if got, want := wire.String(), `{"id":null,"error":{"code":"PROTOCOL","message":"missing id"}}`+"\n"; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	resp, err := NewReader(&wire).ReadResponse()
	if err != nil || resp.Error == nil || resp.Error.Code != CodeProtocol || resp.Error.Error() != "PROTOCOL: missing id" {
		t.Fatalf("got %+v, %v", resp, err)
	}
}
