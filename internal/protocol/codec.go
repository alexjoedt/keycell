package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"

	"github.com/alexjoedt/keycell/internal/vault"
)

// MaxLineLen bounds one message: the base64 form of a maximal value plus
// room for name, kind, attributes and framing. Longer lines are a
// framing error and the connection is unusable afterwards.
const MaxLineLen = 4*((vault.MaxValueLen+2)/3) + 64*1024

// ErrLineTooLong is returned by a Reader when a line exceeds MaxLineLen
// before its newline. The stream is out of sync; close the connection.
var ErrLineTooLong = fmt.Errorf("protocol: line exceeds %d bytes", MaxLineLen)

var methods = map[string]bool{
	MethodGet: true, MethodStore: true, MethodDelete: true, MethodList: true,
	MethodUnlock: true, MethodLock: true, MethodStatus: true,
}

// Reader frames messages from r one line at a time. It owns its buffer
// and zeroes every consumed line, so no identity or value lingers in the
// framing layer; decoded values are the caller's to clear.
type Reader struct {
	r   io.Reader
	buf []byte
	n   int
}

// NewReader returns a Reader over r.
func NewReader(r io.Reader) *Reader {
	return &Reader{r: r, buf: make([]byte, 4096)}
}

// ReadRequest reads the next request. A malformed line (invalid JSON,
// missing or null id, unknown method) yields an error of type *Error
// with code PROTOCOL; when the id was parseable the returned request is
// non-nil and carries it, so the caller can answer with the right id.
// io.EOF means the peer closed cleanly between messages.
func (r *Reader) ReadRequest() (*Request, error) {
	line, err := r.readLine()
	if err != nil {
		return nil, err
	}
	defer r.consume(len(line))
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		return nil, Errorf(CodeProtocol, "invalid JSON: %v", err)
	}
	if len(req.ID) == 0 || bytes.Equal(req.ID, []byte("null")) {
		return nil, Errorf(CodeProtocol, "missing id")
	}
	if !methods[req.Method] {
		return &Request{ID: req.ID}, Errorf(CodeProtocol, "unknown method %q", req.Method)
	}
	return &req, nil
}

// ReadResponse reads the next response. Invalid JSON is a *Error with
// code PROTOCOL; io.EOF means the daemon closed the connection.
func (r *Reader) ReadResponse() (*Response, error) {
	line, err := r.readLine()
	if err != nil {
		return nil, err
	}
	defer r.consume(len(line))
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, Errorf(CodeProtocol, "invalid JSON: %v", err)
	}
	return &resp, nil
}

// readLine returns the next line without its newline. The slice aliases
// the buffer and is valid until consume.
func (r *Reader) readLine() ([]byte, error) {
	for {
		if i := bytes.IndexByte(r.buf[:r.n], '\n'); i >= 0 {
			return r.buf[:i], nil
		}
		if r.n > MaxLineLen {
			return nil, ErrLineTooLong
		}
		if r.n == len(r.buf) {
			grown := make([]byte, min(2*len(r.buf), MaxLineLen+1))
			copy(grown, r.buf)
			clear(r.buf)
			runtime.KeepAlive(r.buf)
			r.buf = grown
		}
		m, err := r.r.Read(r.buf[r.n:])
		r.n += m
		if err != nil {
			if errors.Is(err, io.EOF) {
				if r.n == 0 {
					return nil, io.EOF
				}
				return nil, io.ErrUnexpectedEOF
			}
			return nil, fmt.Errorf("protocol: read: %w", err)
		}
	}
}

// consume zeroes a line of the given length plus its newline and shifts
// any bytes of the next message to the front, zeroing the freed tail.
func (r *Reader) consume(lineLen int) {
	end := lineLen + 1
	clear(r.buf[:end])
	rest := copy(r.buf, r.buf[end:r.n])
	clear(r.buf[rest:r.n])
	r.n = rest
	runtime.KeepAlive(r.buf)
}

// Writer frames messages onto w, one line each, and zeroes its encoding
// buffer after every write. encoding/json keeps pooled scratch buffers
// this package cannot reach; that copy is accepted (see ADR 0005).
type Writer struct {
	w   io.Writer
	buf bytes.Buffer
	enc *json.Encoder
}

// NewWriter returns a Writer onto w.
func NewWriter(w io.Writer) *Writer {
	wr := &Writer{w: w}
	wr.enc = json.NewEncoder(&wr.buf)
	wr.enc.SetEscapeHTML(false)
	return wr
}

// WriteRequest writes req as one line.
func (w *Writer) WriteRequest(req *Request) error { return w.write(req) }

// WriteResponse writes resp as one line.
func (w *Writer) WriteResponse(resp *Response) error { return w.write(resp) }

func (w *Writer) write(v any) error {
	defer w.wipe()
	if err := w.enc.Encode(v); err != nil {
		return fmt.Errorf("protocol: encode: %w", err)
	}
	if _, err := w.w.Write(w.buf.Bytes()); err != nil {
		return fmt.Errorf("protocol: write: %w", err)
	}
	return nil
}

func (w *Writer) wipe() {
	b := w.buf.Bytes()
	clear(b[:cap(b)])
	w.buf.Reset()
	runtime.KeepAlive(b)
}
