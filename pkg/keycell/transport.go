package keycell

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"syscall"

	"github.com/alexjoedt/keycell/internal/protocol"
)

var nextID atomic.Uint64

// call sends one request over a fresh connection and decodes the result
// into result (nil when the method returns nothing). Every error is
// wrapped as "keycell: <method>: ..." and unwraps to a sentinel.
func (c *Client) call(ctx context.Context, method string, params, result any) error {
	_, _, err := c.roundTrip(ctx, method, params, result)
	return err
}

// roundTrip is call with the wire messages returned for inspection; both
// Params and Result are zeroed before it returns.
func (c *Client) roundTrip(ctx context.Context, method string, params, result any) (*protocol.Request, *protocol.Response, error) {
	req, err := protocol.NewRequest(json.RawMessage(strconv.FormatUint(nextID.Add(1), 10)), method, params)
	if err != nil {
		return nil, nil, fmt.Errorf("keycell: %s: %w: %w", method, ErrInvalidArgument, err)
	}
	defer clear(req.Params)

	resp, err := c.exchange(ctx, req)
	if err != nil {
		return req, nil, fmt.Errorf("keycell: %s: %w", method, err)
	}
	defer clear(resp.Result)

	switch {
	case resp.Error != nil:
		return req, resp, fmt.Errorf("keycell: %s: %w", method, &Error{Code: resp.Error.Code, Message: resp.Error.Message})
	case !bytes.Equal(resp.ID, req.ID):
		return req, resp, fmt.Errorf("keycell: %s: %w: response id %s does not match request", method, ErrProtocol, resp.ID)
	case result == nil:
		return req, resp, nil
	}
	if err := json.Unmarshal(resp.Result, result); err != nil {
		return req, resp, fmt.Errorf("keycell: %s: %w: result: %w", method, ErrProtocol, err)
	}
	return req, resp, nil
}

// exchange dials the socket, writes req and reads the single response.
// The context bounds dial and I/O; a missing or dead socket is
// ErrNotRunning.
func (c *Client) exchange(ctx context.Context, req *protocol.Request) (*protocol.Response, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.socket)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOENT) {
			return nil, fmt.Errorf("%w: %s", ErrNotRunning, c.socket)
		}
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if err := protocol.NewWriter(conn).WriteRequest(req); err != nil {
		return nil, ioError(ctx, err)
	}
	resp, err := protocol.NewReader(conn).ReadResponse()
	if err != nil {
		return nil, ioError(ctx, err)
	}
	return resp, nil
}

// ioError maps a transport failure: context first, then everything the
// daemon could have done wrong (closed early, garbage, oversized line)
// is ErrProtocol.
func ioError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) {
		return fmt.Errorf("%w: connection closed without response", ErrProtocol)
	}
	return fmt.Errorf("%w: %w", ErrProtocol, err)
}
