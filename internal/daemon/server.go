package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/alexjoedt/keycell/internal/identity"
	"github.com/alexjoedt/keycell/internal/protocol"
	"github.com/alexjoedt/keycell/internal/vault"
)

// ErrAlreadyRunning: another keycelld answers on the socket path.
var ErrAlreadyRunning = errors.New("daemon: already running")

// shutdownGrace is how long Serve waits for in-flight requests after
// the context is cancelled (wayfinder ticket 04).
const shutdownGrace = 2 * time.Second

// Listen creates the socket directory (0700), removes a stale socket,
// refuses to start beside a live daemon and listens with mode 0600.
func Listen(path string) (*net.UnixListener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("daemon: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("daemon: %w", err)
	}
	if _, err := os.Lstat(path); err == nil {
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("%w on %s", ErrAlreadyRunning, path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("daemon: remove stale socket: %w", err)
		}
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("daemon: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("daemon: %w", err)
	}
	return ln, nil
}

// Server dispatches protocol requests to a Session and a Store.
type Server struct {
	session *Session
	store   *Store
	log     *slog.Logger
	peerUID func(*net.UnixConn) (uint32, error)
	uid     uint32

	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	inflight sync.WaitGroup
}

// NewServer returns a Server that accepts connections from the current
// UID only.
func NewServer(session *Session, store *Store, log *slog.Logger) *Server {
	return &Server{
		session: session,
		store:   store,
		log:     log,
		peerUID: peerUID,
		uid:     uint32(os.Getuid()),
		conns:   map[net.Conn]struct{}{},
	}
}

// Serve accepts connections on ln until ctx is cancelled, then waits up
// to shutdownGrace for running requests, locks the session, closes every
// connection and removes the socket. It returns nil on a clean shutdown.
func (s *Server) Serve(ctx context.Context, ln *net.UnixListener) error {
	defer ln.Close()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	var wg sync.WaitGroup
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			return fmt.Errorf("daemon: accept: %w", err)
		}
		uid, err := s.peerUID(conn)
		if err != nil || uid != s.uid {
			s.log.Warn("rejected connection", "peer_uid", uid, "err", err)
			conn.Close()
			continue
		}
		s.track(conn, true)
		wg.Go(func() {
			defer s.track(conn, false)
			s.handle(conn)
		})
	}

	done := make(chan struct{})
	go func() { s.inflight.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(shutdownGrace):
		s.log.Warn("shutdown: requests still running after grace period")
	}
	s.session.Lock(LockShutdown)
	s.mu.Lock()
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	wg.Wait()
	return nil
}

func (s *Server) track(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
}

// handle serves one connection: requests in order, one response each.
func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	r, w := protocol.NewReader(conn), protocol.NewWriter(conn)
	for {
		req, err := r.ReadRequest()
		if err != nil {
			var pe *protocol.Error
			switch {
			case errors.As(err, &pe):
				var id []byte
				if req != nil {
					id = req.ID
				}
				s.log.Info("request", "method", "?", "code", pe.Code)
				if err := w.WriteResponse(protocol.NewError(id, pe)); err != nil {
					return
				}
				continue
			case errors.Is(err, protocol.ErrLineTooLong):
				s.log.Info("request", "method", "?", "code", protocol.CodeProtocol)
				_ = w.WriteResponse(protocol.NewError(nil, protocol.Errorf(protocol.CodeProtocol, "%v", err)))
				return
			default:
				if !errors.Is(err, io.EOF) {
					s.log.Debug("connection closed", "err", err)
				}
				return
			}
		}
		resp := s.dispatch(req)
		clear(req.Params)
		err = w.WriteResponse(resp)
		clear(resp.Result)
		if err != nil {
			s.log.Debug("write failed", "err", err)
			return
		}
	}
}

// dispatch runs one request and never returns nil.
func (s *Server) dispatch(req *protocol.Request) *protocol.Response {
	s.inflight.Add(1)
	defer s.inflight.Done()
	result, err := s.call(req)
	if err != nil {
		pe := s.toError(err)
		s.log.Info("request", "method", req.Method, "code", pe.Code)
		return protocol.NewError(req.ID, pe)
	}
	resp, err := protocol.NewResult(req.ID, result)
	if err != nil {
		s.log.Error("encode result", "method", req.Method, "err", err)
		return protocol.NewError(req.ID, protocol.Errorf(protocol.CodeInternal, "internal error"))
	}
	s.log.Info("request", "method", req.Method, "code", "ok")
	return resp
}

func (s *Server) call(req *protocol.Request) (any, error) {
	switch req.Method {
	case protocol.MethodStatus:
		locked, at := s.session.Status()
		res := protocol.StatusResult{Protocol: protocol.Version, Locked: locked}
		if !at.IsZero() {
			res.LocksAt = &at
		}
		return res, nil

	case protocol.MethodUnlock:
		var p protocol.UnlockParams
		if err := req.Bind(&p); err != nil {
			return nil, err
		}
		var d *time.Duration
		if p.For != nil {
			v := time.Duration(*p.For) * time.Second
			d = &v
		}
		if err := s.session.Unlock(p.Identity, d); err != nil {
			return nil, err
		}
		if err := s.verifyIdentity(); err != nil {
			s.session.Lock(LockManual)
			return nil, err
		}
		return protocol.Empty{}, nil

	case protocol.MethodLock:
		s.session.Lock(LockManual)
		return protocol.Empty{}, nil

	case protocol.MethodGet:
		var p protocol.GetParams
		if err := req.Bind(&p); err != nil {
			return nil, err
		}
		s.log.Debug("get", "name", p.Name)
		sec, err := s.store.Get(p.Name)
		if err != nil {
			return nil, err
		}
		return protocol.GetResult{SecretInfo: toInfo(*sec), Value: sec.Value}, nil

	case protocol.MethodList:
		var p protocol.ListParams
		if err := req.Bind(&p); err != nil {
			return nil, err
		}
		secs, err := s.store.List(Filter{Kind: p.Kind, Prefix: p.Prefix, Attributes: p.Attributes})
		if err != nil {
			return nil, err
		}
		res := make(protocol.ListResult, len(secs))
		for i, sec := range secs {
			res[i] = toInfo(sec)
		}
		return res, nil

	case protocol.MethodStore:
		var p protocol.StoreParams
		if err := req.Bind(&p); err != nil {
			return nil, err
		}
		defer wipe(p.Value)
		s.log.Debug("store", "name", p.Name)
		if err := s.store.Store(p.Name, p.Kind, p.Attributes, p.Value); err != nil {
			return nil, err
		}
		return protocol.Empty{}, nil

	case protocol.MethodDelete:
		var p protocol.DeleteParams
		if err := req.Bind(&p); err != nil {
			return nil, err
		}
		s.log.Debug("delete", "name", p.Name)
		if err := s.store.Delete(p.Name); err != nil {
			return nil, err
		}
		return protocol.Empty{}, nil
	}
	return nil, protocol.Errorf(protocol.CodeProtocol, "unknown method %q", req.Method)
}

// verifyIdentity reads the vault once so a wrong identity is rejected at
// unlock rather than on the first get.
func (s *Server) verifyIdentity() error {
	_, err := s.store.List(Filter{})
	return err
}

func (s *Server) toError(err error) *protocol.Error {
	var pe *protocol.Error
	switch {
	case errors.As(err, &pe):
		return pe
	case errors.Is(err, ErrLocked):
		return protocol.Errorf(protocol.CodeLocked, "daemon is locked")
	case errors.Is(err, ErrNotFound):
		return protocol.Errorf(protocol.CodeNotFound, "secret not found")
	case errors.Is(err, ErrInvalidArgument):
		return protocol.Errorf(protocol.CodeInvalidArgument, "%s", strings.TrimPrefix(err.Error(), ErrInvalidArgument.Error()+": "))
	case errors.Is(err, identity.ErrMalformed):
		return protocol.Errorf(protocol.CodeInvalidArgument, "identity is not an age X25519 secret key")
	case errors.Is(err, vault.ErrWrongIdentity):
		return protocol.Errorf(protocol.CodeInvalidArgument, "identity does not open the vault")
	case errors.Is(err, fs.ErrNotExist):
		s.log.Warn("vault not found", "err", err)
		return protocol.Errorf(protocol.CodeInternal, "vault not found; run `keycell init`")
	}
	s.log.Error("internal error", "err", err)
	return protocol.Errorf(protocol.CodeInternal, "internal error")
}

func toInfo(sec Secret) protocol.SecretInfo {
	return protocol.SecretInfo{Name: sec.Name, Kind: sec.Kind, Attributes: sec.Attributes, Created: sec.Created, Updated: sec.Updated}
}

func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	return cred.Uid, nil
}
