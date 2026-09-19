package keycell

// StartTestDaemon runs an in-process daemon for the examples in
// keycell_test: socket path, raw identity, data dir and a stop function.
func StartTestDaemon(dataDir, sockDir string) (socket string, identity []byte, stop func() error, err error) {
	d, stop, err := newTestDaemon(dataDir, sockDir)
	if err != nil {
		return "", nil, nil, err
	}
	return d.socket, d.identity, stop, nil
}
