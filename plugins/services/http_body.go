package services

import "io"

const maxServiceHTTPBodyBytes = 2 << 20

func readServiceHTTPBody(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxServiceHTTPBodyBytes))
}
