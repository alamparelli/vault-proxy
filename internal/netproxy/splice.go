package netproxy

import (
	"io"
	"net"
	"sync"
)

// splice copies bytes bidirectionally between a and b. It returns when either
// side closes the connection or either io.Copy errors. Both conns are closed
// on return.
func splice(a, b net.Conn) {
	defer a.Close()
	defer b.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(a, b)
		// Half-close: signal the other direction's Copy to finish.
		if tcp, ok := a.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		if tcp, ok := b.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()

	wg.Wait()
}
