/*
Helper package for opening a http connect proxy connection to tunnel audit data to the cluster;
either a uds socket or a mTLS proxy, and
open a listener and forward connections through the proxy connection.

Connection handling and copying was borrowed from James Bardin's
Go TCP Proxy pattern:
https://gist.github.com/jbardin/821d08cb64c01c84b81a
*/

package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"go.uber.org/zap"
)

type Proxy struct {
	logger          *zap.SugaredLogger
	proxyHost       string
	proxyPort       string
	clientCert      tls.Certificate
	proxyCAPool     *x509.CertPool
	destinationIP   string
	destinationPort string
	listenerIP      string
	listenerPort    string
	listener        *net.TCPListener
}

// Creates a new proxy instance and opens a TCP listener for accepting connections.
func NewProxyMTLS(logger *zap.SugaredLogger, proxyHost, proxyPort, clientCertFile, clientKeyFile, proxyCAFile, destinationIP, destinationPort, listenerIP, listenerPort string) (*Proxy, error) {
	logger.Infow("NewProxyMTLS called", "proxy host", proxyHost, "proxy port", proxyPort, "listener IP", listenerIP, "listener port", listenerPort)
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		logger.Errorw("Could not read client certificate and key", "client cert", clientCertFile, "client key", clientKeyFile)
		return nil, err
	}
	proxyCAPEM, err := os.ReadFile(proxyCAFile)
	if err != nil {
		logger.Errorw("Couldn't load proxy CA file", "proxyCAFile", proxyCAFile)
	}
	proxyCAPool := x509.NewCertPool()
	proxyCAPool.AppendCertsFromPEM(proxyCAPEM)

	proxy := &Proxy{
		logger:          logger,
		proxyHost:       proxyHost,
		proxyPort:       proxyPort,
		clientCert:      clientCert,
		proxyCAPool:     proxyCAPool,
		destinationIP:   destinationIP,
		destinationPort: destinationPort,
		listenerIP:      listenerIP,
		listenerPort:    listenerPort,
	}

	err = proxy.listen()
	if err != nil {
		logger.Errorw("Error opening listener", "proxy", proxy)
		return nil, err
	}
	go proxy.forward()
	return proxy, nil
}

func (p *Proxy) listen() error {
	listenerTCPAddr, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(p.listenerIP, p.listenerPort))
	var err error
	p.listener, err = net.ListenTCP("tcp", listenerTCPAddr)
	if err != nil {
		p.logger.Errorw("Could not open listener", "listener address", listenerTCPAddr)
		return err
	}
	return nil
}

func (p *Proxy) forward() {
	for {
		srvConn, err := p.listener.AcceptTCP()
		if err != nil {
			p.logger.Errorw("Error accepting connection on listener", "listener:", p.listener)
			return
		}
		p.logger.Infow("New connection", "listener", p.listener, "to (listener address)", srvConn.LocalAddr(), "from (client address)", srvConn.RemoteAddr())

		go p.handleConnection(srvConn)
	}
}

// Closes the listener.
func (p *Proxy) DestroyProxy() {
	p.logger.Infow("Closing forwarder", "destination ip", p.destinationIP)
	p.listener.Close()
}

func (p *Proxy) handleConnection(srvConn *net.TCPConn) {
	p.logger.Infow("handleConnection called", "local address", srvConn.LocalAddr(), "remote address", srvConn.RemoteAddr(), "proxy host", p.proxyHost, "proxy port", p.proxyPort, "target address", p.destinationIP)
	var proxyConn net.Conn
	var err error
	proxyConn, err = tls.Dial("tcp", p.proxyHost+":"+p.proxyPort, &tls.Config{
		Certificates: []tls.Certificate{p.clientCert},
		RootCAs:      p.proxyCAPool,
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		p.logger.Errorw("dialing mTLS proxy failed", "proxy address", p.proxyHost+":"+p.proxyPort, "error", err)
	}
	fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", net.JoinHostPort(p.destinationIP, p.destinationPort), p.listenerIP, "auditforwarder")
	br := bufio.NewReader(proxyConn)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		p.logger.Errorf("reading HTTP response from CONNECT to %s failed: %v", p.destinationIP, err)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		p.logger.Errorf("proxy error while dialing %s: %v", p.destinationIP, res.Status)
		return
	}
	// It's safe to discard the bufio.Reader here and return the
	// original TCP conn directly because we only use this for
	// TLS, and in TLS the client speaks first, so we know there's
	// no unbuffered data. But we can double-check.
	if br.Buffered() > 0 {
		p.logger.Errorf("unexpected %d bytes of buffered data from CONNECT", br.Buffered())
		return
	}
	// Now we're supposed to have both connections open.
	// channels to wait on the close event for each connection
	serverClosed := make(chan struct{}, 1)
	proxyClosed := make(chan struct{}, 1)

	go p.broker(srvConn, proxyConn, proxyClosed)
	go p.broker(proxyConn, srvConn, serverClosed)

	// wait for one half of the proxy to exit, then trigger a shutdown of the
	// other half by calling CloseRead(). This will break the read loop in the
	// broker and allow us to fully close the connection cleanly without a
	// "use of closed network connection" error.
	var waitFor chan struct{}
	select {
	case <-proxyClosed:
		// the client closed first and any more packets from the server aren't
		// useful, so we can optionally SetLinger(0) here to recycle the port
		// faster.
		_ = srvConn.SetLinger(0)
		srvConn.Close()
		waitFor = serverClosed
	case <-serverClosed:
		proxyConn.Close()
		waitFor = proxyClosed
	}

	// Wait for the other connection to close.
	// This "waitFor" pattern isn't required, but gives us a way to track the
	// connection and ensure all copies terminate correctly; we can trigger
	// stats on entry and deferred exit of this function.
	<-waitFor
}

// This does the actual data transfer.
// The broker only closes the Read side.
func (p *Proxy) broker(dst, src net.Conn, srcClosed chan struct{}) {
	// We can handle errors in a finer-grained manner by inlining io.Copy (it's
	// simple, and we drop the ReaderFrom or WriterTo checks for
	// net.Conn->net.Conn transfers, which aren't needed). This would also let
	// us adjust buffersize.
	_, err := io.Copy(dst, src)

	if err != nil {
		p.logger.Errorf("Copy error: %s", err)
	}
	if err := src.Close(); err != nil {
		p.logger.Errorf("Close error: %s", err)
	}
	srcClosed <- struct{}{}
}
