package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	systemlog "log"

	log "github.com/sirupsen/logrus"
)

type key int

const (
	requestIDKey key = 0
)

var indexDomains = []string{"dumprequest.com", "www.dumprequest.com"}

type contextKey struct {
	key string
}

var ConnContextKey = &contextKey{"http-conn"}

func SaveConnInContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, ConnContextKey, c)
}
func GetConn(r *http.Request) net.Conn {
	return r.Context().Value(ConnContextKey).(net.Conn)
}

type StatusRecorder struct {
	http.ResponseWriter
	Status int
}

func (r *StatusRecorder) WriteHeader(status int) {
	r.Status = status
	r.ResponseWriter.WriteHeader(status)
}

func (w *StatusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("the hijacker interface is not supported")
	}

	return hj.Hijack()
}

type Server struct {
	logger *log.Logger
	router *http.ServeMux
}

var (
	HI      = make(map[string]*tls.ClientHelloInfo)
	HIMutex = sync.RWMutex{}
)

func saveCHI(RemoteAddr string, helloInfo *tls.ClientHelloInfo) {
	HIMutex.Lock()
	HI[RemoteAddr] = helloInfo
	HIMutex.Unlock()
}

func getCHI(RemoteAddr string) *tls.ClientHelloInfo {
	return HI[RemoteAddr]
}

func delCHI(RemoteAddr string) {
	HIMutex.Lock()
	delete(HI, RemoteAddr)
	HIMutex.Unlock()
}

func tlsConfig() *tls.Config {
	return &tls.Config{
		GetCertificate:           getCertificateHook,
		GetConfigForClient:       getConfigForClientHook,
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
			tls.X25519,
		},
		MinVersion: tls.VersionTLS10, // make it wrong on purpose, this is for testing all weird clients. tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // Go 1.8 only
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,   // Go 1.8 only
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,

			// Best disabled, as they don't provide Forward Secrecy,
			// but might be necessary for some clients
			// tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			// tls.TLS_RSA_WITH_AES_128_GCM_SHA256,

			// support all ciphers, make it wrong on purpose
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
}

func (s Server) serveHTTP(server *http.Server, mux *http.ServeMux, errs chan<- error) {
	s.logger.Printf("Starting HTTP service ...")
	if err := server.ListenAndServe(); err != nil {
		errs <- err
	}
}

func (s Server) serveHTTPS(server *http.Server, mux *http.ServeMux, errs chan<- error) {
	s.logger.Printf("Starting HTTPS service ...")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		errs <- err
	}
}

func StartServer(logger *log.Logger, router *http.ServeMux) {
	s := &Server{logger: logger, router: router}
	nextRequestID := func() string {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}

	w := s.logger.Writer()
	defer w.Close()

	/*mdlw := middleware.New(middleware.Config{
		Recorder: metrics.NewRecorder(metrics.Config{}),
	})

	h := std.Handler("", mdlw, s.router)*/

	httpsServer := &http.Server{
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       15 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		TLSConfig:         tlsConfig(),
		ConnState:         connStateHook,
		ErrorLog:          systemlog.New(w, "", 0),
		Handler:           tracing(nextRequestID)(logging(s.logger)(s.router)),
		ConnContext:       SaveConnInContext,
	}

	httpServer := &http.Server{
		ReadTimeout:       httpsServer.ReadTimeout,
		WriteTimeout:      httpsServer.WriteTimeout,
		IdleTimeout:       httpsServer.IdleTimeout,
		ReadHeaderTimeout: httpsServer.ReadHeaderTimeout,
		ConnState:         httpsServer.ConnState,
		ErrorLog:          httpsServer.ErrorLog,
		Handler:           httpsServer.Handler,
		ConnContext:       httpsServer.ConnContext,
	}

	errs := make(chan error)

	logger.Println("Server is starting...")

	go s.serveHTTP(httpServer, router, errs)
	go s.serveHTTPS(httpsServer, router, errs)

	s.logger.Println("Server started, waiting for connections...")

	err := <-errs
	s.logger.Printf("Service error: %s", err)
}

func connStateHook(c net.Conn, state http.ConnState) {
	/*if state == http.StateActive {
		if cc, ok := c.(*tls.Conn); ok {
			state := cc.ConnectionState()
			log.Println("negotiated cipher: ", tls.CipherSuiteName(state.CipherSuite))
			switch state.Version {
			//case tls.VersionSSL30:
			//	log.Println("negotiated TLS version: VersionSSL30")
			case tls.VersionTLS10:
				log.Println("negotiated TLS version: VersionTLS10")
			case tls.VersionTLS11:
				log.Println("negotiated TLS version: VersionTLS11")
			case tls.VersionTLS12:
				log.Println("negotiated TLS version: VersionTLS12")
			case tls.VersionTLS13:
				log.Println("negotiated TLS version: VersionTLS13")
			default:
				log.Println("negotiated to Unknown TLS version")
			}
		}
	}*/
	if state == http.StateClosed {
		delCHI(c.RemoteAddr().String())
	}
}

func getCertificateHook(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	certDir := "*.dumprequest.com"
	if helloInfo.ServerName == "dumprequest.com" || helloInfo.ServerName == "" {
		certDir = "dumprequest.com"
	}

	cert_ecdsa, err := tls.LoadX509KeyPair(fmt.Sprintf("./cert/%s/cert_ecdsa", certDir), fmt.Sprintf("./cert/%s/privkey_ecdsa", certDir))
	if err != nil {
		log.Fatalln(err)
	}

	if helloInfo.SupportsCertificate(&cert_ecdsa) == nil {
		return &cert_ecdsa, nil
	}

	cert_rsa, err := tls.LoadX509KeyPair(fmt.Sprintf("./cert/%s/cert_rsa", certDir), fmt.Sprintf("./cert/%s/privkey_rsa", certDir))
	if err != nil {
		log.Fatalln(err)
	}

	return &cert_rsa, nil
}

func getConfigForClientHook(helloInfo *tls.ClientHelloInfo) (*tls.Config, error) {
	// MUST save helloInfo here as getCertificate only runs on new connection
	// while getConfigForClient runs always on request
	saveCHI(helloInfo.Conn.RemoteAddr().String(), helloInfo)
	return nil, nil
}

func logging(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			recorder := &StatusRecorder{
				ResponseWriter: w,
				Status:         200,
			}
			defer func() {
				requestID, ok := r.Context().Value(requestIDKey).(string)
				if !ok {
					requestID = "unknown"
				}
				logger.WithFields(log.Fields{
					"request_id": requestID,
				}).Println(recorder.Status, r.Host, r.Method, r.URL.Path, r.RemoteAddr, r.UserAgent())
			}()
			next.ServeHTTP(recorder, r)
		})
	}
}

func tracing(nextRequestID func() string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get("X-Request-Id")
			if requestID == "" {
				requestID = nextRequestID()
			}
			ctx := context.WithValue(r.Context(), requestIDKey, requestID)
			w.Header().Set("X-Request-Id", requestID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
