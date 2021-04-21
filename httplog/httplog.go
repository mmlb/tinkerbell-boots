package httplog

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/packethost/pkg/log"
	"github.com/pkg/errors"
)

type handler struct {
	http.Handler
	logger log.Logger
}

func Handler(l log.Logger, h http.Handler) *handler {
	return &handler{
		Handler: h,
		logger:  l.Package("http"),
	}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var (
		start  = time.Now()
		method = req.Method
		uri    = req.RequestURI
		client = clientIP(req.RemoteAddr)
	)

	log := true
	if uri == "/metrics" || strings.HasPrefix(uri, "/_packet") {
		log = false
	}
	if log {
		h.logger.With("event", "sr", "method", method, "uri", uri, "client", client).Debug()
	}

	res := &ResponseWriter{ResponseWriter: w}
	h.Handler.ServeHTTP(res, req) // process the request
	d := time.Since(start)

	if log {
		h.logger.With("event", "ss", "method", method, "uri", uri, "client", client, "duration", d, "status", res.StatusCode).Info()
	}
}

type ResponseWriter struct {
	http.ResponseWriter
	StatusCode int
}

func (w *ResponseWriter) Write(b []byte) (int, error) {
	if w.StatusCode == 0 {
		w.StatusCode = 200
	}
	n, err := w.ResponseWriter.Write(b)
	return n, errors.Wrap(err, "writing response")
}

func (w *ResponseWriter) WriteHeader(code int) {
	if w.StatusCode == 0 {
		w.StatusCode = code
	}
	w.ResponseWriter.WriteHeader(code)
}

type transport struct {
	http.RoundTripper
	logger log.Logger
}

func Transport(l log.Logger, rt http.RoundTripper) *transport {
	return &transport{
		RoundTripper: rt,
		logger:       l.Package("http"),
	}
}

func (t *transport) RoundTrip(req *http.Request) (res *http.Response, err error) {
	var (
		method = req.Method
		uri    = req.URL.String()
	)
	t.logger.With("event", "cs", "method", method, "uri", uri).Debug()

	start := time.Now()
	res, err = t.RoundTripper.RoundTrip(req)
	d := time.Since(start)

	if res != nil {
		t.logger.With("event", "cr", "method", method, "uri", uri, "duration", d, "status", res.StatusCode).Info()
	}
	return
}

func clientIP(str string) string {
	host, _, err := net.SplitHostPort(str)
	if err != nil {
		return "?"
	}
	return host
}
