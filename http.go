package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/pprof"
	"runtime"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sebest/xff"
	"github.com/tinkerbell/boots/conf"
	"github.com/tinkerbell/boots/httplog"
	"github.com/tinkerbell/boots/installers"
	"github.com/tinkerbell/boots/job"
	"github.com/tinkerbell/boots/metrics"
	"github.com/tinkerbell/boots/packet"
)

var (
	httpAddr = conf.HTTPBind
)

func init() {
	flag.StringVar(&httpAddr, "http-addr", httpAddr, "IP and port to listen on for HTTP.")
}

// ServeHTTP is a useless comment
func ServeHTTP() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", serveJobFile)
	mux.HandleFunc("/_packet/healthcheck", serveHealthchecker(GitRev, StartTime))
	mux.HandleFunc("/_packet/pprof/", pprof.Index)
	mux.HandleFunc("/_packet/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/_packet/pprof/profile", pprof.Profile)
	mux.HandleFunc("/_packet/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/_packet/pprof/trace", pprof.Trace)
	mux.HandleFunc("/events", func(w http.ResponseWriter, req *http.Request) { serveEvents(client, w, req) })
	mux.HandleFunc("/hardware-components", serveHardware)
	mux.HandleFunc("/healthcheck", serveHealthchecker(GitRev, StartTime))
	mux.HandleFunc("/metrics", promhttp.Handler().ServeHTTP)
	mux.HandleFunc("/phone-home/key", job.ServePublicKey)
	mux.HandleFunc("/phone-home", servePhoneHome)
	mux.HandleFunc("/problem", serveProblem)
	installers.RegisterHTTPHandlers(mux)

	var h http.Handler
	if len(conf.TrustedProxies) > 0 {
		xffmw, _ := xff.New(xff.Options{
			AllowedSubnets: conf.TrustedProxies,
		})

		h = xffmw.Handler(&httplog.Handler{
			Handler: mux,
		})
	} else {
		h = &httplog.Handler{
			Handler: mux,
		}
	}

	if err := http.ListenAndServe(httpAddr, h); err != nil {
		err = errors.Wrap(err, "listen and serve http")
		mainlog.Fatal(err)
	}
}

func serveHealthchecker(rev string, start time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		res := struct {
			GitRev     string  `json:"git_rev"`
			Uptime     float64 `json:"uptime"`
			Goroutines int     `json:"goroutines"`
		}{
			GitRev:     rev,
			Uptime:     time.Since(start).Seconds(),
			Goroutines: runtime.NumGoroutine(),
		}

		b, err := json.Marshal(&res)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			mainlog.Package("http").Error(errors.Wrap(err, "marshaling healtcheck json"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}
}

func serveJobFile(w http.ResponseWriter, req *http.Request) {
	labels := prometheus.Labels{"from": "http", "op": "file"}
	metrics.JobsTotal.With(labels).Inc()
	metrics.JobsInProgress.With(labels).Inc()
	defer metrics.JobsInProgress.With(labels).Dec()
	timer := prometheus.NewTimer(metrics.JobDuration.With(labels))
	defer timer.ObserveDuration()

	metrics.JobsInProgress.With(labels).Inc()
	l := mainlog.Package("http").With("ip", req.RemoteAddr)
	j, err := job.CreateFromRemoteAddr(req.RemoteAddr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		l.With("error", err).Info("no job found for client address")
		return
	}
	l = l.With("hardware_id", j.HardwareID().String(), "instance_id", j.InstanceID())

	// This gates serving PXE file by
	// 1. the existence of a hardware record in tink server
	// AND
	// 2. the network.interfaces[].netboot.allow_pxe value, in the tink server hardware record, equal to true
	// This allows serving custom ipxe scripts, starting up into OSIE or other installation environments
	// without a tink workflow present.
	if !j.AllowPxe() {
		w.WriteHeader(http.StatusNotFound)
		l.Info("the hardware data for this machine, or lack there of, does not allow it to pxe; allow_pxe: false")
		return
	}

	j.ServeFile(w, req)
}

func serveHardware(w http.ResponseWriter, req *http.Request) {
	labels := prometheus.Labels{"from": "http", "op": "hardware-components"}
	metrics.JobsTotal.With(labels).Inc()
	metrics.JobsInProgress.With(labels).Inc()
	defer metrics.JobsInProgress.With(labels).Dec()
	timer := prometheus.NewTimer(metrics.JobDuration.With(labels))
	defer timer.ObserveDuration()

	l := mainlog.Package("http").With("ip", req.RemoteAddr)
	j, err := job.CreateFromRemoteAddr(req.RemoteAddr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		l.With("error", err).Info("no job found for client address")
		return
	}
	l = l.With("hardware_id", j.HardwareID().String(), "instance_id", j.InstanceID())

	activeWorkflows, err := job.HasActiveWorkflow(j.HardwareID())
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		l.With("error", err).Info("failed to get workflows")
		return
	}
	if !activeWorkflows {
		w.WriteHeader(http.StatusNotFound)
		l.Info("no active workflows")
		return
	}

	j.AddHardware(w, req)
}

func servePhoneHome(w http.ResponseWriter, req *http.Request) {
	labels := prometheus.Labels{"from": "http", "op": "phone-home"}
	metrics.JobsTotal.With(labels).Inc()
	metrics.JobsInProgress.With(labels).Inc()
	defer metrics.JobsInProgress.With(labels).Dec()
	timer := prometheus.NewTimer(metrics.JobDuration.With(labels))
	defer timer.ObserveDuration()

	l := mainlog.Package("http").With("ip", req.RemoteAddr)
	j, err := job.CreateFromRemoteAddr(req.RemoteAddr)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		l.With("error", err).Info("no job found for client address")
		return
	}
	j.ServePhoneHomeEndpoint(w, req)
}

func serveProblem(w http.ResponseWriter, req *http.Request) {
	labels := prometheus.Labels{"from": "http", "op": "problem"}
	metrics.JobsTotal.With(labels).Inc()
	metrics.JobsInProgress.With(labels).Inc()
	defer metrics.JobsInProgress.With(labels).Dec()
	timer := prometheus.NewTimer(metrics.JobDuration.With(labels))
	defer timer.ObserveDuration()

	l := mainlog.Package("http").With("ip", req.RemoteAddr)
	j, err := job.CreateFromRemoteAddr(req.RemoteAddr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		l.With("error", err).Info("no job found for client address")
		return
	}
	l = l.With("hardware_id", j.HardwareID().String(), "instance_id", j.InstanceID())

	activeWorkflows, err := job.HasActiveWorkflow(j.HardwareID())
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		l.With("error", err).Info("failed to get workflows")
		return
	}
	if !activeWorkflows {
		w.WriteHeader(http.StatusNotFound)
		l.Info("no active workflows")
		return
	}

	j.ServeProblemEndpoint(w, req)
}

func readClose(r io.ReadCloser) (b []byte, err error) {
	b, err = ioutil.ReadAll(r)
	err = errors.Wrap(err, "read data")
	r.Close()
	return
}

type eventsServer interface {
	GetIDsFromIP(net.IP) (packet.HardwareID, string, error)
	PostInstanceEvent(string, io.Reader) (string, error)
}

// Forward user generated events to Packet API
func serveEvents(client eventsServer, w http.ResponseWriter, req *http.Request) {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		err = errors.Wrap(err, "split host port")
		mainlog.Package("http").With("ip", req.RemoteAddr, "error", err).Info("failed to parse remote ip")
		return
	}
	l := mainlog.Package("http").With("ip", host)

	ip := net.ParseIP(host)
	if ip == nil {
		w.WriteHeader(http.StatusOK)

		err := errors.New("no device found for client address")
		l.With("error", err).Info("failed to parse IP")
		return
	}

	hwID, instanceID, err := client.GetIDsFromIP(ip)
	if err != nil || instanceID == "" {
		w.WriteHeader(http.StatusOK)

		err := errors.New("no device found for client address")
		l.With("error", err).Info("failed to parse IP")
		return
	}
	l = l.With("hardware_id", hwID, "instance_id", instanceID)

	b, err := readClose(req.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		l.With("error", err).Info("failed to read body")
		return
	}
	if len(b) == 0 {
		w.WriteHeader(http.StatusBadRequest)

		err := errors.New("userEvent body is empty")
		l.With("error", err).Info("failed to read body")
		return
	}

	var res struct {
		Code    int    `json:"code"`
		State   string `json:"state"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(b, &res); err != nil {
		w.WriteHeader(http.StatusBadRequest)

		err := errors.New("userEvent cannot be generated from supplied json")
		l.With("error", err).Info("failed to read body")
		return
	}

	e := struct {
		Code    string `json:"type"`
		State   string `json:"state"`
		Message string `json:"body"`
	}{
		Code:    "user." + strconv.Itoa(res.Code),
		State:   res.State,
		Message: res.Message,
	}
	payload, err := json.Marshal(e)
	if err != nil {
		// TODO(mmlb): this should be 500
		w.WriteHeader(http.StatusBadRequest)

		err := errors.New("userEvent cannot be encoded")
		l.With("error", err).Info()
		return
	}

	if _, err := client.PostInstanceEvent(instanceID, bytes.NewReader(payload)); err != nil {
		// TODO(mmlb): this should be 500
		w.WriteHeader(http.StatusBadRequest)

		err := errors.New("failed to post userEvent")
		l.With("error", err).Info()
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte{})
	return
}
