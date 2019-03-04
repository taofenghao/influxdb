package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/influxdata/flux"
	"github.com/influxdata/flux/csv"
	"github.com/influxdata/flux/iocounter"
	"github.com/influxdata/influxdb"
	"github.com/influxdata/influxdb/query"
	"github.com/julienschmidt/httprouter"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

const (
	queryPath = "/api/v2/querysvc"

	queryStatisticsTrailer = "Influx-Query-Statistics"
)

type QueryHandler struct {
	*httprouter.Router

	Logger *zap.Logger

	csvDialect csv.Dialect

	QueryService     query.QueryService
	CompilerMappings flux.CompilerMappings

	// OnFinishedHandler is invoked when a query is finished.
	// If nil, it is not called.
	OnFinishedHandler func(event QueryFinishedEvent)
}

// QueryFinishedEvent is sent when a query is finished to the OnFinishedHandler.
type QueryFinishedEvent struct {
	OrganizationID    influxdb.ID
	Statistics        flux.Statistics
	ResponseByteCount int64
	Err               error
}

// NewQueryHandler returns a new instance of QueryHandler.
func NewQueryHandler() *QueryHandler {
	h := &QueryHandler{
		Router: NewRouter(),
		csvDialect: csv.Dialect{
			ResultEncoderConfig: csv.DefaultEncoderConfig(),
		},
	}

	h.HandlerFunc("GET", "/ping", h.handlePing)
	h.HandlerFunc("POST", queryPath, h.handlePostQuery)
	return h
}

// handlePing returns a simple response to let the client know the server is running.
func (h *QueryHandler) handlePing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNoContent)
}

// handlePostQuery is the HTTP handler for the POST /api/v2/query route.
func (h *QueryHandler) handlePostQuery(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req query.Request
	req.WithCompilerMappings(h.CompilerMappings)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		EncodeError(ctx, err, w)
		return
	}

	results, err := h.QueryService.Query(ctx, &req)
	if err != nil {
		EncodeError(ctx, err, w)
		return
	}
	// Always cancel the results to free resources.
	defer results.Release()

	// Setup headers
	w.Header().Set("Trailer", queryStatisticsTrailer)

	// NOTE: We do not write out the headers here.
	// It is possible that if the encoding step fails
	// that we can write an error header so long as
	// the encoder did not write anything.
	// As such we rely on the http.ResponseWriter behavior
	// to write an StatusOK header with the first write.

	encw := iocounter.Writer{Writer: w}
	switch r.Header.Get("Accept") {
	case "text/csv":
		fallthrough
	default:
		h.csvDialect.SetHeaders(w)
		encoder := h.csvDialect.Encoder()
		n, err := encoder.Encode(&encw, results)
		if err != nil {
			if n == 0 {
				// If the encoder did not write anything, we can write an error header.
				EncodeError(ctx, err, w)
			} else {
				h.Logger.Info("Failed to encode client response",
					zap.Error(err),
				)
			}
		}
	}

	// Release the resources which should finalize the statistics.
	results.Release()

	stats := results.Statistics()
	stats.Metadata.Add("influxdb/response-bytes", encw.Count())
	if h.OnFinishedHandler != nil {
		event := QueryFinishedEvent{
			OrganizationID:    req.OrganizationID,
			Statistics:        stats,
			ResponseByteCount: encw.Count(),
			Err:               results.Err(),
		}
		h.OnFinishedHandler(event)
	}

	data, err := json.Marshal(stats)
	if err != nil {
		h.Logger.Info("Failed to encode statistics", zap.Error(err))
		return
	}
	// Write statistics trailer
	w.Header().Set(queryStatisticsTrailer, string(data))
}

// PrometheusCollectors satisifies the prom.PrometheusCollector interface.
func (h *QueryHandler) PrometheusCollectors() []prometheus.Collector {
	// TODO: gather and return relevant metrics.
	return nil
}

type QueryService struct {
	Addr               string
	Token              string
	InsecureSkipVerify bool
}

// Ping checks to see if the server is responding to a ping request.
func (s *QueryService) Ping(ctx context.Context) error {
	u, err := newURL(s.Addr, "/ping")
	if err != nil {
		return err
	}

	hreq, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return err
	}
	SetToken(s.Token, hreq)
	hreq = hreq.WithContext(ctx)

	hc := newClient(u.Scheme, s.InsecureSkipVerify)
	resp, err := hc.Do(hreq)
	if err != nil {
		return err
	}

	return CheckError(resp)
}

// Query calls the query route with the requested query and returns a result iterator.
func (s *QueryService) Query(ctx context.Context, req *query.Request) (flux.ResultIterator, error) {
	u, err := newURL(s.Addr, queryPath)
	if err != nil {
		return nil, err
	}
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(req); err != nil {
		return nil, err
	}

	hreq, err := http.NewRequest("POST", u.String(), &body)
	if err != nil {
		return nil, err
	}
	SetToken(s.Token, hreq)
	hreq = hreq.WithContext(ctx)

	hc := newClient(u.Scheme, s.InsecureSkipVerify)
	resp, err := hc.Do(hreq)
	if err != nil {
		return nil, err
	}
	if err := CheckError(resp); err != nil {
		return nil, err
	}

	var decoder flux.MultiResultDecoder
	switch resp.Header.Get("Content-Type") {
	case "text/csv":
		fallthrough
	default:
		decoder = csv.NewMultiResultDecoder(csv.ResultDecoderConfig{})
	}
	results, err := decoder.Decode(resp.Body)
	if err != nil {
		return nil, err
	}

	statResults := &statsResultIterator{
		results: results,
		resp:    resp,
	}
	return statResults, nil
}

// statsResultIterator implements flux.ResultIterator and flux.Statisticser by reading the HTTP trailers.
type statsResultIterator struct {
	results    flux.ResultIterator
	resp       *http.Response
	statisitcs flux.Statistics
	err        error
}

func (s *statsResultIterator) More() bool {
	return s.results.More()
}

func (s *statsResultIterator) Next() flux.Result {
	return s.results.Next()
}

func (s *statsResultIterator) Release() {
	s.results.Release()
	s.readStats()
}

func (s *statsResultIterator) Err() error {
	err := s.results.Err()
	if err != nil {
		return err
	}
	return s.err
}

func (s *statsResultIterator) Statistics() flux.Statistics {
	return s.statisitcs
}

// readStats reads the query statisitcs off the response trailers.
func (s *statsResultIterator) readStats() {
	data := s.resp.Trailer.Get(queryStatisticsTrailer)
	if data != "" {
		s.err = json.Unmarshal([]byte(data), &s.statisitcs)
	}
}

type responseWriter struct {
	http.ResponseWriter
	count int
}

func (rw *responseWriter) Write(data []byte) (n int, err error) {
	n, err = rw.ResponseWriter.Write(data)
	rw.count += n
	return n, err
}
