package query

import (
	"context"
	"encoding/json"
	"github.com/influxdata/influxdb/kit/tracing"
	"github.com/opentracing/opentracing-go"
	"io"
	"net/http"

	"github.com/influxdata/flux"
	platform "github.com/influxdata/influxdb"
)

// QueryServiceBridge implements the QueryService interface while consuming the AsyncQueryService interface.
type QueryServiceBridge struct {
	AsyncQueryService AsyncQueryService
}

func (b QueryServiceBridge) Query(ctx context.Context, req *Request) (flux.ResultIterator, error) {
	query, err := b.AsyncQueryService.Query(ctx, req)
	if err != nil {
		return nil, err
	}
	return flux.NewResultIteratorFromQuery(query), nil
}

// ProxyQueryServiceBridge implements ProxyQueryService while consuming a QueryService interface.
type ProxyQueryServiceBridge struct {
	QueryService QueryService
}

func (b ProxyQueryServiceBridge) Query(ctx context.Context, w io.Writer, req *ProxyRequest) (int64, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "ProxyQueryServiceBridge.Query")
	defer span.Finish()

	results, err := b.QueryService.Query(ctx, &req.Request)
	if err != nil {
		return 0, tracing.LogError(span, err)
	}
	defer results.Release()

	// Setup headers
	if w, ok := w.(http.ResponseWriter); ok {
		w.Header().Set("Trailer", "Influx-Query-Statistics")
	}

	encoder := req.Dialect.Encoder()
	n, err := encoder.Encode(w, results)
	if err != nil {
		return n, tracing.LogError(span, err)
	}

	if w, ok := w.(http.ResponseWriter); ok {
		data, _ := json.Marshal(results.Statistics())
		w.Header().Set("Influx-Query-Statistics", string(data))
	}

	return n, nil
}

// REPLQuerier implements the repl.Querier interface while consuming a QueryService
type REPLQuerier struct {
	// Authorization is the authorization to provide for all requests
	Authorization *platform.Authorization
	// OrganizationID is the ID to provide for all requests
	OrganizationID platform.ID
	QueryService   QueryService
}

func (q *REPLQuerier) Query(ctx context.Context, compiler flux.Compiler) (flux.ResultIterator, error) {
	req := &Request{
		Authorization:  q.Authorization,
		OrganizationID: q.OrganizationID,
		Compiler:       compiler,
	}
	return q.QueryService.Query(ctx, req)
}
