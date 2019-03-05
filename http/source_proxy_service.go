package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/influxdata/influxdb/kit/tracing"
	"github.com/opentracing/opentracing-go"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/influxdata/flux/lang"
	platform "github.com/influxdata/influxdb"
	"github.com/influxdata/influxdb/query"
	"github.com/influxdata/influxdb/query/influxql"
)

type SourceProxyQueryService struct {
	Addr               string
	InsecureSkipVerify bool
	platform.SourceFields
}

func (s *SourceProxyQueryService) Query(ctx context.Context, w io.Writer, req *query.ProxyRequest) (int64, error) {
	switch req.Request.Compiler.CompilerType() {
	case influxql.CompilerType:
		return s.queryInfluxQL(ctx, w, req)
	case lang.FluxCompilerType:
		return s.queryFlux(ctx, w, req)
	}
	return 0, fmt.Errorf("compiler type not supported")
}

func (s *SourceProxyQueryService) queryFlux(ctx context.Context, w io.Writer, req *query.ProxyRequest) (int64, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "SourceProxyQueryService.queryFlux")
	defer span.Finish()

	u, err := newURL(s.Addr, "/api/v2/query")
	if err != nil {
		return 0, tracing.LogError(span, err)
	}
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(req); err != nil {
		return 0, tracing.LogError(span, err)
	}

	hreq, err := http.NewRequest("POST", u.String(), &body)
	if err != nil {
		return 0, tracing.LogError(span, err)
	}
	hreq.Header.Set("Authorization", fmt.Sprintf("Token %s", s.Token))
	hreq.Header.Set("Content-Type", "application/json")
	hreq = hreq.WithContext(ctx)
	tracing.InjectToHTTPRequest(span, hreq)

	hc := newClient(u.Scheme, s.InsecureSkipVerify)
	resp, err := hc.Do(hreq)
	if err != nil {
		return 0, tracing.LogError(span, err)
	}
	defer resp.Body.Close()
	if err := CheckError(resp); err != nil {
		return 0, tracing.LogError(span, err)
	}
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		return 0, tracing.LogError(span, err)
	}

	return n, nil
}

func (s *SourceProxyQueryService) queryInfluxQL(ctx context.Context, w io.Writer, req *query.ProxyRequest) (int64, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "SourceProxyQueryService.queryInfluxQL")
	defer span.Finish()

	compiler, ok := req.Request.Compiler.(*influxql.Compiler)

	if !ok {
		err := fmt.Errorf("compiler is not of type 'influxql'")
		return 0, tracing.LogError(span, err)
	}

	u, err := newURL(s.Addr, "/query")
	if err != nil {
		return 0, tracing.LogError(span, err)
	}

	body := url.Values{}
	body.Add("db", compiler.DB)
	body.Add("org", compiler.Cluster)
	body.Add("q", compiler.Query)
	body.Add("rp", compiler.RP)
	hreq, err := http.NewRequest("POST", u.String(), strings.NewReader(body.Encode()))
	if err != nil {
		return 0, tracing.LogError(span, err)
	}
	hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hreq.Header.Set("Authorization", fmt.Sprintf("Token %s", s.Token))
	hreq = hreq.WithContext(ctx)

	hc := newClient(u.Scheme, s.InsecureSkipVerify)
	resp, err := hc.Do(hreq)
	if err != nil {
		return 0, tracing.LogError(span, err)
	}
	defer resp.Body.Close()

	if err := CheckError(resp); err != nil {
		return 0, tracing.LogError(span, err)
	}
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		return 0, tracing.LogError(span, err)
	}

	return n, nil
}
