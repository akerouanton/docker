package otelutil

import (
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// RecordStatus records the status of a span based on the error provided.
//
// If err is nil, the span takes status OK. If err is not nil, the span takes
// status Error, and the error message is recorded.
func RecordStatus(span trace.Span, err error) {
	status := codes.Ok
	var desc string
	if err != nil {
		span.RecordError(err)
		status = codes.Error
		desc = err.Error()
	}
	span.SetStatus(status, desc)
}
