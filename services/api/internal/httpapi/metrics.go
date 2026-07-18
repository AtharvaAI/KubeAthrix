package httpapi

import (
	"fmt"
	"net/http"
	"sort"
	"time"
)

func (s *Server) prometheusMetrics(w http.ResponseWriter, r *http.Request) {
	s.metrics.mu.Lock()
	statuses := make([]int, 0, len(s.metrics.requests))
	for status := range s.metrics.requests {
		statuses = append(statuses, status)
	}
	sort.Ints(statuses)
	requests := make(map[int]uint64, len(s.metrics.requests))
	var total uint64
	for _, status := range statuses {
		requests[status] = s.metrics.requests[status]
		total += requests[status]
	}
	duration := s.metrics.durationSum.Seconds()
	s.metrics.mu.Unlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintln(w, "# HELP kubeathrix_api_build_info Static API build information.")
	fmt.Fprintln(w, "# TYPE kubeathrix_api_build_info gauge")
	fmt.Fprintln(w, `kubeathrix_api_build_info{version="0.2.1"} 1`) // x-release-please-version
	fmt.Fprintln(w, "# HELP kubeathrix_http_requests_total HTTP requests grouped by response status.")
	fmt.Fprintln(w, "# TYPE kubeathrix_http_requests_total counter")
	for _, status := range statuses {
		fmt.Fprintf(w, "kubeathrix_http_requests_total{status=%q} %d\n", fmt.Sprint(status), requests[status])
	}
	fmt.Fprintln(w, "# HELP kubeathrix_http_request_duration_seconds_sum Total HTTP request duration.")
	fmt.Fprintln(w, "# TYPE kubeathrix_http_request_duration_seconds_sum counter")
	fmt.Fprintf(w, "kubeathrix_http_request_duration_seconds_sum %.6f\n", duration)
	fmt.Fprintln(w, "# HELP kubeathrix_http_request_duration_seconds_count Count of timed HTTP requests.")
	fmt.Fprintln(w, "# TYPE kubeathrix_http_request_duration_seconds_count counter")
	fmt.Fprintf(w, "kubeathrix_http_request_duration_seconds_count %d\n", total)
	fmt.Fprintln(w, "# HELP kubeathrix_http_requests_in_flight Current in-flight HTTP requests.")
	fmt.Fprintln(w, "# TYPE kubeathrix_http_requests_in_flight gauge")
	fmt.Fprintf(w, "kubeathrix_http_requests_in_flight %d\n", s.metrics.inFlight.Load())
	fmt.Fprintln(w, "# HELP kubeathrix_api_uptime_seconds API process uptime.")
	fmt.Fprintln(w, "# TYPE kubeathrix_api_uptime_seconds gauge")
	fmt.Fprintf(w, "kubeathrix_api_uptime_seconds %.0f\n", time.Since(s.metrics.startedAt).Seconds())
	if runs, err := s.repository.ListChaosRuns(r.Context()); err == nil {
		counts := map[string]int{}
		for _, run := range runs {
			counts[run.Status]++
		}
		chaosStatuses := make([]string, 0, len(counts))
		for status := range counts {
			chaosStatuses = append(chaosStatuses, status)
		}
		sort.Strings(chaosStatuses)
		fmt.Fprintln(w, "# HELP kubeathrix_chaos_runs Chaos runs grouped by persistent lifecycle state.")
		fmt.Fprintln(w, "# TYPE kubeathrix_chaos_runs gauge")
		for _, status := range chaosStatuses {
			fmt.Fprintf(w, "kubeathrix_chaos_runs{status=%q} %d\n", status, counts[status])
		}
	}
}
