package api

import (
	"encoding/json"
	"testing"

	"cloudflare-forward-panel/internal/cfclient"
)

func TestAggregateAnalyticsRows(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		m, ts := aggregateAnalyticsRows(nil)
		if m.TotalRequests != 0 || m.TotalBytes != 0 || m.TotalVisits != 0 || m.UniqueIPs != 0 {
			t.Fatalf("expected zero metrics, got %+v", m)
		}
		if len(ts) != 0 {
			t.Fatalf("expected empty timeseries, got %d items", len(ts))
		}
	})

	t.Run("single row", func(t *testing.T) {
		row := cfclient.ZoneHTTPMetrics{}
		row.Sum.Requests = 100
		row.Sum.EdgeResponseBytes = 5000
		row.Sum.Visits = 50
		row.Uniq.Uniques = 30
		row.Dimensions.DatetimeMinute = "2026-08-16T10:00:00Z"

		m, ts := aggregateAnalyticsRows([]cfclient.ZoneHTTPMetrics{row})
		if m.TotalRequests != 100 || m.TotalBytes != 5000 || m.TotalVisits != 50 || m.UniqueIPs != 30 {
			t.Fatalf("unexpected metrics: %+v", m)
		}
		if len(ts) != 1 {
			t.Fatalf("expected 1 timeseries point, got %d", len(ts))
		}
		if ts[0].Time != "2026-08-16T10:00:00Z" || ts[0].Requests != 100 || ts[0].Bytes != 5000 {
			t.Fatalf("unexpected timeseries point: %+v", ts[0])
		}
	})

	t.Run("multiple rows", func(t *testing.T) {
		rows := make([]cfclient.ZoneHTTPMetrics, 3)
		for i := range rows {
			rows[i].Sum.Requests = int64((i + 1) * 10)
			rows[i].Sum.EdgeResponseBytes = int64((i + 1) * 100)
			rows[i].Sum.Visits = int64((i + 1) * 5)
			rows[i].Uniq.Uniques = int64((i + 1) * 3)
			rows[i].Dimensions.DatetimeMinute = "2026-08-16T10:0" + string(rune('0'+i)) + ":00Z"
		}
		m, ts := aggregateAnalyticsRows(rows)
		if m.TotalRequests != 60 || m.TotalBytes != 600 || m.TotalVisits != 30 || m.UniqueIPs != 18 {
			t.Fatalf("unexpected metrics: %+v", m)
		}
		if len(ts) != 3 {
			t.Fatalf("expected 3 timeseries points, got %d", len(ts))
		}
	})
}

func TestAggregateAnalyticsRows_Hourly(t *testing.T) {
	row := cfclient.ZoneHTTPMetrics{}
	row.Sum.Requests = 200
	row.Sum.EdgeResponseBytes = 10000
	row.Dimensions.DatetimeHour = "2026-08-16T10:00:00Z"
	// 分钟为空，小时有值 → TimeKey 取小时

	m, ts := aggregateAnalyticsRows([]cfclient.ZoneHTTPMetrics{row})
	if m.TotalRequests != 200 {
		t.Fatalf("expected 200 requests, got %d", m.TotalRequests)
	}
	if len(ts) != 1 || ts[0].Time != "2026-08-16T10:00:00Z" {
		t.Fatalf("unexpected timeseries: %+v", ts)
	}
}

func TestAnalyticsMetricsJSON(t *testing.T) {
	m := analyticsMetrics{
		TotalRequests: 12345,
		TotalBytes:    987654321,
		TotalVisits:   4567,
		UniqueIPs:     890,
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var got analyticsMetrics
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got != m {
		t.Fatalf("round-trip mismatch: %+v vs %+v", got, m)
	}
}