package api

import (
	"reflect"
	"testing"
)

func TestParseHostnameList(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want []string
	}{
		{
			name: "single host",
			expr: `(http.host eq "a.example.com")`,
			want: []string{"a.example.com"},
		},
		{
			name: "multiple hosts",
			expr: `((http.host eq "a.example.com") or (http.host eq "b.example.com"))`,
			want: []string{"a.example.com", "b.example.com"},
		},
		{
			name: "legacy comma separated",
			expr: `a.example.com, b.example.com`,
			want: []string{"a.example.com", "b.example.com"},
		},
		{
			name: "empty",
			expr: ``,
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseHostnameList(tt.expr)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseHostnameList(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestBuildHostExpressionRoundTrip(t *testing.T) {
	hosts := []string{"b.example.com", "a.example.com", "a.example.com"}
	expr := buildHostExpression(hosts)
	wantExpr := `((http.host eq "a.example.com") or (http.host eq "b.example.com"))`
	if expr != wantExpr {
		t.Fatalf("buildHostExpression() = %q, want %q", expr, wantExpr)
	}

	got := parseHostnameList(expr)
	want := []string{"a.example.com", "b.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %v, want %v", got, want)
	}
}

func TestDetectDNSRecordType(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"192.0.2.1", "A"},
		{"2001:db8::1", "AAAA"},
		{"origin.example.com", "CNAME"},
	}
	for _, tt := range tests {
		if got := detectDNSRecordType(tt.host); got != tt.want {
			t.Errorf("detectDNSRecordType(%q) = %q, want %q", tt.host, got, tt.want)
		}
	}
}
