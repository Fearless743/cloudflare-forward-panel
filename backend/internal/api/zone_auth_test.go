package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"cloudflare-forward-panel/internal/auth"
	"cloudflare-forward-panel/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&models.User{}, &models.CFAccount{}, &models.Zone{}, &models.ZoneUser{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &Handler{db: db}
}

func TestAvailableLocalZonesForUserOnlyAssigned(t *testing.T) {
	h := newTestHandler(t)

	zones := []models.Zone{
		{CFID: "cf-a", Name: "a.example.com"},
		{CFID: "cf-b", Name: "b.example.com"},
		{CFID: "cf-c", Name: "c.example.com"},
	}
	for i := range zones {
		if err := h.db.Create(&zones[i]).Error; err != nil {
			t.Fatalf("create zone: %v", err)
		}
	}
	if err := h.db.Create(&models.ZoneUser{ZoneID: zones[0].ID, UserID: 1}).Error; err != nil {
		t.Fatalf("create assignment: %v", err)
	}

	got := h.availableLocalZonesForUser(1)
	if len(got) != 1 || got[0].Name != "a.example.com" {
		t.Fatalf("user 1 zones = %+v, want only a.example.com", got)
	}

	if got := h.availableLocalZonesForUser(2); len(got) != 0 {
		t.Fatalf("user 2 zones = %+v, want none", got)
	}
}

func TestUserCanUseZoneCFID(t *testing.T) {
	h := newTestHandler(t)

	zone := models.Zone{CFID: "cf-a", Name: "a.example.com"}
	if err := h.db.Create(&zone).Error; err != nil {
		t.Fatalf("create zone: %v", err)
	}
	if err := h.db.Create(&models.ZoneUser{ZoneID: zone.ID, UserID: 1}).Error; err != nil {
		t.Fatalf("create assignment: %v", err)
	}

	if !h.userCanUseZoneCFID(1, "cf-a") {
		t.Fatal("user 1 should use assigned zone")
	}
	if h.userCanUseZoneCFID(2, "cf-a") {
		t.Fatal("user 2 should not use unassigned zone")
	}
	if h.userCanUseZoneCFID(1, "cf-missing") {
		t.Fatal("missing zone should not be usable")
	}
}

func TestListForwardRulesOnlyOwn(t *testing.T) {
	h := newTestHandler(t)
	if err := h.db.AutoMigrate(&models.ForwardRule{}); err != nil {
		t.Fatalf("migrate forward rules: %v", err)
	}

	rules := []models.ForwardRule{
		{UserID: 1, ZoneID: "cf-a", ZoneName: "a.example.com", Hostname: "a.a.example.com", OriginPort: 1001},
		{UserID: 2, ZoneID: "cf-a", ZoneName: "a.example.com", Hostname: "b.a.example.com", OriginPort: 1001},
	}
	for i := range rules {
		if err := h.db.Create(&rules[i]).Error; err != nil {
			t.Fatalf("create rule: %v", err)
		}
	}

	// 管理员与普通用户都只能看到自己创建的规则
	for _, role := range []string{"admin", "user"} {
		claims := &auth.Claims{UserID: 1, Username: "u1", Role: role}
		req := httptest.NewRequest("GET", "/api/forward-rules", nil)
		req = req.WithContext(context.WithValue(req.Context(), auth.UserContextKey, claims))
		w := httptest.NewRecorder()

		h.listForwardRules(w, req)

		var resp struct {
			Success bool `json:"success"`
			Result  []struct {
				UserID   uint   `json:"user_id"`
				Hostname string `json:"hostname"`
			} `json:"result"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("role %s: decode response: %v", role, err)
		}
		if !resp.Success || len(resp.Result) != 1 {
			t.Fatalf("role %s: got %d rules, want 1", role, len(resp.Result))
		}
		if resp.Result[0].UserID != 1 || resp.Result[0].Hostname != "a.a.example.com" {
			t.Fatalf("role %s: got %+v, want only own rule", role, resp.Result[0])
		}
	}
}

func TestFindExistingRuleForPortInZones(t *testing.T) {
	h := newTestHandler(t)
	if err := h.db.AutoMigrate(&models.ForwardRule{}); err != nil {
		t.Fatalf("migrate forward rules: %v", err)
	}

	rules := []models.ForwardRule{
		{UserID: 1, ZoneID: "cf-a", ZoneName: "a.example.com", Hostname: "a1.a.example.com", OriginPort: 8080},
		{UserID: 2, ZoneID: "cf-b", ZoneName: "b.example.com", Hostname: "b1.b.example.com", OriginPort: 8080},
	}
	for i := range rules {
		if err := h.db.Create(&rules[i]).Error; err != nil {
			t.Fatalf("create rule: %v", err)
		}
	}

	if got := h.findExistingRuleForPortInZones(8080, []string{"cf-b"}, 0); got == nil || got.ZoneID != "cf-b" {
		t.Fatalf("zone B lookup = %+v, want cf-b", got)
	}
	if got := h.findExistingRuleForPortInZones(8080, []string{"cf-a"}, 0); got == nil || got.ZoneID != "cf-a" {
		t.Fatalf("zone A lookup = %+v, want cf-a", got)
	}
	if got := h.findExistingRuleForPortInZones(8080, []string{"cf-c"}, 0); got != nil {
		t.Fatalf("zone C lookup = %+v, want nil", got)
	}
	if got := h.findExistingRuleForPortInZones(9999, []string{"cf-a", "cf-b"}, 0); got != nil {
		t.Fatalf("unused port lookup = %+v, want nil", got)
	}
}
