package api

import (
	"testing"

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
