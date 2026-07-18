package internal

import (
	"testing"
	"time"
)

func TestGetUserRoles(t *testing.T) {

	SetDBConfig(Config{
		"localhost",
		5432,
		"postgres",
		"postgres",
		"postgres",
		"auth",
		"",
		25,
		10,
		30 * time.Minute,
	})

	repo := Repository()

	roles, err := repo.GetUserRoles(1)

	if err != nil {
		t.Errorf("Error: %s", err.Error())
	}

	if len(roles) == 0 {
		t.Errorf("Empty recordset")
	}
}
