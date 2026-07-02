package internal

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	SSLMode  string
}

var pdb *sql.DB
var dbcfg Config = Config{
	"localhost",
	5432,
	"scadenziario",
	"scadenziario",
	"ComelitPL",
	"",
}

func SetDBConfig(cfg Config) {
	dbcfg = cfg
}

// Connect apre la connessione a PostgreSQL e verifica il collegamento
func connect(cfg Config) error {

	if pdb != nil {
		return nil
	}

	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host,
		cfg.Port,
		cfg.User,
		cfg.Password,
		cfg.Database,
		cfg.SSLMode,
	)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}

	// Pool di connessioni
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)

	// Test connessione
	if err := db.Ping(); err != nil {
		db.Close()
		return err
	}

	pdb = db

	return nil
}

// Disconnect chiude la connessione
func disconnect() error {
	if pdb == nil {
		return nil
	}

	var tbd *sql.DB = pdb

	pdb = nil

	return tbd.Close()
}

type AuthRepository struct {
	DB *sql.DB
}

var repo *AuthRepository

func Repository() *AuthRepository {
	if repo == nil {
		err := connect(dbcfg)

		if err == nil {
			repo = &AuthRepository{
				DB: pdb,
			}
		}
	}
	return repo
}

type UserMapDTO struct {
	Username string `json:"username"`
}

func (r *AuthRepository) UserMap(
	ctx context.Context,
	dto UserMapDTO,
) (int64, error) {

	var userID int64

	query := `
		CALL public.auth_user_map(
            $1,
            $2
        )    
	`

	err := r.DB.QueryRowContext(
		ctx,
		query,
		dto.Username,
		&userID,
	).Scan(&userID)

	if err != nil {
		return 0, err
	}

	return userID, nil
}

type AuthenticateUserDTO struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (r *AuthRepository) AuthenticateUser(
	ctx context.Context,
	dto AuthenticateUserDTO,
) (string, error) {

	query := `
        call public.auth_user_authenticate(
            $1,
            $2,
			$3
        )
    `

	var hashedPassword string

	err := r.DB.QueryRowContext(
		ctx,
		query,
		dto.Username,
		dto.Password,
		&hashedPassword,
	).Scan(&hashedPassword)

	if err != nil || hashedPassword == "" {
		return "", err
	}

	return hashedPassword, nil
}

type AddRefreshTokenDTO struct {
	UserID    int64     `json:"userId"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func (r *AuthRepository) AddRefreshToken(
	ctx context.Context,
	dto AddRefreshTokenDTO,
) error {

	query := `
        CALL public.auth_add_refresh_token(
            $1,
            $2,
            $3
        )
    `

	_, err := r.DB.ExecContext(
		ctx,
		query,
		dto.UserID,
		dto.Token,
		dto.ExpiresAt,
	)

	return err
}

type AddUserAuditDTO struct {
	UserID    int64     `json:"userId"`
	LoginDate time.Time `json:"loginDate,omitempty"`
	IPAddress *string   `json:"ipAddress,omitempty"`
	UserAgent *string   `json:"userAgent,omitempty"`
	Success   bool      `json:"success"`
}

func (r *AuthRepository) AddUserAudit(
	ctx context.Context,
	dto AddUserAuditDTO,
) error {

	if dto.UserID > 0 {
		query := `
			CALL public.auth_add_user_audit(
				$1,
				$2,
				$3,
				$4,
				$5
			)
		`

		_, err := r.DB.ExecContext(
			ctx,
			query,
			dto.UserID,
			dto.LoginDate,
			dto.IPAddress,
			dto.UserAgent,
			dto.Success,
		)

		return err
	}

	return nil
}

type RevokeRefreshTokenDTO struct {
	Token string `json:"token"`
}

func (r *AuthRepository) RevokeRefreshToken(
	ctx context.Context,
	dto RevokeRefreshTokenDTO,
) error {

	query := `
        CALL public.auth_revoke_refresh_token(
            $1
        )
    `

	_, err := r.DB.ExecContext(
		ctx,
		query,
		dto.Token,
	)

	return err
}

type ChangePasswordDTO struct {
	UserID         int64  `json:"userId"`
	HashedPassword string `json:"hashedPassword"`
}

func (r *AuthRepository) ChangePassword(
	ctx context.Context,
	dto ChangePasswordDTO,
) error {

	query := `
        CALL public.auth_user_changepassword(
            $1,
            $2
        )
    `

	_, err := r.DB.ExecContext(
		ctx,
		query,
		dto.UserID,
		dto.HashedPassword,
	)

	return err
}
