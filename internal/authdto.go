package internal

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type Config struct {
	Host            string
	Port            int
	User            string
	Password        string
	Database        string
	AuthSchema      string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	MaxConnLifetime time.Duration
}

var pdb *sql.DB
var dbcfg Config = Config{
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

type AuthenticateUserDTO struct {
	Username string
	Password string
}

func (r *AuthRepository) AuthenticateUser(
	ctx context.Context,
	dto AuthenticateUserDTO,
) (string, int64, error) {

	query := `
        CALL ` + dbcfg.AuthSchema + `.auth_user_authenticate(
            $1,
            $2,
			$3,
			$4
        )
    `

	var hashedPassword string
	var userid int64

	err := r.DB.QueryRowContext(
		ctx,
		query,
		dto.Username,
		dto.Password,
		&hashedPassword,
		&userid,
	).Scan(&hashedPassword, &userid)

	if err != nil || hashedPassword == "" {
		return "", -1, err
	}

	return hashedPassword, userid, nil
}

type AddRefreshTokenDTO struct {
	UserID    int64
	Token     string
	ExpiresAt time.Time
}

func (r *AuthRepository) AddRefreshToken(
	ctx context.Context,
	dto AddRefreshTokenDTO,
) error {

	query := `
        CALL ` + dbcfg.AuthSchema + `.auth_add_refresh_token(
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

type RevokeRefreshTokenDTO struct {
	Token string
}

func (r *AuthRepository) RevokeRefreshToken(
	ctx context.Context,
	dto RevokeRefreshTokenDTO,
) error {

	query := `
        CALL ` + dbcfg.AuthSchema + `.auth_revoke_refresh_token(
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

type AddUserAuditDTO struct {
	UserID    int64
	LoginDate time.Time
	IPAddress *string
	UserAgent *string
	Success   bool
	Reason    int
}

func (r *AuthRepository) AddUserAudit(
	ctx context.Context,
	dto AddUserAuditDTO,
) error {

	if dto.UserID > 0 {
		query := `
			CALL ` + dbcfg.AuthSchema + `.auth_user_addaudit(
				$1,
				$2,
				$3,
				$4,
				$5,
				$6
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
			dto.Reason,
		)

		return err
	}

	return nil
}
