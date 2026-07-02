package jwtauth

import (
	"context"
	"encoding/json"
	"errors"
	"jwtauth/internal"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func RegisterAuthRoutes(mux *http.ServeMux, basePath string) {
	mux.HandleFunc(basePath+"/login", Login)
	mux.HandleFunc(basePath+"/refresh", Refresh)
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type DBConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	SSLMode  string
}

type AuthConfig struct {
	jwtKey   []byte
	dbConfig DBConfig
}

type LoginResponse struct {
	Token   string `json:"access_token"`
	Refresh string `json:"refresh_token"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

var authConfig = AuthConfig{
	[]byte("super-secret-signing-key"),
	DBConfig{
		"localhost",
		5432,
		"auth",
		"auth",
		"Auth",
		"",
	},
}

func SetAuthConfig(cfg AuthConfig) {
	authConfig = cfg
	internal.SetDBConfig(internal.Config(cfg.dbConfig))
}

// Login
//
// @Summary Login utente
// @Description Autenticazione JWT
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body authdto.AuthenticateUserDTO true "Credenziali"
// @Success 200 {object} LoginResponse
// @Failure 401 {string} string
// @Router /auth/login [post]
func Login(w http.ResponseWriter, r *http.Request) {

	var credentials internal.AuthenticateUserDTO

	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	repo := internal.Repository()
	success := false
	var userid int64
	var err error
	var hashedPassword string

	// audit the access at the end of the function
	defer func() {
		auditAccess(r.Context(), repo, userid, r.RemoteAddr, r.Header["User-Agent"][0], success)
	}()

	hashedPassword, err = repo.AuthenticateUser(r.Context(), credentials)

	if err != nil || hashedPassword == "" {
		http.Error(w, "authentication error", 401)
		return
	}

	err = bcrypt.CompareHashAndPassword(
		[]byte(hashedPassword),
		[]byte(credentials.Password),
	)

	if err != nil {
		http.Error(w, "authentication error", 401)
		return
	}

	userid, err = repo.UserMap(r.Context(), internal.UserMapDTO{
		Username: credentials.Username,
	})

	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}

	var refreshExpiration *jwt.NumericDate = jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour))

	exp := time.Now().Add(15 * time.Minute)
	claims := &Claims{Username: credentials.Username, RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(exp)}}
	t, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(authConfig.jwtKey)
	refresh, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{Username: credentials.Username, RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: refreshExpiration}}).SignedString(authConfig.jwtKey)

	// store token in DB
	err = repo.AddRefreshToken(r.Context(), internal.AddRefreshTokenDTO{
		UserID:    userid,
		Token:     refresh,
		ExpiresAt: refreshExpiration.Time,
	})

	success = true

	json.NewEncoder(w).Encode(LoginResponse{
		Token:   t,
		Refresh: refresh,
	})
}

func Refresh(w http.ResponseWriter, r *http.Request) {

	token := r.Header.Get("Authorization")
	if len(token) < 8 {
		http.Error(w, "missing token", 401)
		return
	}
	_, err := jwt.ParseWithClaims(token[7:], &Claims{}, func(t *jwt.Token) (interface{}, error) { return authConfig.jwtKey, nil })
	if err != nil {
		http.Error(w, "invalid token", 401)
		return
	}

	// TODO check refresh token

	Login(w, r)
}

// Authentication handler

func Auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if len(token) < 8 {
			http.Error(w, "missing token", 401)
			return
		}
		jwttoken, err := jwt.ParseWithClaims(token[7:], &Claims{}, func(t *jwt.Token) (interface{}, error) { return authConfig.jwtKey, nil })

		if !jwttoken.Valid {
			if err != nil {

				if errors.Is(err, jwt.ErrTokenExpired) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)

					json.NewEncoder(w).Encode(ErrorResponse{
						Error:   "token_expired",
						Message: "JWT token has expired",
					})
				}

				if errors.Is(err, jwt.ErrTokenNotValidYet) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)

					json.NewEncoder(w).Encode(ErrorResponse{
						Error:   "token_invalid",
						Message: "JWT token not already valid",
					})
				}

				if errors.Is(err, jwt.ErrTokenMalformed) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)

					json.NewEncoder(w).Encode(ErrorResponse{
						Error:   "token_malformed",
						Message: "JWT token has wrong format",
					})
				}

				if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)

					json.NewEncoder(w).Encode(ErrorResponse{
						Error:   "token_signature",
						Message: "JWT token has wrong signature",
					})
				}

				return
			}
		}

		next(w, r)
	}
}

func auditAccess(context context.Context, repo *internal.AuthRepository, userid int64, remoteAddr string, userAgent string, success bool) error {
	return repo.AddUserAudit(context, internal.AddUserAuditDTO{
		UserID:    userid,
		LoginDate: time.Now().UTC(),
		IPAddress: &remoteAddr,
		UserAgent: &userAgent,
		Success:   success,
	})
}
