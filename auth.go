package jwtauth

import (
	"context"
	"encoding/json"
	"errors"

	"net/http"
	"time"

	"github.com/Auarion/jwtauth/internal"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Configuration
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type AuthConfig struct {
	JwtKey               []byte
	TokenExpirationMin   int32
	RefreshExpirationMin int32
	DbConfig             DBConfig
}

type DBConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	SSLMode  string
}

var authConfig = AuthConfig{
	[]byte("super-secret-signing-key"),
	15,
	60 * 24,
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
	internal.SetDBConfig(internal.Config(cfg.DbConfig))
}

// APIs

type AuthenticateUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token   string `json:"access_token"`
	Refresh string `json:"refresh_token"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func RegisterAuthRoutes(mux *http.ServeMux, basePath string) {
	mux.HandleFunc("POST "+basePath+"/login", Login)
	mux.HandleFunc("GET "+basePath+"/refresh", Refresh)
}

// Login
//
// @Summary Login request
// @Description JWT authentication and tokens release
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body authdto.AuthenticateUser true "User credentials"
// @Success 200 {object} LoginResponse
// @Failure 401 {string} string
// @Router /auth/login [post]
func Login(w http.ResponseWriter, r *http.Request) {

	var credentials AuthenticateUser

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
		auditAccess(r.Context(), repo, userid, r.RemoteAddr, r.Header["User-Agent"][0], success, 0)
	}()

	hashedPassword, userid, err = repo.AuthenticateUser(r.Context(), internal.AuthenticateUserDTO{
		Username: credentials.Username,
		Password: credentials.Password,
	})

	if err != nil || hashedPassword == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(ErrorResponse{
			Error:   "auth_error",
			Message: "Authentication error",
		})
		return
	}

	err = bcrypt.CompareHashAndPassword(
		[]byte(hashedPassword),
		[]byte(credentials.Password),
	)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(ErrorResponse{
			Error:   "auth_error",
			Message: "Authentication error",
		})
		return
	}

	t, refresh, refreshExpiration := generateTokens(credentials.Username)

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

// Refresh
//
// @Summary Token refresh
// @Description Token generation using refresh token
// @Tags Authentication
// @Accept
// @Produce json
// @Success 200 {object} LoginResponse
// @Failure 401 {object} ErrorResponse
// @Router /auth/refresh [get]
func Refresh(w http.ResponseWriter, r *http.Request) {

	repo := internal.Repository()
	var userid int64
	success := false

	// audit the access at the end of the function
	defer func() {
		auditAccess(r.Context(), repo, userid, r.RemoteAddr, r.Header["User-Agent"][0], success, 1)
	}()

	token := r.Header.Get("Authorization")
	if len(token) < 8 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(ErrorResponse{
			Error:   "token_format",
			Message: "Invalid token format",
		})
		return
	}

	jwttoken, err := jwt.ParseWithClaims(token[7:], &Claims{}, func(t *jwt.Token) (interface{}, error) { return authConfig.JwtKey, nil })

	if !jwttoken.Valid {
		tokenError(err, w)
	} else {
		username := jwttoken.Claims.(jwt.MapClaims)["username"].(string)
		t, refresh, refreshExpiration := generateTokens(username)

		userid, _ := repo.UserMap(r.Context(), internal.UserMapDTO{
			Username: username,
		})

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
}

// Authentication handler

func Auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if len(token) < 8 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(ErrorResponse{
				Error:   "token_format",
				Message: "Invalid token format",
			})
			return
		}
		jwttoken, err := jwt.ParseWithClaims(token[7:], &Claims{}, func(t *jwt.Token) (interface{}, error) { return authConfig.JwtKey, nil })

		if !jwttoken.Valid {
			tokenError(err, w)
		} else {
			next(w, r)
		}
	}
}

func generateTokens(username string) (string, string, *jwt.NumericDate) {
	var refreshExpiration *jwt.NumericDate = jwt.NewNumericDate(time.Now().Add(time.Duration(authConfig.RefreshExpirationMin) * time.Minute))

	exp := time.Now().Add(time.Duration(authConfig.TokenExpirationMin) * time.Minute)
	claims := &Claims{Username: username, RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(exp)}}
	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(authConfig.JwtKey)

	exp = time.Now().Add(time.Duration(authConfig.RefreshExpirationMin) * time.Minute)
	claims = &Claims{Username: username, RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: refreshExpiration}}
	refresh, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(authConfig.JwtKey)

	return token, refresh, refreshExpiration
}

func tokenError(err error, w http.ResponseWriter) {
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(ErrorResponse{
			Error:   "unspecified error",
			Message: "Unspecified error: nil",
		})
	} else if errors.Is(err, jwt.ErrTokenExpired) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(ErrorResponse{
			Error:   "token_expired",
			Message: "JWT token has expired",
		})
	} else if errors.Is(err, jwt.ErrTokenNotValidYet) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(ErrorResponse{
			Error:   "token_invalid",
			Message: "JWT token not already valid",
		})
	} else if errors.Is(err, jwt.ErrTokenMalformed) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(ErrorResponse{
			Error:   "token_malformed",
			Message: "JWT token has wrong format",
		})
	} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(ErrorResponse{
			Error:   "token_signature",
			Message: "JWT token has wrong signature",
		})
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(ErrorResponse{
			Error:   "unspecified error",
			Message: "Unspecified error: " + err.Error(),
		})
	}
}

func auditAccess(context context.Context, repo *internal.AuthRepository, userid int64, remoteAddr string, userAgent string, success bool, reason int) {
	if userid > 0 {
		repo.AddUserAudit(context, internal.AddUserAuditDTO{
			UserID:    userid,
			LoginDate: time.Now().UTC(),
			IPAddress: &remoteAddr,
			UserAgent: &userAgent,
			Success:   success,
			Reason:    reason,
		})
	}
}
