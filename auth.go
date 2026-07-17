package jwtauth

import (
	"context"
	"encoding/json"
	"errors"
	"log"

	"net/http"
	"time"

	"github.com/Auarion/jwtauth/internal"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
)

type APIConfig struct {
	Path               string
	Method             string
	Handler            func(w http.ResponseWriter, r *http.Request)
	AuthorizationRoles []string
}

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
	APIConfig            []APIConfig
	Authorize            bool
	LogHandler           func(http.Handler) http.Handler
}

type DBConfig struct {
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

var authConfig AuthConfig
var apisMap map[string]APIConfig = make(map[string]APIConfig)
var corsManager *cors.Cors

func SetAuthConfig(cfg AuthConfig, cOpts cors.Options) {
	authConfig = cfg
	internal.SetDBConfig(internal.Config(cfg.DbConfig))

	for _, apiCfg := range authConfig.APIConfig {
		apisMap[apiCfg.Path] = apiCfg
	}

	corsManager = cors.New(cOpts)

	if authConfig.LogHandler == nil {
		authConfig.LogHandler = loggingMiddleware
	}
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
		emitError(w, http.StatusUnauthorized, "auth_error", "Authentication error")
		return
	}

	err = bcrypt.CompareHashAndPassword(
		[]byte(hashedPassword),
		[]byte(credentials.Password),
	)

	if err != nil {
		emitError(w, http.StatusUnauthorized, "auth_error", "Authentication error")
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

func LoginImpl(ctx context.Context, credentials AuthenticateUser, remoteAddress string, userAgent string) interface{} {

	repo := internal.Repository()
	success := false
	var userid int64
	var err error
	var hashedPassword string

	// audit the access at the end of the function
	defer func() {
		auditAccess(ctx, repo, userid, remoteAddress, userAgent, success, 0)
	}()

	hashedPassword, userid, err = repo.AuthenticateUser(ctx, internal.AuthenticateUserDTO{
		Username: credentials.Username,
		Password: credentials.Password,
	})

	if err != nil || hashedPassword == "" {
		return ErrorResponse{
			Error:   "auth_error",
			Message: "Authentication error",
		}
	}

	err = bcrypt.CompareHashAndPassword(
		[]byte(hashedPassword),
		[]byte(credentials.Password),
	)

	if err != nil {
		return ErrorResponse{
			Error:   "auth_error",
			Message: "Authentication error",
		}
	}

	t, refresh, refreshExpiration := generateTokens(credentials.Username)

	// store token in DB
	err = repo.AddRefreshToken(ctx, internal.AddRefreshTokenDTO{
		UserID:    userid,
		Token:     refresh,
		ExpiresAt: refreshExpiration.Time,
	})

	success = true

	return LoginResponse{
		Token:   t,
		Refresh: refresh,
	}
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
		emitError(w, http.StatusUnauthorized, "token_format", "Invalid token format")
		return
	}

	claims := &Claims{}

	jwttoken, err := jwt.ParseWithClaims(token[7:], claims, func(t *jwt.Token) (interface{}, error) { return authConfig.JwtKey, nil })

	if !jwttoken.Valid {
		tokenError(err, w)
	} else {
		username := claims.Username
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

func RefreshImpl(ctx context.Context, token string, remoteAddress string, userAgent string) interface{} {

	repo := internal.Repository()
	var userid int64
	success := false

	// audit the access at the end of the function
	defer func() {
		auditAccess(ctx, repo, userid, remoteAddress, userAgent, success, 1)
	}()

	if len(token) < 8 {
		return ErrorResponse{
			Error:   "token_format",
			Message: "Invalid token format",
		}
	}

	claims := &Claims{}

	jwttoken, err := jwt.ParseWithClaims(token[7:], claims, func(t *jwt.Token) (interface{}, error) { return authConfig.JwtKey, nil })

	if !jwttoken.Valid {
		return tokenErrorMsg(err)
	} else {
		username := claims.Username
		t, refresh, refreshExpiration := generateTokens(username)

		userid, _ := repo.UserMap(ctx, internal.UserMapDTO{
			Username: username,
		})

		// store token in DB
		err = repo.AddRefreshToken(ctx, internal.AddRefreshTokenDTO{
			UserID:    userid,
			Token:     refresh,
			ExpiresAt: refreshExpiration.Time,
		})

		success = true

		return LoginResponse{
			Token:   t,
			Refresh: refresh,
		}
	}
}

const UserID = "UserID"

type UserIdentification struct {
	Username string
	UserId   int64
}

// Authentication handler generation
func Auth(apiConfig APIConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if len(token) < 8 {
			emitError(w, http.StatusUnauthorized, "token_format", "Invalid token format")
			return
		}

		claims := &Claims{}

		jwttoken, err := jwt.ParseWithClaims(token[7:], claims, func(t *jwt.Token) (interface{}, error) { return authConfig.JwtKey, nil })

		if !jwttoken.Valid {
			tokenError(err, w)
		} else {

			if authConfig.Authorize {

				repo := internal.Repository()
				username := claims.Username
				userid, err := repo.UserMap(r.Context(), internal.UserMapDTO{
					Username: username,
				})
				if err != nil {
					emitError(w, http.StatusUnauthorized, "internal_error", "Username")
					return
				}

				userroles, err := repo.GetUserRoles(userid)
				if err != nil {
					emitError(w, http.StatusUnauthorized, "internal_error", "Get roles")
					return
				}

				commonRoles := intersection(userroles, apiConfig.AuthorizationRoles)

				if len(commonRoles) == 0 {
					emitError(w, http.StatusUnauthorized, "auth_authorization", "User not authorized")
					return
				}

				ctx := context.WithValue(r.Context(), UserID, UserIdentification{
					Username: username,
					UserId:   userid,
				})

				apiConfig.Handler(w, r.WithContext(ctx))
			} else {
				apiConfig.Handler(w, r)
			}
		}
	}
}

func GetCORSHandler(mux *http.ServeMux) http.Handler {
	return corsManager.Handler(mux)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		log.Printf(
			"method=%s path=%s remote=%s user-agent=%q",
			r.Method,
			r.URL.Path,
			r.RemoteAddr,
			r.UserAgent(),
		)

		keys := make([]string, 0, len(r.Header))

		for k := range r.Header {
			keys = append(keys, k)
		}

		for _, k := range keys {
			var msg = "  " + k + "="
			for _, v := range r.Header[k] {
				msg = msg + v + " "
			}
			log.Println(msg)
		}

		next.ServeHTTP(w, r)

		log.Printf(
			"completed path=%s duration=%s",
			r.URL.Path,
			time.Since(start),
		)
	})
}

func RegisterAPIsRoutes(mux *http.ServeMux, apisList []APIConfig, enableLog bool) {

	for _, cfg := range apisList {
		var handler http.HandlerFunc

		if len(cfg.AuthorizationRoles) > 0 {
			handler = Auth(cfg)
		} else {
			handler = cfg.Handler
		}

		if enableLog {
			handler = loggingMiddleware(handler).ServeHTTP
		}

		mux.HandleFunc(cfg.Method+" "+cfg.Path, handler)
	}
}

func intersection(a, b []string) []string {
	set := make(map[string]struct{})

	for _, s := range a {
		set[s] = struct{}{}
	}

	result := make([]string, 0)

	for _, s := range b {
		if _, found := set[s]; found {
			result = append(result, s)
		}
	}

	return result
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
	var errmsg, msg string

	if err == nil {
		errmsg = "unspecified error"
		msg = "Unspecified error: nil"
	} else if errors.Is(err, jwt.ErrTokenExpired) {
		errmsg = "token_expired"
		msg = "JWT token has expired"
	} else if errors.Is(err, jwt.ErrTokenNotValidYet) {
		errmsg = "token_invalid"
		msg = "JWT token not already valid"
	} else if errors.Is(err, jwt.ErrTokenMalformed) {
		errmsg = "token_malformed"
		msg = "JWT token has wrong format"
	} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		errmsg = "token_signature"
		msg = "JWT token has wrong signature"
	} else {
		errmsg = "unspecified error"
		msg = "Unspecified error: " + err.Error()
	}

	emitError(w, http.StatusUnauthorized, errmsg, msg)
}

func tokenErrorMsg(err error) ErrorResponse {
	var errmsg, msg string

	if err == nil {
		errmsg = "unspecified error"
		msg = "Unspecified error: nil"
	} else if errors.Is(err, jwt.ErrTokenExpired) {
		errmsg = "token_expired"
		msg = "JWT token has expired"
	} else if errors.Is(err, jwt.ErrTokenNotValidYet) {
		errmsg = "token_invalid"
		msg = "JWT token not already valid"
	} else if errors.Is(err, jwt.ErrTokenMalformed) {
		errmsg = "token_malformed"
		msg = "JWT token has wrong format"
	} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		errmsg = "token_signature"
		msg = "JWT token has wrong signature"
	} else {
		errmsg = "unspecified error"
		msg = "Unspecified error: " + err.Error()
	}

	return ErrorResponse{
		Error:   errmsg,
		Message: msg,
	}
}

func emitError(w http.ResponseWriter, status int, errormsg string, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	json.NewEncoder(w).Encode(ErrorResponse{
		Error:   errormsg,
		Message: message,
	})
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
