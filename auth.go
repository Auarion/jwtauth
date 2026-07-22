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
	Username string   `json:"username"`
	Userid   int64    `json:"userid"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

type AuthConfig struct {
	JwtKey               []byte
	TokenExpirationMin   int32
	RefreshExpirationMin int32
	DbConfig             DBConfig
	APIConfig            []APIConfig
	Authorize            bool
	TokenRoles           bool
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

type UserRoles struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
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

func LoginImpl(ctx context.Context, credentials AuthenticateUser, remoteAddress string, userAgent string) interface{} {

	repo := internal.DBRepository()
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

	t, refresh, refreshExpiration, err := generateTokens(repo, credentials.Username, userid)
	if err != nil {
		return ErrorResponse{
			Error:   "int_error",
			Message: "Token generation",
		}
	}

	// store token in DB
	err = repo.AddRefreshToken(ctx, internal.AddRefreshTokenDTO{
		UserID:    userid,
		Token:     refresh,
		ExpiresAt: refreshExpiration.Time,
	})
	if err != nil {
		return ErrorResponse{
			Error:   "int_error",
			Message: "Token storage",
		}
	}

	success = true

	return LoginResponse{
		Token:   t,
		Refresh: refresh,
	}
}

func RefreshImpl(ctx context.Context, token string, remoteAddress string, userAgent string) interface{} {

	repo := internal.DBRepository()
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
		userid = claims.Userid
		t, refresh, refreshExpiration, err := generateTokens(repo, username, userid)
		if err != nil {
			return ErrorResponse{
				Error:   "int_error",
				Message: "Token generation",
			}
		}

		// store token in DB
		err = repo.AddRefreshToken(ctx, internal.AddRefreshTokenDTO{
			UserID:    userid,
			Token:     refresh,
			ExpiresAt: refreshExpiration.Time,
		})
		if err != nil {
			return ErrorResponse{
				Error:   "int_error",
				Message: "Token storage",
			}
		}

		success = true

		return LoginResponse{
			Token:   t,
			Refresh: refresh,
		}
	}
}

type key string

var userKey key

type UserIdentification struct {
	Username string
	UserId   int64
}

func newContext(ctx context.Context, u *UserIdentification) context.Context {
	return context.WithValue(ctx, userKey, u)
}

func FromContext(ctx context.Context) (*UserIdentification, bool) {
	u, ok := ctx.Value(userKey).(*UserIdentification)
	return u, ok
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

			if authConfig.Authorize && apiConfig.AuthorizationRoles != nil && len(apiConfig.AuthorizationRoles) > 0 {

				username := claims.Username
				userid := claims.Userid

				var userroles []string

				if !authConfig.TokenRoles {
					// Read user roles from DB
					//
					repo := internal.DBRepository()

					userroles, err = repo.GetUserRoles(userid)
					if err != nil {
						emitError(w, http.StatusUnauthorized, "internal_error", "Get roles")
						return
					}
				} else {
					userroles = claims.Roles
				}

				commonRoles := intersection(userroles, apiConfig.AuthorizationRoles)

				if len(commonRoles) == 0 {
					emitError(w, http.StatusUnauthorized, "auth_authorization", "User not authorized")
					return
				}

				ctx := newContext(r.Context(), &UserIdentification{
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

func GetUserRoles(username string) (*UserRoles, error) {
	repo := internal.DBRepository()

	ret, err := repo.GetUserRolesByUsername(username)

	if err != nil {
		return nil, err
	}

	return &UserRoles{
		Username: username,
		Roles:    ret,
	}, nil
}

func GetRoles() ([]string, error) {
	repo := internal.DBRepository()

	ret, err := repo.GetRoles()

	if err != nil {
		return nil, err
	}

	return ret, nil
}

func GetCORSHandler(mux *http.ServeMux) http.Handler {
	return corsManager.Handler(mux)
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
			if authConfig.LogHandler != nil {
				handler = authConfig.LogHandler(handler).ServeHTTP
			} else {
				handler = loggingMiddleware(handler).ServeHTTP
			}
		}

		mux.HandleFunc(cfg.Method+" "+cfg.Path, handler)
	}
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

func generateTokens(repo *internal.AuthRepository, username string, userid int64) (string, string, *jwt.NumericDate, error) {

	var roles = make([]string, 0)
	var err error

	if authConfig.TokenRoles {
		roles, err = repo.GetUserRoles(userid)

		if err != nil {
			return "", "", nil, err
		}
	}

	var refreshExpiration *jwt.NumericDate = jwt.NewNumericDate(time.Now().Add(time.Duration(authConfig.RefreshExpirationMin) * time.Minute))

	exp := time.Now().Add(time.Duration(authConfig.TokenExpirationMin) * time.Minute)
	claims := &Claims{Username: username, Userid: userid, Roles: roles, RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(exp)}}
	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(authConfig.JwtKey)

	exp = time.Now().Add(time.Duration(authConfig.RefreshExpirationMin) * time.Minute)
	claims = &Claims{Username: username, Userid: userid, Roles: roles, RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: refreshExpiration}}
	refresh, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(authConfig.JwtKey)

	return token, refresh, refreshExpiration, nil
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
