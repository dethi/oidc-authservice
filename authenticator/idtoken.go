package authenticator

import (
	"net/http"

	"github.com/arrikto/oidc-authservice/logger"
	"github.com/arrikto/oidc-authservice/oidc"
	"github.com/arrikto/oidc-authservice/svc"
)

type idTokenAuthenticator struct {
	header         string // header name where id token is stored
	userIDClaim    string // retrieve the userid if the claim exists
	groupsClaim    string
	sessionManager oidc.SessionManager
	tlsCfg         svc.TlsConfig
}

func NewIdTokenAuthenticator(
	header, userIDClaim, groupsClaim string,
	sm oidc.SessionManager,
	tlsCfg svc.TlsConfig) Authenticator {
	return &idTokenAuthenticator{
		header:         header,
		userIDClaim:    userIDClaim,
		groupsClaim:    groupsClaim,
		sessionManager: sm,
		tlsCfg:         tlsCfg,
	}
}

func (s *idTokenAuthenticator) Authenticate(w http.ResponseWriter, r *http.Request) (*User, error) {
	logger := logger.ForRequest(r)
	logger.Infof("Attempting idtoken authentication using token header '%s'", s.header)

	clientID := r.Header.Get("X-OIDC-Client-Id")

	// get id-token from header
	bearer := oidc.GetBearerToken(r.Header.Get(s.header))
	if len(bearer) == 0 {
		return nil, nil
	}

	ctx := s.tlsCfg.Context(r.Context())

	// Verifying received ID token
	token, err := s.sessionManager.Verify(ctx, bearer, clientID)
	if err != nil {
		logger.Errorf("id-token verification failed: %v", err)
		return nil, nil
	}

	claims, err := oidc.NewClaims(token, s.userIDClaim, s.groupsClaim)
	if err != nil {
		logger.Errorf("retrieving user claims failed: %v", err)
		return nil, nil
	}

	userID, err := claims.UserID()
	if err != nil {
		// this token doesn't have a userid claim (or the associated groups)
		// we return an empty user here because this is expected in the case
		// of client credentials flows
		logger.Info("USERID_CLAIM doesn't exist in the id token")
		return &User{}, nil
	}

	user := User{Name: userID, Groups: claims.Groups()}
	return &user, nil
}
