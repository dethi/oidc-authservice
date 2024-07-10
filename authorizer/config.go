package authorizer

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/arrikto/oidc-authservice/common"
	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v3"
)

// AuthzConfig is the authorization schema, a yaml config based with fine-grained
// group authorization control.
type AuthzConfig struct {
	// DefaultRule defines the behavior when a host does not match any known rule.
	//
	// If no default rule is provided the default behavior is AllowAll.
	DefaultRule *HostRule `yaml:"default"`
	// Rules is a map from host name to HostRule which contain authorization
	// rules that apply to the host
	Rules map[string]HostRule `yaml:"rules"`
}

// HostRule describes authorization rules for requests that match a given host name.
//
// Membership is required for at least 1 group in the list.
type HostRule struct {
	Groups []string `yaml:"groups"`
}

// Matcher returns a set of groups to allow or deny.
func (h HostRule) Matcher() ruleMatcher {
	return newRuleMatcher(h.Groups)
}

type configAuthorizer struct {
	config       *AuthzConfig
	path         string
	groupMatcher map[string]ruleMatcher
	lock         sync.RWMutex
}

func watchLoop(watcher *fsnotify.Watcher, path string, do func() error) error {
	if err := watcher.Add(path); err != nil {
		return err
	}
	for {
		select {
		case ev, ok := <-watcher.Events:
			if !ok {
				return errors.New("watcher events channel closed")
			}

			log.Debugf("file watcher event: name=%s op=%s", ev.Name, ev.Op)

			// do nothing on Chmod
			if ev.Op == fsnotify.Chmod {
				continue
			}

			if ev.Op&fsnotify.Remove == fsnotify.Remove {
				return errors.New("watcher path removed")
			}

			log.Infof("try to reload %s", path)
			if err := do(); err != nil {
				return fmt.Errorf("failed to reload: %w", err)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return fmt.Errorf("watcher event errors channel closed")
			}
			return fmt.Errorf("watcher error: %w", err)
		}
	}

}

func NewConfigAuthorizer(path string) (Authorizer, error) {
	ca := configAuthorizer{}
	ca.path = path
	if err := ca.loadConfig(); err != nil {
		return nil, err
	}

	go func() {
		for i := 0; i < 5; i++ { // allow 5 failures before giving up

			// loadConfig() before attempting to create a watcher
			// We only want to do this on watcher reload (after an error),
			// and avoid doing this for the first iteration
			// since we have already run loadConfig() before we entered
			// this loop
			if i != 0 {
				log.Infof("configAuthorizer: try to reload %s", path)
				if err := ca.loadConfig(); err != nil {
					log.Errorf("configAuthorizer: failed to reload %q: %v", ca.path, err)
				}
			}
			watcher, err := fsnotify.NewWatcher()
			if err != nil {
				log.Errorf("couldn't create fsnotify watcher: %v", err)
			}
			if err = watchLoop(watcher, ca.path, ca.loadConfig); err != nil {
				log.Errorf("configAuthorizer: error watching %q: %v", ca.path, err)
			}
			watcher.Close()
			time.Sleep(1 * time.Second)
		}
		log.Fatal("configAuthorizer: watch loop failed, cannot continue")
	}()

	return &ca, nil
}

func (ca *configAuthorizer) loadConfig() error {
	authzConfig, err := ca.parseConfig(ca.path)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	// build groupMatcher map
	groupMatcher := make(map[string]ruleMatcher)
	for host, rule := range authzConfig.Rules {
		groupMatcher[host] = rule.Matcher()
	}

	defaultMatcher := newRuleMatcher([]string{"*"}) // allow all by default
	if authzConfig.DefaultRule != nil {
		defaultMatcher = authzConfig.DefaultRule.Matcher()
	}
	groupMatcher["*"] = defaultMatcher

	log.Infof("loaded AuthzConfig: %+v", *authzConfig)
	ca.lock.Lock()
	defer ca.lock.Unlock()
	ca.groupMatcher = groupMatcher
	ca.config = authzConfig
	return nil
}

func (ca *configAuthorizer) parse(raw []byte) (*AuthzConfig, error) {
	var c AuthzConfig
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	err := decoder.Decode(&c)
	// XXX io.EOF is returned for an empty file
	if err != nil {
		return nil, err
	}
	// XXX should add some validation here probably
	// return &c, c.Validate()
	return &c, nil
}

func (ca *configAuthorizer) parseConfig(path string) (*AuthzConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error loading AuthzConfig file %q: %v", path, err)
	}
	c, err := ca.parse(b)
	if err != nil {
		return nil, fmt.Errorf("errors while parsing AuthzConfig file %q: %v", path, err)
	}
	return c, nil
}

func formatReason(authed bool, user, host, matched, reason string) string {
	const f = "access %s: user=%s host=%s matched=%s reason=%q"
	if authed {
		return fmt.Sprintf(f, "granted", user, host, matched, reason)
	}
	return fmt.Sprintf(f, "denied", user, host, matched, reason)
}

func (ca *configAuthorizer) Authorize(r *http.Request, user *common.User) (bool, string, error) {
	host := r.Host
	hostPrefixes := hostWildcardPrefixes(host)

	var (
		hostMatcher ruleMatcher
		ok          bool
	)

	ca.lock.RLock()
	// Find the longest host matcher. First match is the one.
	for _, h := range hostPrefixes {
		if hostMatcher, ok = ca.groupMatcher[h]; ok {
			break
		}
	}
	ca.lock.RUnlock()

	if !ok {
		// WTF? This should never happen. But if it does, fail the authorize call.
		return false, "", fmt.Errorf("no matcher found for host=%s", host)
	}

	authed, reason := hostMatcher.Match(user)
	reason = formatReason(authed, user.Name, host, host, reason)
	log.Infof("authorization: %v", reason)
	return authed, reason, nil
}

func hostWildcardPrefixes(host string) []string {
	hostPart := strings.Split(host, ".")
	prefixes := make([]string, 0, len(hostPart)+2)
	// The actual host
	prefixes = append(prefixes, host)
	// Followed by all the wildcard parent hosts
	for i := 1; i < len(hostPart); i++ {
		prefixes = append(prefixes, "*."+strings.Join(hostPart[i:], "."))
	}
	// And finally the root wildcard (i.e. default)
	prefixes = append(prefixes, "*")
	return prefixes
}
