package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
)

const (
	FingerprintSourceCreated           = "created"
	FingerprintSourceMigratedRedis     = "migrated_redis"
	FingerprintSourceMigratedGenerated = "migrated_generated"
	FingerprintSourceRegenerated       = "regenerated"

	FingerprintTLSBindingAuto     = "auto"
	FingerprintTLSBindingExplicit = "explicit"

	fingerprintRandRetries = 8
)

var (
	// fingerprintRand is the CSPRNG used for seed/ClientID. Tests may replace it.
	fingerprintRand io.Reader = rand.Reader

	ErrFingerprintNotApplicable = errors.New("fingerprint not applicable")
	ErrFingerprintIsolated      = errors.New("fingerprint isolated")
	ErrFingerprintGeneration    = errors.New("fingerprint generation conflict")
	ErrFingerprintRNG           = errors.New("fingerprint rng failed")
	ErrFingerprintUnique        = errors.New("fingerprint unique constraint")
)

// FingerprintStore is the durable store for Claude Code fingerprints (DB).
type FingerprintStore interface {
	Get(ctx context.Context, accountID int64) (*Fingerprint, error)
	Insert(ctx context.Context, fp *Fingerprint) error
	Update(ctx context.Context, fp *Fingerprint) error
	CompareAndSwapGeneration(ctx context.Context, accountID int64, expected int, next *Fingerprint) (bool, error)
	ListByAccountIDs(ctx context.Context, ids []int64) (map[int64]*Fingerprint, error)
	ListConflictAccountIDs(ctx context.Context) ([]int64, error)
	FindActiveByClientID(ctx context.Context, clientID string) (*Fingerprint, error)
	FindActiveBySeed(ctx context.Context, seed string) (*Fingerprint, error)
}

// FingerprintUniqueError marks a seed or client_id collision on an active row.
type FingerprintUniqueError struct {
	Field string
}

func (e *FingerprintUniqueError) Error() string {
	return "fingerprint unique violation: " + e.Field
}

func (e *FingerprintUniqueError) Unwrap() error { return ErrFingerprintUnique }

func IsFingerprintUniqueViolation(err error) bool {
	return errors.Is(err, ErrFingerprintUnique)
}

type fingerprintTemplate struct {
	OS               string
	Arch             string
	Runtime          string
	RuntimeVersion   string
	StainlessOS      string
	StainlessArch    string
	StainlessRuntime string
}

// Four-entry device template pool (D2). Stainless wire values match current
// Claude Code / DefaultHeaders capitalization so outbound headers stay genuine;
// template OS identifiers are lowercase (macos/linux/windows).
var fingerprintTemplates = []fingerprintTemplate{
	{OS: "macos", Arch: "x64", Runtime: "node", RuntimeVersion: "v24.3.0", StainlessOS: "Mac", StainlessArch: "x64", StainlessRuntime: "node"},
	{OS: "linux", Arch: "x64", Runtime: "node", RuntimeVersion: "v24.3.0", StainlessOS: "Linux", StainlessArch: "x64", StainlessRuntime: "node"},
	{OS: "linux", Arch: "arm64", Runtime: "node", RuntimeVersion: "v24.3.0", StainlessOS: "Linux", StainlessArch: "arm64", StainlessRuntime: "node"},
	{OS: "windows", Arch: "x64", Runtime: "node", RuntimeVersion: "v24.3.0", StainlessOS: "Windows", StainlessArch: "x64", StainlessRuntime: "node"},
}

func pickFingerprintTemplate(seed string) fingerprintTemplate {
	sum := sha256.Sum256([]byte(seed))
	return fingerprintTemplates[int(sum[0])%len(fingerprintTemplates)]
}

func stickyIndex(seed string, n int) int {
	if n <= 0 {
		return 0
	}
	sum := sha256.Sum256([]byte("tls:" + seed))
	return int(binaryMod(sum[:], n))
}

func binaryMod(b []byte, n int) uint64 {
	var v uint64
	for i := 0; i < len(b) && i < 8; i++ {
		v = (v << 8) | uint64(b[i])
	}
	return v % uint64(n)
}

func generateFingerprintSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := io.ReadFull(fingerprintRand, buf); err != nil {
		return "", fmt.Errorf("%w: %v", ErrFingerprintRNG, err)
	}
	return hex.EncodeToString(buf), nil
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isValidLegacyFingerprint(fp *Fingerprint) bool {
	if fp == nil {
		return false
	}
	if !isHex64(fp.ClientID) {
		return false
	}
	if strings.TrimSpace(fp.StainlessOS) == "" || strings.TrimSpace(fp.StainlessArch) == "" {
		return false
	}
	return true
}

func builtUserAgent() string {
	return "claude-cli/" + claude.EffectiveCLIVersion() + " (external, cli)"
}

func applyVersionFloorToFingerprint(fp *Fingerprint) bool {
	if fp == nil {
		return false
	}
	changed := false
	if floored, ok := floorClaudeCLIUserAgentVersion(fp.UserAgent); ok {
		fp.UserAgent = floored
		changed = true
	}
	// Version-bound stainless package version stays at the built-in default
	// unless already set; we never copy a downstream client's package version.
	if fp.StainlessPackageVersion == "" {
		fp.StainlessPackageVersion = defaultFingerprint().StainlessPackageVersion
	}
	if fp.UserAgent == "" {
		fp.UserAgent = builtUserAgent()
		changed = true
	}
	return changed
}

func newGeneratedFingerprint(accountID int64, source string, tlsProfileID int64, tlsBinding string) (*Fingerprint, error) {
	seed, err := generateFingerprintSecret()
	if err != nil {
		return nil, err
	}
	clientID, err := generateFingerprintSecret()
	if err != nil {
		return nil, err
	}
	tpl := pickFingerprintTemplate(seed)
	now := time.Now().UTC()
	fp := &Fingerprint{
		AccountID:               accountID,
		Seed:                    seed,
		ClientID:                clientID,
		Generation:              1,
		Source:                  source,
		OS:                      tpl.OS,
		UserAgent:               builtUserAgent(),
		StainlessLang:           "js",
		StainlessPackageVersion: defaultFingerprint().StainlessPackageVersion,
		StainlessOS:             tpl.StainlessOS,
		StainlessArch:           tpl.StainlessArch,
		StainlessRuntime:        tpl.StainlessRuntime,
		StainlessRuntimeVersion: tpl.RuntimeVersion,
		TLSProfileID:            tlsProfileID,
		TLSBinding:              tlsBinding,
		UpdatedAt:               now.Unix(),
		UpdatedAtTime:           now,
	}
	if fp.TLSBinding == "" {
		fp.TLSBinding = FingerprintTLSBindingAuto
	}
	return fp, nil
}

func cloneFingerprint(fp *Fingerprint) *Fingerprint {
	if fp == nil {
		return nil
	}
	cp := *fp
	return &cp
}

// MemoryFingerprintStore is an in-process FingerprintStore for tests.
type MemoryFingerprintStore struct {
	mu        sync.Mutex
	byAccount map[int64]*Fingerprint
}

func NewMemoryFingerprintStore() *MemoryFingerprintStore {
	return &MemoryFingerprintStore{byAccount: map[int64]*Fingerprint{}}
}

func (s *MemoryFingerprintStore) Get(_ context.Context, accountID int64) (*Fingerprint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fp := s.byAccount[accountID]
	if fp == nil {
		return nil, nil
	}
	return cloneFingerprint(fp), nil
}

func (s *MemoryFingerprintStore) Insert(_ context.Context, fp *Fingerprint) error {
	if fp == nil {
		return errors.New("nil fingerprint")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.byAccount[fp.AccountID]; ok && existing != nil {
		return &FingerprintUniqueError{Field: "account_id"}
	}
	if !fp.Conflict {
		for _, other := range s.byAccount {
			if other.Conflict {
				continue
			}
			if other.ClientID == fp.ClientID {
				return &FingerprintUniqueError{Field: "client_id"}
			}
			if other.Seed == fp.Seed {
				return &FingerprintUniqueError{Field: "seed"}
			}
		}
	}
	s.byAccount[fp.AccountID] = cloneFingerprint(fp)
	return nil
}

func (s *MemoryFingerprintStore) Update(_ context.Context, fp *Fingerprint) error {
	if fp == nil {
		return errors.New("nil fingerprint")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byAccount[fp.AccountID] == nil {
		return errors.New("fingerprint not found")
	}
	s.byAccount[fp.AccountID] = cloneFingerprint(fp)
	return nil
}

func (s *MemoryFingerprintStore) CompareAndSwapGeneration(_ context.Context, accountID int64, expected int, next *Fingerprint) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.byAccount[accountID]
	if cur == nil || cur.Generation != expected {
		return false, nil
	}
	s.byAccount[accountID] = cloneFingerprint(next)
	return true, nil
}

func (s *MemoryFingerprintStore) ListByAccountIDs(_ context.Context, ids []int64) (map[int64]*Fingerprint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[int64]*Fingerprint, len(ids))
	for _, id := range ids {
		if fp := s.byAccount[id]; fp != nil {
			out[id] = cloneFingerprint(fp)
		}
	}
	return out, nil
}

func (s *MemoryFingerprintStore) ListConflictAccountIDs(_ context.Context) ([]int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []int64
	for id, fp := range s.byAccount {
		if fp != nil && fp.Conflict {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (s *MemoryFingerprintStore) FindActiveByClientID(_ context.Context, clientID string) (*Fingerprint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, fp := range s.byAccount {
		if fp != nil && !fp.Conflict && fp.ClientID == clientID {
			return cloneFingerprint(fp), nil
		}
	}
	return nil, nil
}

func (s *MemoryFingerprintStore) FindActiveBySeed(_ context.Context, seed string) (*Fingerprint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, fp := range s.byAccount {
		if fp != nil && !fp.Conflict && fp.Seed == seed {
			return cloneFingerprint(fp), nil
		}
	}
	return nil, nil
}

// FingerprintListFlags are the read-only list projections.
type FingerprintListFlags struct {
	HasFingerprint      bool
	FingerprintIsolated bool
}

// NewCreatedFingerprint builds a unique identity for a newly inserted account.
func NewCreatedFingerprint(account *Account) (*Fingerprint, error) {
	if account == nil {
		return nil, errors.New("nil account")
	}
	binding := FingerprintTLSBindingAuto
	tlsID := int64(0)
	if id := account.GetTLSFingerprintProfileID(); id > 0 {
		binding = FingerprintTLSBindingExplicit
		tlsID = id
	}
	return newGeneratedFingerprint(account.ID, FingerprintSourceCreated, tlsID, binding)
}

func sanitizeStoredFingerprintUA(fp *Fingerprint) bool {
	if fp == nil {
		return false
	}
	if !isAcceptableFingerprintUserAgent(fp.UserAgent) {
		fp.UserAgent = builtUserAgent()
		return true
	}
	return applyVersionFloorToFingerprint(fp)
}
