package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

type memFPCache struct {
	mu       sync.Mutex
	fps      map[int64]*Fingerprint
	sessions map[int64]string
}

func newMemFPCache() *memFPCache {
	return &memFPCache{fps: map[int64]*Fingerprint{}, sessions: map[int64]string{}}
}

func (c *memFPCache) GetFingerprint(_ context.Context, accountID int64) (*Fingerprint, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fp, ok := c.fps[accountID]
	if !ok || fp == nil {
		return nil, fmt.Errorf("not found")
	}
	clone := *fp
	return &clone, nil
}

func (c *memFPCache) SetFingerprint(_ context.Context, accountID int64, fp *Fingerprint) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	clone := *fp
	c.fps[accountID] = &clone
	return nil
}

func (c *memFPCache) DeleteFingerprint(_ context.Context, accountID int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.fps, accountID)
	return nil
}

func (c *memFPCache) GetMaskedSessionID(_ context.Context, accountID int64) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessions[accountID], nil
}

func (c *memFPCache) SetMaskedSessionID(_ context.Context, accountID int64, sessionID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessions[accountID] = sessionID
	return nil
}

func (c *memFPCache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fps = map[int64]*Fingerprint{}
	c.sessions = map[int64]string{}
}

type capturedUpstream struct {
	AccountID int64
	Path      string
	UA        string
	OS        string
	Arch      string
	Lang      string
	Pkg       string
	Runtime   string
	RuntimeV  string
	DeviceID  string
	AccUUID   string
	SessID    string
	UserID    string
}

func parseCaptured(accountID int64, path string, req *http.Request, body []byte) capturedUpstream {
	uid := gjson.GetBytes(body, "metadata.user_id").String()
	parsed := ParseMetadataUserID(uid)
	out := capturedUpstream{
		AccountID: accountID,
		Path:      path,
		UA:        req.Header.Get("User-Agent"),
		OS:        headerAny(req, "X-Stainless-OS"),
		Arch:      headerAny(req, "X-Stainless-Arch"),
		Lang:      headerAny(req, "X-Stainless-Lang"),
		Pkg:       headerAny(req, "X-Stainless-Package-Version"),
		Runtime:   headerAny(req, "X-Stainless-Runtime"),
		RuntimeV:  headerAny(req, "X-Stainless-Runtime-Version"),
		UserID:    uid,
	}
	if parsed != nil {
		out.DeviceID = parsed.DeviceID
		out.AccUUID = parsed.AccountUUID
		out.SessID = parsed.SessionID
	}
	return out
}

func headerAny(req *http.Request, key string) string {
	if v := req.Header.Get(key); v != "" {
		return v
	}
	for k, vs := range req.Header {
		if strings.EqualFold(k, key) && len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}

func clientHeaders(ua, os, arch, runtimeV string) http.Header {
	h := make(http.Header)
	if ua != "" {
		h.Set("User-Agent", ua)
	}
	if os != "" {
		h.Set("X-Stainless-OS", os)
	}
	if arch != "" {
		h.Set("X-Stainless-Arch", arch)
	}
	h.Set("X-Stainless-Lang", "js")
	h.Set("X-Stainless-Package-Version", "0.94.0")
	h.Set("X-Stainless-Runtime", "node")
	if runtimeV != "" {
		h.Set("X-Stainless-Runtime-Version", runtimeV)
	}
	h.Set("x-app", "cli")
	return h
}

func sampleLegacyUserID(deviceHex, session string) string {
	return FormatMetadataUserID(deviceHex, "", session, "2.0.0")
}

func messagesBody(withBilling bool, userID string) []byte {
	sys := `"You are helpful"`
	if withBilling {
		sys = `[{"type":"text","text":"x-anthropic-billing-header cc_version=2.1.258 cc_entrypoint=cli"}]`
	}
	return []byte(fmt.Sprintf(`{
		"model":"claude-sonnet-4-5-20250929",
		"max_tokens":16,
		"messages":[{"role":"user","content":"hello fingerprint audit"}],
		"metadata":{"user_id":%q},
		"system":%s
	}`, userID, sys))
}

func newAuditGinCtx(raw []byte, headers http.Header) *gin.Context {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(raw))
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	c.Request = req
	return c
}

func oauthAccount(id int64, uuid string) *Account {
	return &Account{
		ID:        id,
		Name:      fmt.Sprintf("acc-%d", id),
		Platform:  PlatformAnthropic,
		Type:      AccountTypeOAuth,
		CreatedAt: time.Unix(id, 0).UTC(),
		Extra:     map[string]any{"account_uuid": uuid},
	}
}

func newHarnessIdentity() (*IdentityService, *MemoryFingerprintStore, *memFPCache) {
	store := NewMemoryFingerprintStore()
	cache := newMemFPCache()
	ident := NewIdentityService(cache)
	ident.SetStore(store)
	return ident, store, cache
}

func seedAccount(t *testing.T, ident *IdentityService, acc *Account) *Fingerprint {
	t.Helper()
	fp, err := ident.PersistNewFingerprint(context.Background(), acc)
	if err != nil {
		t.Fatalf("persist fingerprint %d: %v", acc.ID, err)
	}
	return fp
}

func identityProjection(fp *Fingerprint) (ua, os, arch, runtime, runtimeV, clientID string) {
	return fp.UserAgent, fp.StainlessOS, fp.StainlessArch, fp.StainlessRuntime, fp.StainlessRuntimeVersion, fp.ClientID
}

func captureMessages(t *testing.T, svc *GatewayService, account *Account, headers http.Header, body []byte, stream, mimic bool) capturedUpstream {
	t.Helper()
	c := newAuditGinCtx(body, headers)
	req, outBody, err := svc.buildUpstreamRequest(context.Background(), c, account, body, "test-oauth-token", "oauth", "claude-sonnet-4-5-20250929", stream, mimic)
	if err != nil {
		t.Fatalf("buildUpstreamRequest account=%d mimic=%v: %v", account.ID, mimic, err)
	}
	got, _ := io.ReadAll(req.Body)
	if len(outBody) > 0 {
		got = outBody
	}
	return parseCaptured(account.ID, "/v1/messages", req, got)
}

func captureCountTokens(t *testing.T, svc *GatewayService, account *Account, headers http.Header, body []byte, mimic bool) capturedUpstream {
	t.Helper()
	c := newAuditGinCtx(body, headers)
	req, outBody, err := svc.buildCountTokensRequest(context.Background(), c, account, body, "test-oauth-token", "oauth", "claude-sonnet-4-5-20250929", mimic)
	if err != nil {
		t.Fatalf("buildCountTokensRequest account=%d mimic=%v: %v", account.ID, mimic, err)
	}
	got, _ := io.ReadAll(req.Body)
	if len(outBody) > 0 {
		got = outBody
	}
	return parseCaptured(account.ID, "/v1/messages/count_tokens", req, got)
}

func assertMatchesFingerprint(t *testing.T, row capturedUpstream, fp *Fingerprint) {
	t.Helper()
	if row.UA != fp.UserAgent {
		t.Errorf("account %d path %s UA mismatch: got %q want %q", row.AccountID, row.Path, row.UA, fp.UserAgent)
	}
	if row.OS != fp.StainlessOS || row.Arch != fp.StainlessArch || row.Runtime != fp.StainlessRuntime || row.RuntimeV != fp.StainlessRuntimeVersion {
		t.Errorf("account %d path %s stainless mismatch: os/arch/runtime=%s/%s/%s/%s want %s/%s/%s/%s",
			row.AccountID, row.Path, row.OS, row.Arch, row.Runtime, row.RuntimeV,
			fp.StainlessOS, fp.StainlessArch, fp.StainlessRuntime, fp.StainlessRuntimeVersion)
	}
	if row.DeviceID != "" && row.DeviceID != fp.ClientID {
		t.Errorf("account %d path %s device_id=%s want %s", row.AccountID, row.Path, row.DeviceID, fp.ClientID)
	}
}

func TestAudit3FP_Matrix(t *testing.T) {
	ident, _, _ := newHarnessIdentity()
	svc := &GatewayService{identityService: ident}

	type accSpec struct {
		id   int64
		uuid string
		hdr  http.Header
	}
	accounts := []accSpec{
		{101, "11111111-1111-4111-8111-111111111111", clientHeaders("claude-cli/2.1.200 (external, cli)", "Mac", "x64", "v22.17.0")},
		{102, "22222222-2222-4222-8222-222222222222", clientHeaders("claude-cli/2.1.210 (external, cli)", "Windows", "x64", "v22.14.0")},
		{103, "33333333-3333-4333-8333-333333333333", clientHeaders("", "", "", "")},
	}

	stored := map[int64]*Fingerprint{}
	for _, a := range accounts {
		stored[a.id] = seedAccount(t, ident, oauthAccount(a.id, a.uuid))
	}

	deviceHex := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sessionA := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	baseUID := sampleLegacyUserID(deviceHex, sessionA)

	var rows []capturedUpstream
	record := func(c capturedUpstream) { rows = append(rows, c) }

	for _, a := range accounts {
		acc := oauthAccount(a.id, a.uuid)
		body := messagesBody(false, baseUID)
		record(captureMessages(t, svc, acc, a.hdr, body, false, true))
		record(captureMessages(t, svc, acc, a.hdr, body, true, true))
		record(captureMessages(t, svc, acc, a.hdr, messagesBody(true, baseUID), false, false))
		record(captureCountTokens(t, svc, acc, a.hdr, messagesBody(false, baseUID), true))
		record(captureCountTokens(t, svc, acc, a.hdr, messagesBody(true, baseUID), false))
		record(captureMessages(t, svc, acc, a.hdr, messagesBody(true, baseUID), false, false))
	}

	newer := clientHeaders("claude-cli/2.1.250 (external, cli)", "Linux", "arm64", "v24.3.0")
	record(captureMessages(t, svc, oauthAccount(101, accounts[0].uuid), newer, messagesBody(true, baseUID), false, false))

	failover101 := captureMessages(t, svc, oauthAccount(101, accounts[0].uuid), accounts[0].hdr, messagesBody(true, baseUID), false, false)
	failover102 := captureMessages(t, svc, oauthAccount(102, accounts[1].uuid), accounts[1].hdr, messagesBody(true, baseUID), false, false)
	record(failover101)
	record(failover102)

	for _, row := range rows {
		assertMatchesFingerprint(t, row, stored[row.AccountID])
	}

	if stored[101].ClientID == stored[102].ClientID || stored[101].ClientID == stored[103].ClientID || stored[102].ClientID == stored[103].ClientID {
		t.Fatalf("accounts shared ClientID: %s %s %s", stored[101].ClientID, stored[102].ClientID, stored[103].ClientID)
	}

	if failover101.AccUUID == failover102.AccUUID {
		t.Errorf("FAILOVER leak account_uuid %s", failover101.AccUUID)
	}
	if failover101.DeviceID == failover102.DeviceID {
		t.Errorf("FAILOVER leak device_id %s", failover101.DeviceID)
	}
	if failover101.SessID == failover102.SessID {
		t.Errorf("FAILOVER leak session_id %s", failover101.SessID)
	}

	// Test-connection payload for the same account must reuse the persisted ClientID.
	sess, err := generateSessionStringFromFingerprint(stored[101])
	if err != nil {
		t.Fatal(err)
	}
	parsed := ParseMetadataUserID(sess)
	if parsed == nil || parsed.DeviceID != stored[101].ClientID {
		t.Errorf("TEST_CONN device_id %v want %s", parsed, stored[101].ClientID)
	}
}

func TestAudit3FP_ConcurrentFirstRequestRace(t *testing.T) {
	ident, store, _ := newHarnessIdentity()
	acc := oauthAccount(777, "77777777-7777-4777-8777-777777777777")
	const n = 100
	ids := make([]string, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			fp, err := ident.GetOrCreateForAccount(context.Background(), acc, nil)
			if err != nil {
				t.Errorf("GetOrCreate: %v", err)
				return
			}
			ids[i] = fp.ClientID
		}(i)
	}
	wg.Wait()
	uniq := map[string]int{}
	for _, id := range ids {
		if id != "" {
			uniq[id]++
		}
	}
	if len(uniq) != 1 {
		t.Fatalf("concurrent first create produced %d identities: %+v", len(uniq), uniq)
	}
	stored, err := store.Get(context.Background(), acc.ID)
	if err != nil || stored == nil {
		t.Fatalf("store missing: %v", err)
	}
	for id := range uniq {
		if id != stored.ClientID {
			t.Fatalf("in-flight id %s != stored %s", id, stored.ClientID)
		}
	}
}

func TestAudit3FP_RedisFlushKeepsIdentity(t *testing.T) {
	ident, _, cache := newHarnessIdentity()
	acc := oauthAccount(5, "55555555-5555-4555-8555-555555555555")
	fp1 := seedAccount(t, ident, acc)
	cache.Flush()
	fp2, err := ident.GetOrCreateForAccount(context.Background(), acc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fp1.ClientID != fp2.ClientID || fp1.Seed != fp2.Seed {
		t.Fatalf("identity changed after cache flush: %s -> %s", fp1.ClientID, fp2.ClientID)
	}
}

func TestAudit3FP_ClientHeadersDoNotOverrideTemplate(t *testing.T) {
	ident, _, _ := newHarnessIdentity()
	acc := oauthAccount(9, "99999999-9999-4999-8999-999999999999")
	fp1 := seedAccount(t, ident, acc)
	win := clientHeaders("claude-cli/9.9.9 (external, cli)", "Windows", "x64", "v20.11.0")
	fp2, err := ident.GetOrCreateForAccount(context.Background(), acc, win)
	if err != nil {
		t.Fatal(err)
	}
	if fp2.ClientID != fp1.ClientID || fp2.StainlessOS != fp1.StainlessOS || fp2.StainlessArch != fp1.StainlessArch {
		t.Fatalf("client headers mutated locked identity: %+v vs %+v", fp1, fp2)
	}
}

func TestAudit3FP_EmptyHeadersStillUnique(t *testing.T) {
	ident, _, _ := newHarnessIdentity()
	a := seedAccount(t, ident, oauthAccount(21, ""))
	b := seedAccount(t, ident, oauthAccount(22, ""))
	if a.ClientID == b.ClientID || a.Seed == b.Seed {
		t.Fatalf("empty-header accounts shared identifiers")
	}
}

func TestAudit3FP_ThousandAccountsUnique(t *testing.T) {
	ident, _, _ := newHarnessIdentity()
	seenID := map[string]int64{}
	seenSeed := map[string]int64{}
	for i := int64(1); i <= 1000; i++ {
		fp := seedAccount(t, ident, oauthAccount(10000+i, ""))
		if other, ok := seenID[fp.ClientID]; ok {
			t.Fatalf("client_id collision %d and %d", other, fp.AccountID)
		}
		if other, ok := seenSeed[fp.Seed]; ok {
			t.Fatalf("seed collision %d and %d", other, fp.AccountID)
		}
		seenID[fp.ClientID] = fp.AccountID
		seenSeed[fp.Seed] = fp.AccountID
	}
}

func TestAudit3FP_RNGFailureDoesNotWrite(t *testing.T) {
	ident, store, _ := newHarnessIdentity()
	orig := fingerprintRand
	fingerprintRand = bytes.NewReader(nil)
	defer func() { fingerprintRand = orig }()
	_, err := ident.PersistNewFingerprint(context.Background(), oauthAccount(42, ""))
	if err == nil {
		t.Fatal("expected rng failure")
	}
	got, _ := store.Get(context.Background(), 42)
	if got != nil {
		t.Fatalf("partial fingerprint written after rng failure")
	}
}

func TestAudit3FP_RegenerateOnlyTouchesOneAccount(t *testing.T) {
	ident, _, cache := newHarnessIdentity()
	a := oauthAccount(31, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	b := oauthAccount(32, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	fpA := seedAccount(t, ident, a)
	fpB := seedAccount(t, ident, b)
	next, err := ident.RegenerateFingerprint(context.Background(), a, fpA.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if next.ClientID == fpA.ClientID || next.Generation != fpA.Generation+1 {
		t.Fatalf("regenerate did not advance identity: %+v", next)
	}
	stillB, err := ident.GetOrCreateForAccount(context.Background(), b, nil)
	if err != nil {
		t.Fatal(err)
	}
	if stillB.ClientID != fpB.ClientID {
		t.Fatalf("other account changed")
	}
	cache.Flush()
	afterFlush, err := ident.GetOrCreateForAccount(context.Background(), a, nil)
	if err != nil {
		t.Fatal(err)
	}
	if afterFlush.ClientID != next.ClientID {
		t.Fatalf("old cache resurrected identity")
	}
}

func TestAudit3FP_LocalTLSHelloStable(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fp-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var hellos []string
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			hellos = append(hellos, fmt.Sprintf("%v|%v|%v", chi.CipherSuites, chi.SupportedCurves, chi.SupportedProtos))
			mu.Unlock()
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 1)
			_, _ = conn.Read(buf)
			_ = conn.Close()
		}
	}()

	dial := func() {
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, ServerName: "fp-test"})
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		_ = conn.Close()
	}
	dial()
	dial()
	mu.Lock()
	defer mu.Unlock()
	if len(hellos) < 2 {
		t.Fatalf("expected ClientHello captures, got %d", len(hellos))
	}
	if hellos[0] != hellos[1] {
		t.Fatalf("ClientHello not stable under same client config: %q vs %q", hellos[0], hellos[1])
	}
	t.Logf("TLS ClientHello stable (cipher/curve/alpn) under identical transport policy; this is not a per-account JA3 claim")
}

func TestAudit3FP_JSONReportHelper(t *testing.T) {
	report := map[string]any{
		"harness": "zz_audit3_fingerprint_harness_test.go",
		"rerun":   "cd /workspace/sub2api-be3/backend && go test -tags=unit -count=1 -timeout 180s -run 'TestAudit3FP' ./internal/service/",
	}
	b, _ := json.Marshal(report)
	t.Logf("HARNESS_META %s", b)
}

func TestAudit3FP_OAuthRefreshNotCLIPath(t *testing.T) {
	// D9: OAuth token refresh stays on axios/Chrome and is not part of the CLI identity matrix.
	t.Log("OAuth refresh is explicitly excluded from CLI fingerprint consistency (D9)")
}
