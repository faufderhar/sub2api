package admin

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type regenerateFingerprintRequest struct {
	Confirm            bool `json:"confirm"`
	ExpectedGeneration int  `json:"expected_generation"`
}

func (h *AccountHandler) attachFingerprintListFlags(ctx context.Context, accounts []service.Account, result []AccountWithConcurrency) {
	if h == nil || h.identityService == nil || len(accounts) == 0 {
		return
	}
	ids := make([]int64, 0, len(accounts))
	for i := range accounts {
		ids = append(ids, accounts[i].ID)
	}
	flags, err := h.identityService.ListFingerprintFlags(ctx, ids)
	if err != nil {
		return
	}
	for i := range result {
		if result[i].Account == nil {
			continue
		}
		flag := flags[result[i].Account.ID]
		result[i].Account.HasFingerprint = flag.HasFingerprint
		result[i].Account.FingerprintIsolated = flag.FingerprintIsolated
	}
}

// GetFingerprint GET /api/v1/admin/accounts/:id/fingerprint
func (h *AccountHandler) GetFingerprint(c *gin.Context) {
	account, ok := h.loadAccount(c)
	if !ok {
		return
	}
	if h.identityService == nil || !account.IsAnthropicOAuthOrSetupToken() {
		response.Success(c, h.identityService.BuildSummary(nil, account, h.passthroughEnabled(c), ""))
		return
	}
	fp, err := h.identityService.GetOrCreateForAccount(c.Request.Context(), account, nil)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, h.identityService.BuildSummary(fp, account, h.passthroughEnabled(c), h.tlsProfileName(fp)))
}

// RegenerateFingerprint POST /api/v1/admin/accounts/:id/fingerprint/regenerate
func (h *AccountHandler) RegenerateFingerprint(c *gin.Context) {
	accountID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid account ID")
		return
	}
	var req regenerateFingerprintRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.ErrorWithDetails(c, 400, "invalid request", "INVALID_REQUEST", nil)
		return
	}
	if !req.Confirm {
		response.ErrorWithDetails(c, 400, "请确认再生指纹（上游会视为设备变更）", "FINGERPRINT_CONFIRM_REQUIRED", nil)
		return
	}
	result, err := executeAdminIdempotent(
		c,
		"admin.accounts.fingerprint.regenerate",
		struct {
			AccountID          int64 `json:"account_id"`
			ExpectedGeneration int   `json:"expected_generation"`
		}{AccountID: accountID, ExpectedGeneration: req.ExpectedGeneration},
		service.DefaultWriteIdempotencyTTL(),
		func(ctx context.Context) (any, error) {
			account, execErr := h.adminService.GetAccount(ctx, accountID)
			if execErr != nil {
				return nil, execErr
			}
			if h.identityService == nil || !account.IsAnthropicOAuthOrSetupToken() {
				return nil, service.ErrFingerprintNotApplicable
			}
			fp, execErr := h.identityService.RegenerateFingerprint(ctx, account, req.ExpectedGeneration)
			if execErr != nil {
				return fp, execErr
			}
			return h.identityService.BuildSummary(fp, account, h.passthroughEnabled(c), h.tlsProfileName(fp)), nil
		},
	)
	if err != nil {
		if errors.Is(err, service.ErrFingerprintNotApplicable) {
			response.ErrorWithDetails(c, 409, "该账号没有持久 Claude Code 指纹", "FINGERPRINT_NOT_APPLICABLE", nil)
			return
		}
		if errors.Is(err, service.ErrFingerprintGeneration) {
			meta := map[string]string{}
			if result != nil {
				if fp, ok := result.Data.(*service.Fingerprint); ok && fp != nil {
					meta["current_generation"] = strconv.Itoa(fp.Generation)
				}
			}
			response.ErrorWithDetails(c, 409, "指纹已被更新，请刷新后重试", "FINGERPRINT_GENERATION_CONFLICT", meta)
			return
		}
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result.Data)
}

func (h *AccountHandler) loadAccount(c *gin.Context) (*service.Account, bool) {
	accountID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid account ID")
		return nil, false
	}
	account, err := h.adminService.GetAccount(c.Request.Context(), accountID)
	if err != nil {
		response.ErrorFrom(c, err)
		return nil, false
	}
	return account, true
}

func (h *AccountHandler) passthroughEnabled(c *gin.Context) bool {
	if h == nil || h.settingService == nil {
		return false
	}
	_, enableMPT, _ := h.settingService.GetGatewayForwardingSettings(c.Request.Context())
	return enableMPT
}

func (h *AccountHandler) tlsProfileName(fp *service.Fingerprint) string {
	if h == nil || h.tlsFPProfileService == nil || fp == nil || fp.TLSProfileID == 0 {
		return ""
	}
	if p := h.tlsFPProfileService.GetProfileByID(fp.TLSProfileID); p != nil {
		return p.Name
	}
	return fmt.Sprintf("profile-%d", fp.TLSProfileID)
}
