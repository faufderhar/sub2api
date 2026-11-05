package admin

import (
	"context"
	"sort"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// M-7：PUT /api/v1/admin/settings 中的支付配置只有在「实际变更」时才要求 step-up。
// 常规保存（前端会把 GET 回来的支付字段原样回传）不得触发 STEP_UP_REQUIRED。
//
// 比较基准：
//   - payment_* 字段 → PaymentConfigService.GetPaymentConfig（与 GET /admin/settings 返回同源）
//   - payment_visible_method_* 字段 → previousSettings（同为 GET 的数据源）
//
// 读取当前支付配置失败时按「已变更」处理（fail-closed），即要求 step-up。
func (h *SettingHandler) paymentSettingsChanged(ctx context.Context, req UpdateSettingsRequest, previous *service.SystemSettings) bool {
	if visibleMethodSettingsChanged(req, previous) {
		return true
	}
	if h.paymentConfigService == nil || !hasPaymentFields(req) {
		// 未注入支付服务时 payment_* 字段不会被写入，无需门控。
		return false
	}
	current, err := h.paymentConfigService.GetPaymentConfig(ctx)
	if err != nil || current == nil {
		return true
	}
	return paymentConfigFieldsChanged(req, current)
}

func visibleMethodSettingsChanged(req UpdateSettingsRequest, previous *service.SystemSettings) bool {
	if previous == nil {
		return req.PaymentVisibleMethodAlipaySource != nil || req.PaymentVisibleMethodWxpaySource != nil ||
			req.PaymentVisibleMethodAlipayEnabled != nil || req.PaymentVisibleMethodWxpayEnabled != nil
	}
	if req.PaymentVisibleMethodAlipaySource != nil &&
		service.NormalizeVisibleMethodSource("alipay", *req.PaymentVisibleMethodAlipaySource) !=
			service.NormalizeVisibleMethodSource("alipay", previous.PaymentVisibleMethodAlipaySource) {
		return true
	}
	if req.PaymentVisibleMethodWxpaySource != nil &&
		service.NormalizeVisibleMethodSource("wxpay", *req.PaymentVisibleMethodWxpaySource) !=
			service.NormalizeVisibleMethodSource("wxpay", previous.PaymentVisibleMethodWxpaySource) {
		return true
	}
	if boolChanged(req.PaymentVisibleMethodAlipayEnabled, previous.PaymentVisibleMethodAlipayEnabled) ||
		boolChanged(req.PaymentVisibleMethodWxpayEnabled, previous.PaymentVisibleMethodWxpayEnabled) {
		return true
	}
	return false
}

func paymentConfigFieldsChanged(req UpdateSettingsRequest, cur *service.PaymentConfig) bool {
	switch {
	case boolChanged(req.PaymentEnabled, cur.Enabled),
		floatChanged(req.PaymentMinAmount, cur.MinAmount),
		floatChanged(req.PaymentMaxAmount, cur.MaxAmount),
		floatChanged(req.PaymentDailyLimit, cur.DailyLimit),
		intChanged(req.PaymentOrderTimeoutMin, cur.OrderTimeoutMin),
		intChanged(req.PaymentMaxPendingOrders, cur.MaxPendingOrders),
		req.PaymentEnabledTypes != nil && !sameStringSet(req.PaymentEnabledTypes, cur.EnabledTypes),
		boolChanged(req.PaymentBalanceDisabled, cur.BalanceDisabled),
		floatChanged(req.PaymentBalanceRechargeMultiplier, cur.BalanceRechargeMultiplier),
		floatChanged(req.PaymentSubscriptionUSDToCNYRate, cur.SubscriptionUSDToCNYRate),
		floatChanged(req.PaymentRechargeFeeRate, cur.RechargeFeeRate),
		req.PaymentRechargeBonusTiers != nil && !sameBonusTiers(rechargeBonusTiersFromDTO(req.PaymentRechargeBonusTiers), cur.RechargeBonusTiers),
		req.PaymentRechargeBonusMode != nil && rechargeBonusModeToDTO(*req.PaymentRechargeBonusMode) != rechargeBonusModeToDTO(cur.RechargeBonusMode),
		trimmedStringChanged(req.PaymentRechargeBonusNotice, cur.RechargeBonusNotice),
		trimmedStringChanged(req.PaymentLoadBalanceStrat, cur.LoadBalanceStrategy),
		trimmedStringChanged(req.PaymentProductNamePrefix, cur.ProductNamePrefix),
		trimmedStringChanged(req.PaymentProductNameSuffix, cur.ProductNameSuffix),
		trimmedStringChanged(req.PaymentHelpImageURL, cur.HelpImageURL),
		trimmedStringChanged(req.PaymentHelpText, cur.HelpText),
		boolChanged(req.PaymentCancelRateLimitEnabled, cur.CancelRateLimitEnabled),
		intChanged(req.PaymentCancelRateLimitMax, cur.CancelRateLimitMax),
		intChanged(req.PaymentCancelRateLimitWindow, cur.CancelRateLimitWindow),
		trimmedStringChanged(req.PaymentCancelRateLimitUnit, cur.CancelRateLimitUnit),
		trimmedStringChanged(req.PaymentCancelRateLimitMode, cur.CancelRateLimitMode),
		boolChanged(req.PaymentAlipayForceQRCode, cur.AlipayForceQRCode),
		boolChanged(req.PaymentAlipayMobilePrecreateDeepLink, cur.AlipayMobilePrecreateDeepLink):
		return true
	}
	return false
}

func boolChanged(v *bool, cur bool) bool        { return v != nil && *v != cur }
func intChanged(v *int, cur int) bool           { return v != nil && *v != cur }
func floatChanged(v *float64, cur float64) bool { return v != nil && *v != cur }
func trimmedStringChanged(v *string, cur string) bool {
	return v != nil && strings.TrimSpace(*v) != strings.TrimSpace(cur)
}

func sameStringSet(a, b []string) bool {
	norm := func(in []string) []string {
		out := make([]string, 0, len(in))
		seen := make(map[string]struct{}, len(in))
		for _, s := range in {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
		sort.Strings(out)
		return out
	}
	na, nb := norm(a), norm(b)
	if len(na) != len(nb) {
		return false
	}
	for i := range na {
		if na[i] != nb[i] {
			return false
		}
	}
	return true
}

func sameBonusTiers(a *[]service.RechargeBonusTier, b []service.RechargeBonusTier) bool {
	var left []service.RechargeBonusTier
	if a != nil {
		left = append(left, (*a)...)
	}
	right := append([]service.RechargeBonusTier(nil), b...)
	if len(left) != len(right) {
		return false
	}
	less := func(s []service.RechargeBonusTier) func(i, j int) bool {
		return func(i, j int) bool {
			if s[i].MinAmount != s[j].MinAmount {
				return s[i].MinAmount < s[j].MinAmount
			}
			return s[i].BonusPercent < s[j].BonusPercent
		}
	}
	sort.SliceStable(left, less(left))
	sort.SliceStable(right, less(right))
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
