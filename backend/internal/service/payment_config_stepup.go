package service

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// M-7：支付配置「是否实际变更」的判定，供 step-up 条件门控使用。

// VisibleMethodSettings 是支付可见方式路由的当前存储值（已归一化）。
type VisibleMethodSettings struct {
	AlipaySource  string
	WxpaySource   string
	AlipayEnabled bool
	WxpayEnabled  bool
}

// GetVisibleMethodSettings 读取支付可见方式路由的当前值。
func (s *PaymentConfigService) GetVisibleMethodSettings(ctx context.Context) (*VisibleMethodSettings, error) {
	vals, err := s.settingRepo.GetMultiple(ctx, []string{
		SettingPaymentVisibleMethodAlipaySource, SettingPaymentVisibleMethodWxpaySource,
		SettingPaymentVisibleMethodAlipayEnabled, SettingPaymentVisibleMethodWxpayEnabled,
	})
	if err != nil {
		return nil, fmt.Errorf("get visible method settings: %w", err)
	}
	return &VisibleMethodSettings{
		AlipaySource:  NormalizeVisibleMethodSource("alipay", vals[SettingPaymentVisibleMethodAlipaySource]),
		WxpaySource:   NormalizeVisibleMethodSource("wxpay", vals[SettingPaymentVisibleMethodWxpaySource]),
		AlipayEnabled: vals[SettingPaymentVisibleMethodAlipayEnabled] == "true",
		WxpayEnabled:  vals[SettingPaymentVisibleMethodWxpayEnabled] == "true",
	}, nil
}

// VisibleMethodFieldsChanged 判断请求中出现的可见方式字段是否与当前值不同。
func VisibleMethodFieldsChanged(alipaySource, wxpaySource *string, alipayEnabled, wxpayEnabled *bool, cur VisibleMethodSettings) bool {
	if alipaySource != nil && NormalizeVisibleMethodSource("alipay", *alipaySource) != NormalizeVisibleMethodSource("alipay", cur.AlipaySource) {
		return true
	}
	if wxpaySource != nil && NormalizeVisibleMethodSource("wxpay", *wxpaySource) != NormalizeVisibleMethodSource("wxpay", cur.WxpaySource) {
		return true
	}
	if alipayEnabled != nil && *alipayEnabled != cur.AlipayEnabled {
		return true
	}
	if wxpayEnabled != nil && *wxpayEnabled != cur.WxpayEnabled {
		return true
	}
	return false
}

// PaymentConfigRequestChanged 判断 UpdatePaymentConfigRequest 的 payment 字段是否与 cur 不同
// （不含 VisibleMethod* 字段，见 VisibleMethodFieldsChanged）。
// 归一化：字符串去首尾空白；类型按集合；阶梯排序后比较；模式空值视为 bonus。
func PaymentConfigRequestChanged(req UpdatePaymentConfigRequest, cur *PaymentConfig) bool {
	if cur == nil {
		return true
	}
	bc := func(v *bool, c bool) bool { return v != nil && *v != c }
	ic := func(v *int, c int) bool { return v != nil && *v != c }
	fc := func(v *float64, c float64) bool { return v != nil && *v != c }
	sc := func(v *string, c string) bool { return v != nil && strings.TrimSpace(*v) != strings.TrimSpace(c) }
	modeChanged := false
	if req.RechargeBonusMode != nil {
		a, _ := NormalizeRechargeBonusMode(*req.RechargeBonusMode)
		b, _ := NormalizeRechargeBonusMode(cur.RechargeBonusMode)
		modeChanged = a != b
	}
	return bc(req.Enabled, cur.Enabled) ||
		fc(req.MinAmount, cur.MinAmount) ||
		fc(req.MaxAmount, cur.MaxAmount) ||
		fc(req.DailyLimit, cur.DailyLimit) ||
		ic(req.OrderTimeoutMin, cur.OrderTimeoutMin) ||
		ic(req.MaxPendingOrders, cur.MaxPendingOrders) ||
		(req.EnabledTypes != nil && !sameTrimmedStringSet(req.EnabledTypes, cur.EnabledTypes)) ||
		bc(req.BalanceDisabled, cur.BalanceDisabled) ||
		fc(req.BalanceRechargeMultiplier, cur.BalanceRechargeMultiplier) ||
		fc(req.SubscriptionUSDToCNYRate, cur.SubscriptionUSDToCNYRate) ||
		fc(req.RechargeFeeRate, cur.RechargeFeeRate) ||
		(req.RechargeBonusTiers != nil && !sameBonusTiers(*req.RechargeBonusTiers, cur.RechargeBonusTiers)) ||
		modeChanged ||
		sc(req.RechargeBonusNotice, cur.RechargeBonusNotice) ||
		sc(req.LoadBalanceStrategy, cur.LoadBalanceStrategy) ||
		sc(req.ProductNamePrefix, cur.ProductNamePrefix) ||
		sc(req.ProductNameSuffix, cur.ProductNameSuffix) ||
		sc(req.HelpImageURL, cur.HelpImageURL) ||
		sc(req.HelpText, cur.HelpText) ||
		bc(req.CancelRateLimitEnabled, cur.CancelRateLimitEnabled) ||
		ic(req.CancelRateLimitMax, cur.CancelRateLimitMax) ||
		ic(req.CancelRateLimitWindow, cur.CancelRateLimitWindow) ||
		sc(req.CancelRateLimitUnit, cur.CancelRateLimitUnit) ||
		sc(req.CancelRateLimitMode, cur.CancelRateLimitMode) ||
		bc(req.AlipayForceQRCode, cur.AlipayForceQRCode) ||
		bc(req.AlipayMobilePrecreateDeepLink, cur.AlipayMobilePrecreateDeepLink)
}

// ProviderInstanceUpdateChanges 判断更新请求是否会实际修改服务商实例。
// 敏感字段提交空值表示「保持不变」，与 mergeConfig 语义一致。
func (s *PaymentConfigService) ProviderInstanceUpdateChanges(ctx context.Context, id int64, req UpdateProviderInstanceRequest) (bool, error) {
	if s == nil || s.entClient == nil {
		return true, fmt.Errorf("payment config service unavailable")
	}
	current, err := s.entClient.PaymentProviderInstance.Get(ctx, id)
	if err != nil {
		return true, fmt.Errorf("load provider instance: %w", err)
	}
	if req.Name != nil && strings.TrimSpace(*req.Name) != strings.TrimSpace(current.Name) {
		return true, nil
	}
	if req.Enabled != nil && *req.Enabled != current.Enabled {
		return true, nil
	}
	if req.PaymentMode != nil && strings.TrimSpace(*req.PaymentMode) != strings.TrimSpace(current.PaymentMode) {
		return true, nil
	}
	if req.SortOrder != nil && *req.SortOrder != current.SortOrder {
		return true, nil
	}
	if req.Limits != nil && strings.TrimSpace(*req.Limits) != strings.TrimSpace(current.Limits) {
		return true, nil
	}
	if req.RefundEnabled != nil && *req.RefundEnabled != current.RefundEnabled {
		return true, nil
	}
	if req.AllowUserRefund != nil && *req.AllowUserRefund != current.AllowUserRefund {
		return true, nil
	}
	if req.SupportedTypes != nil && !sameTrimmedStringSet(req.SupportedTypes, splitTypes(current.SupportedTypes)) {
		return true, nil
	}
	if req.Config != nil {
		existing, err := s.decryptConfig(current.Config)
		if err != nil {
			return true, fmt.Errorf("decrypt existing config: %w", err)
		}
		for k, v := range req.Config {
			if v == "" && isSensitiveProviderConfigField(current.ProviderKey, k) {
				continue
			}
			if old, ok := existing[k]; !ok || old != v {
				if !ok && v == "" {
					continue
				}
				return true, nil
			}
		}
	}
	return false, nil
}

func sameTrimmedStringSet(a, b []string) bool {
	norm := func(in []string) []string {
		seen := make(map[string]struct{}, len(in))
		out := make([]string, 0, len(in))
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

func sameBonusTiers(a, b []RechargeBonusTier) bool {
	if len(a) != len(b) {
		return false
	}
	l := append([]RechargeBonusTier(nil), a...)
	r := append([]RechargeBonusTier(nil), b...)
	less := func(s []RechargeBonusTier) func(i, j int) bool {
		return func(i, j int) bool {
			if s[i].MinAmount != s[j].MinAmount {
				return s[i].MinAmount < s[j].MinAmount
			}
			return s[i].BonusPercent < s[j].BonusPercent
		}
	}
	sort.SliceStable(l, less(l))
	sort.SliceStable(r, less(r))
	for i := range l {
		if l[i] != r[i] {
			return false
		}
	}
	return true
}
