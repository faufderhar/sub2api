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
	// AlipaySourceRaw / WxpaySourceRaw 是未经归一化的原始存储值（BD2-1）。
	AlipaySourceRaw string
	WxpaySourceRaw  string
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

		AlipaySourceRaw: vals[SettingPaymentVisibleMethodAlipaySource],
		WxpaySourceRaw:  vals[SettingPaymentVisibleMethodWxpaySource],
	}, nil
}

// VisibleMethodFieldsChanged 判断请求中出现的可见方式字段是否与当前值不同。
func VisibleMethodFieldsChanged(alipaySource, wxpaySource *string, alipayEnabled, wxpayEnabled *bool, cur VisibleMethodSettings) bool {
	// PUT /admin/settings 路径：handler 先去空白、SettingService 再按同一规则归一化后存储，
	// 因此按归一化结果比较即「按存储值比较」。
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

// VisibleMethodFieldsChangedRawStored 用于 PUT /admin/payment/config：UpdatePaymentConfig 原样写入
// source（不去空白、不归一化），因此请求值与原始存储值逐字比较（BD2-1）。
func VisibleMethodFieldsChangedRawStored(alipaySource, wxpaySource *string, alipayEnabled, wxpayEnabled *bool, cur VisibleMethodSettings) bool {
	if alipaySource != nil && *alipaySource != cur.AlipaySourceRaw {
		return true
	}
	if wxpaySource != nil && *wxpaySource != cur.WxpaySourceRaw {
		return true
	}
	return VisibleMethodFieldsChanged(nil, nil, alipayEnabled, wxpayEnabled, cur)
}

// PaymentConfigRequestChanged 判断 UpdatePaymentConfigRequest 的 payment 字段是否与 cur 不同
// （不含 VisibleMethod* 字段，见 VisibleMethodFieldsChanged）。
// 归一化与 UpdatePaymentConfig 的存储方式一致（BD2-1）：字符串原样存储因此逐字比较
// （recharge_bonus_notice 存储前去首尾空白，故比较前同样去空白）；enabled_types 按存储的
// 逗号拼接结果（含顺序）比较；阶梯排序后比较；模式空值视为 bonus。
func PaymentConfigRequestChanged(req UpdatePaymentConfigRequest, cur *PaymentConfig) bool {
	if cur == nil {
		return true
	}
	bc := func(v *bool, c bool) bool { return v != nil && *v != c }
	ic := func(v *int, c int) bool { return v != nil && *v != c }
	fc := func(v *float64, c float64) bool { return v != nil && *v != c }
	sc := func(v *string, c string) bool { return v != nil && *v != c }
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
		(req.EnabledTypes != nil && strings.Join(req.EnabledTypes, ",") != strings.Join(cur.EnabledTypes, ",")) ||
		bc(req.BalanceDisabled, cur.BalanceDisabled) ||
		fc(req.BalanceRechargeMultiplier, cur.BalanceRechargeMultiplier) ||
		fc(req.SubscriptionUSDToCNYRate, cur.SubscriptionUSDToCNYRate) ||
		fc(req.RechargeFeeRate, cur.RechargeFeeRate) ||
		(req.RechargeBonusTiers != nil && !sameBonusTiers(*req.RechargeBonusTiers, cur.RechargeBonusTiers)) ||
		modeChanged ||
		(req.RechargeBonusNotice != nil && strings.TrimSpace(*req.RechargeBonusNotice) != cur.RechargeBonusNotice) ||
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

// ProviderInstanceUpdateChanges 判断更新请求是否会实际修改服务商实例的存储值。
//
// BD2-1：逐字段按 UpdateProviderInstance 的实际写入方式计算「将要存储的值」再与当前存储值比较，
// 归一化与存储完全一致（name/payment_mode/limits 原样存储因此逐字比较；supported_types 按
// joinTypes 的结果含顺序比较；allow_user_refund 按存储时的级联规则推导；config 按 mergeConfig
// 合并后的结果比较，敏感字段提交空值表示「保持不变」）。任何会改变存储内容的写入都需要 step-up。
func (s *PaymentConfigService) ProviderInstanceUpdateChanges(ctx context.Context, id int64, req UpdateProviderInstanceRequest) (bool, error) {
	if s == nil || s.entClient == nil {
		return true, fmt.Errorf("payment config service unavailable")
	}
	current, err := s.entClient.PaymentProviderInstance.Get(ctx, id)
	if err != nil {
		return true, fmt.Errorf("load provider instance: %w", err)
	}
	if req.Name != nil && *req.Name != current.Name {
		return true, nil
	}
	if req.Enabled != nil && *req.Enabled != current.Enabled {
		return true, nil
	}
	if req.PaymentMode != nil && *req.PaymentMode != current.PaymentMode {
		return true, nil
	}
	if req.SortOrder != nil && *req.SortOrder != current.SortOrder {
		return true, nil
	}
	if req.Limits != nil && *req.Limits != current.Limits {
		return true, nil
	}
	if req.SupportedTypes != nil && joinTypes(req.SupportedTypes) != current.SupportedTypes {
		return true, nil
	}
	nextRefund := current.RefundEnabled
	nextAllow := current.AllowUserRefund
	if req.RefundEnabled != nil {
		nextRefund = *req.RefundEnabled
		if !nextRefund {
			nextAllow = false
		}
	}
	if req.AllowUserRefund != nil {
		if *req.AllowUserRefund {
			if nextRefund {
				nextAllow = true
			}
		} else {
			nextAllow = false
		}
	}
	if nextRefund != current.RefundEnabled || nextAllow != current.AllowUserRefund {
		return true, nil
	}
	if req.Config != nil {
		existing, err := s.decryptConfig(current.ID, current.ProviderKey, current.Config)
		if err != nil {
			return true, fmt.Errorf("decrypt existing config: %w", err)
		}
		merged := make(map[string]string, len(existing)+len(req.Config))
		for k, v := range existing {
			merged[k] = v
		}
		for k, v := range req.Config {
			if v == "" && isSensitiveProviderConfigField(current.ProviderKey, k) {
				continue
			}
			merged[k] = v
		}
		if !sameStringMap(existing, merged) {
			return true, nil
		}
	}
	return false, nil
}

func sameStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
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
