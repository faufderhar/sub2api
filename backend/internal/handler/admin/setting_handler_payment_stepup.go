package admin

import (
	"context"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// M-7：所有支付配置写入仅在「实际变更」时要求 step-up（PM 统一规则）。
// 常规保存（前端把 GET 回来的字段原样回传）不得触发 STEP_UP_REQUIRED。
// 读取当前值失败时按「已变更」处理（fail-closed），即要求 step-up。

// paymentSettingsChanged 用于 PUT /api/v1/admin/settings。
// payment_* 与 PaymentConfigService.GetPaymentConfig 比较；payment_visible_method_*
// 与 previousSettings 比较（二者均为 GET /admin/settings 的数据源）。
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
	cur := service.VisibleMethodSettings{}
	if previous == nil {
		return req.PaymentVisibleMethodAlipaySource != nil || req.PaymentVisibleMethodWxpaySource != nil ||
			req.PaymentVisibleMethodAlipayEnabled != nil || req.PaymentVisibleMethodWxpayEnabled != nil
	}
	cur.AlipaySource = previous.PaymentVisibleMethodAlipaySource
	cur.WxpaySource = previous.PaymentVisibleMethodWxpaySource
	cur.AlipayEnabled = previous.PaymentVisibleMethodAlipayEnabled
	cur.WxpayEnabled = previous.PaymentVisibleMethodWxpayEnabled
	return service.VisibleMethodFieldsChanged(req.PaymentVisibleMethodAlipaySource, req.PaymentVisibleMethodWxpaySource,
		req.PaymentVisibleMethodAlipayEnabled, req.PaymentVisibleMethodWxpayEnabled, cur)
}

// paymentConfigFieldsChanged 把 settings 请求映射为 UpdatePaymentConfigRequest 后复用统一比较逻辑。
func paymentConfigFieldsChanged(req UpdateSettingsRequest, cur *service.PaymentConfig) bool {
	return service.PaymentConfigRequestChanged(service.UpdatePaymentConfigRequest{
		Enabled:                       req.PaymentEnabled,
		MinAmount:                     req.PaymentMinAmount,
		MaxAmount:                     req.PaymentMaxAmount,
		DailyLimit:                    req.PaymentDailyLimit,
		OrderTimeoutMin:               req.PaymentOrderTimeoutMin,
		MaxPendingOrders:              req.PaymentMaxPendingOrders,
		EnabledTypes:                  req.PaymentEnabledTypes,
		BalanceDisabled:               req.PaymentBalanceDisabled,
		BalanceRechargeMultiplier:     req.PaymentBalanceRechargeMultiplier,
		SubscriptionUSDToCNYRate:      req.PaymentSubscriptionUSDToCNYRate,
		RechargeFeeRate:               req.PaymentRechargeFeeRate,
		RechargeBonusTiers:            rechargeBonusTiersFromDTO(req.PaymentRechargeBonusTiers),
		RechargeBonusMode:             req.PaymentRechargeBonusMode,
		RechargeBonusNotice:           req.PaymentRechargeBonusNotice,
		LoadBalanceStrategy:           req.PaymentLoadBalanceStrat,
		ProductNamePrefix:             req.PaymentProductNamePrefix,
		ProductNameSuffix:             req.PaymentProductNameSuffix,
		HelpImageURL:                  req.PaymentHelpImageURL,
		HelpText:                      req.PaymentHelpText,
		CancelRateLimitEnabled:        req.PaymentCancelRateLimitEnabled,
		CancelRateLimitMax:            req.PaymentCancelRateLimitMax,
		CancelRateLimitWindow:         req.PaymentCancelRateLimitWindow,
		CancelRateLimitUnit:           req.PaymentCancelRateLimitUnit,
		CancelRateLimitMode:           req.PaymentCancelRateLimitMode,
		AlipayForceQRCode:             req.PaymentAlipayForceQRCode,
		AlipayMobilePrecreateDeepLink: req.PaymentAlipayMobilePrecreateDeepLink,
	}, cur)
}

// paymentConfigRequestChanged 用于 PUT /api/v1/admin/payment/config。
func (h *PaymentHandler) paymentConfigRequestChanged(ctx context.Context, req service.UpdatePaymentConfigRequest) bool {
	if h.configService == nil {
		return true
	}
	if req.VisibleMethodAlipaySource != nil || req.VisibleMethodWxpaySource != nil ||
		req.VisibleMethodAlipayEnabled != nil || req.VisibleMethodWxpayEnabled != nil {
		vis, err := h.configService.GetVisibleMethodSettings(ctx)
		if err != nil || vis == nil {
			return true
		}
		if service.VisibleMethodFieldsChanged(req.VisibleMethodAlipaySource, req.VisibleMethodWxpaySource,
			req.VisibleMethodAlipayEnabled, req.VisibleMethodWxpayEnabled, *vis) {
			return true
		}
	}
	current, err := h.configService.GetPaymentConfig(ctx)
	if err != nil || current == nil {
		return true
	}
	return service.PaymentConfigRequestChanged(req, current)
}
