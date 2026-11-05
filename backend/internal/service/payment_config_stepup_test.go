package service

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/payment"
	"github.com/stretchr/testify/require"
)

func TestM7_ProviderInstanceUpdateChanges(t *testing.T) {
	ctx := context.Background()
	client := newPaymentConfigServiceTestClient(t)
	inst, err := client.PaymentProviderInstance.Create().
		SetProviderKey(payment.TypeEasyPay).
		SetName("EasyPay Alipay").
		SetConfig(`{"pid":"1001","pkey":"secret"}`).
		SetSupportedTypes("alipay,wxpay").
		SetEnabled(true).
		Save(ctx)
	require.NoError(t, err)
	svc := &PaymentConfigService{entClient: client}
	id := int64(inst.ID)
	name := " EasyPay Alipay "
	enabled := true
	off := false
	newName := "Other"

	changed, err := svc.ProviderInstanceUpdateChanges(ctx, id, UpdateProviderInstanceRequest{
		Name: &name, Enabled: &enabled, SupportedTypes: []string{"wxpay", "alipay"},
		Config: map[string]string{"pid": "1001", "pkey": ""}, // 敏感字段留空 = 保持不变
	})
	require.NoError(t, err)
	require.False(t, changed, "round-tripped values must not require step-up")

	for _, req := range []UpdateProviderInstanceRequest{
		{Name: &newName},
		{Enabled: &off},
		{SupportedTypes: []string{"alipay"}},
		{Config: map[string]string{"pid": "2002"}},
	} {
		changed, err := svc.ProviderInstanceUpdateChanges(ctx, id, req)
		require.NoError(t, err)
		require.True(t, changed)
	}

	changed, err = svc.ProviderInstanceUpdateChanges(ctx, id+999, UpdateProviderInstanceRequest{})
	require.Error(t, err)
	require.True(t, changed, "lookup failure is treated as changed (fail-closed)")
}

func TestM7_PaymentConfigRequestChanged(t *testing.T) {
	cur := &PaymentConfig{Enabled: true, MinAmount: 5, EnabledTypes: []string{"alipay", "wxpay"}, RechargeBonusMode: "bonus"}
	tr, five, empty := true, 5.0, ""
	require.False(t, PaymentConfigRequestChanged(UpdatePaymentConfigRequest{Enabled: &tr, MinAmount: &five, EnabledTypes: []string{"wxpay", "alipay"}, RechargeBonusMode: &empty}, cur))
	ten := 10.0
	require.True(t, PaymentConfigRequestChanged(UpdatePaymentConfigRequest{MinAmount: &ten}, cur))
	require.True(t, PaymentConfigRequestChanged(UpdatePaymentConfigRequest{}, nil))

	vis := VisibleMethodSettings{AlipaySource: NormalizeVisibleMethodSource("alipay", "easypay"), AlipayEnabled: true}
	src := "easypay"
	require.False(t, VisibleMethodFieldsChanged(&src, nil, &tr, nil, vis))
	require.True(t, VisibleMethodFieldsChanged(nil, nil, nil, &tr, vis))
}
