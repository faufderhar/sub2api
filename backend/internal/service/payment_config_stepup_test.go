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
	name := "EasyPay Alipay"
	enabled := true
	off := false
	newName := "Other"
	paddedName := " EasyPay Alipay "

	changed, err := svc.ProviderInstanceUpdateChanges(ctx, id, UpdateProviderInstanceRequest{
		Name: &name, Enabled: &enabled, SupportedTypes: []string{"alipay", "wxpay"},
		Config: map[string]string{"pid": "1001", "pkey": ""}, // 敏感字段留空 = 保持不变
	})
	require.NoError(t, err)
	require.False(t, changed, "round-tripped values must not require step-up")

	for _, req := range []UpdateProviderInstanceRequest{
		{Name: &newName},
		{Enabled: &off},
		{SupportedTypes: []string{"alipay"}},
		{Config: map[string]string{"pid": "2002"}},
		// BD2-1：存储层不 trim / 不排序，因此这些都会改变存储值，必须要求 step-up。
		{Name: &paddedName},
		{SupportedTypes: []string{"wxpay", "alipay"}},
		{SupportedTypes: []string{"alipay", "wxpay "}},
		{Config: map[string]string{"pid": " 1001"}},
		{Config: map[string]string{"new_field": ""}},
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
	require.False(t, PaymentConfigRequestChanged(UpdatePaymentConfigRequest{Enabled: &tr, MinAmount: &five, EnabledTypes: []string{"alipay", "wxpay"}, RechargeBonusMode: &empty}, cur))
	// BD2-1：enabled_types 按存储的拼接结果比较（顺序/空白变化会改变存储值）。
	require.True(t, PaymentConfigRequestChanged(UpdatePaymentConfigRequest{EnabledTypes: []string{"wxpay", "alipay"}}, cur))
	require.True(t, PaymentConfigRequestChanged(UpdatePaymentConfigRequest{EnabledTypes: []string{"alipay", " wxpay"}}, cur))
	ten := 10.0
	require.True(t, PaymentConfigRequestChanged(UpdatePaymentConfigRequest{MinAmount: &ten}, cur))
	require.True(t, PaymentConfigRequestChanged(UpdatePaymentConfigRequest{}, nil))

	vis := VisibleMethodSettings{AlipaySource: NormalizeVisibleMethodSource("alipay", "easypay"), AlipayEnabled: true}
	src := "easypay"
	require.False(t, VisibleMethodFieldsChanged(&src, nil, &tr, nil, vis))
	require.True(t, VisibleMethodFieldsChanged(nil, nil, nil, &tr, vis))
}

// BD2-1：字符串字段原样存储，因此只要会改变存储值（含首尾空白）就视为变更；
// recharge_bonus_notice 存储前去空白，比较前同样去空白。
func TestBD21_PaymentConfigStringsCompareAsStored(t *testing.T) {
	cur := &PaymentConfig{HelpText: "hi", ProductNamePrefix: "P", RechargeBonusNotice: "notice"}
	same, padded := "hi", " hi "
	require.False(t, PaymentConfigRequestChanged(UpdatePaymentConfigRequest{HelpText: &same}, cur))
	require.True(t, PaymentConfigRequestChanged(UpdatePaymentConfigRequest{HelpText: &padded}, cur))
	pp := "P "
	require.True(t, PaymentConfigRequestChanged(UpdatePaymentConfigRequest{ProductNamePrefix: &pp}, cur))
	notice := "  notice  "
	require.False(t, PaymentConfigRequestChanged(UpdatePaymentConfigRequest{RechargeBonusNotice: &notice}, cur), "notice is trimmed before storage")

	vis := VisibleMethodSettings{AlipaySource: VisibleMethodSourceEasyPayAlipay, AlipaySourceRaw: VisibleMethodSourceEasyPayAlipay}
	exact := VisibleMethodSourceEasyPayAlipay
	alias := "easypay"
	require.False(t, VisibleMethodFieldsChangedRawStored(&exact, nil, nil, nil, vis))
	require.True(t, VisibleMethodFieldsChangedRawStored(&alias, nil, nil, nil, vis), "payment/config stores the raw source")
	require.False(t, VisibleMethodFieldsChanged(&alias, nil, nil, nil, vis), "settings path normalizes before storage")
}

// BD2-1：服务商 name 加首尾空白会被原样写入，必须要求 step-up；且判定与实际写入一致。
func TestBD21_ProviderNameWhitespaceIsAStoredChange(t *testing.T) {
	ctx := context.Background()
	client := newPaymentConfigServiceTestClient(t)
	svc := &PaymentConfigService{entClient: client}
	inst, err := svc.CreateProviderInstance(ctx, CreateProviderInstanceRequest{
		ProviderKey: payment.TypeEasyPay, Name: "li-p", Config: map[string]string{"pid": "1"}, SupportedTypes: []string{"alipay"},
	})
	require.NoError(t, err)
	id := int64(inst.ID)
	padded := " li-p "
	changed, err := svc.ProviderInstanceUpdateChanges(ctx, id, UpdateProviderInstanceRequest{Name: &padded})
	require.NoError(t, err)
	require.True(t, changed)

	// 判定为「未变更」的请求写入后存储值不变（判定 == 实际写入）。
	same := "li-p"
	refund := true
	req := UpdateProviderInstanceRequest{Name: &same, Config: map[string]string{"pid": "1", "pkey": ""}, SupportedTypes: []string{"alipay"}}
	changed, err = svc.ProviderInstanceUpdateChanges(ctx, id, req)
	require.NoError(t, err)
	require.False(t, changed)
	before, _ := client.PaymentProviderInstance.Get(ctx, inst.ID)
	_, err = svc.UpdateProviderInstance(ctx, id, req)
	require.NoError(t, err)
	after, _ := client.PaymentProviderInstance.Get(ctx, inst.ID)
	require.Equal(t, before.Name, after.Name)
	require.Equal(t, before.Config, after.Config)
	require.Equal(t, before.SupportedTypes, after.SupportedTypes)

	// allow_user_refund=true 但 refund 关闭：存储层不会写入，因此不算变更。
	allow := true
	changed, err = svc.ProviderInstanceUpdateChanges(ctx, id, UpdateProviderInstanceRequest{AllowUserRefund: &allow})
	require.NoError(t, err)
	require.False(t, changed)
	changed, err = svc.ProviderInstanceUpdateChanges(ctx, id, UpdateProviderInstanceRequest{RefundEnabled: &refund, AllowUserRefund: &allow})
	require.NoError(t, err)
	require.True(t, changed)
}
