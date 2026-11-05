package service

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/payment"
	"github.com/stretchr/testify/require"
)

// BD2-2：创建/更新 provider 的响应与 GET 列表同形，config 为对象且不含敏感字段。
func TestBD22_ProviderCreateUpdateResponseMasksSecrets(t *testing.T) {
	ctx := context.Background()
	client := newPaymentConfigServiceTestClient(t)
	svc := &PaymentConfigService{entClient: client}

	inst, err := svc.CreateProviderInstance(ctx, CreateProviderInstanceRequest{
		ProviderKey: payment.TypeEasyPay, Name: "li-p",
		Config:         map[string]string{"pid": "1001", "pkey": "TOP-SECRET-PKEY"},
		SupportedTypes: []string{"alipay"},
	})
	require.NoError(t, err)

	resp, err := svc.ProviderInstanceToResponse(inst)
	require.NoError(t, err)
	raw, err := json.Marshal(resp)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "TOP-SECRET-PKEY")
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	cfg, ok := decoded["config"].(map[string]any)
	require.True(t, ok, "config must be a JSON object, got %T", decoded["config"])
	require.Equal(t, "1001", cfg["pid"])
	_, hasPkey := cfg["pkey"]
	require.False(t, hasPkey)

	list, err := svc.ListProviderInstancesWithConfig(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, list[0], *resp, "create response must equal the GET list item")

	pid := map[string]string{"pid": "2002", "pkey": "NEW-SECRET"}
	updated, err := svc.UpdateProviderInstance(ctx, int64(inst.ID), UpdateProviderInstanceRequest{Config: pid})
	require.NoError(t, err)
	uresp, err := svc.ProviderInstanceToResponse(updated)
	require.NoError(t, err)
	raw, _ = json.Marshal(uresp)
	require.NotContains(t, string(raw), "NEW-SECRET")
	require.Equal(t, "2002", uresp.Config["pid"])

	_, err = svc.ProviderInstanceToResponse(nil)
	require.Error(t, err)
}
