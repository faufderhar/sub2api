# Claude Code 指纹一致性验收测试

位置：`backend/internal/service/zz_audit3_fingerprint_harness_test.go`  
分支：`fix/backend-round3`

本文件是第三轮 R3-FP 的正向回归，不再把现状缺陷记成 PASS。

## 复跑

全程本机、不联网、不碰共享实例 18093：

```bash
cd /workspace/sub2api-be3/backend
go test -tags=unit -count=1 -timeout 180s -v -run 'TestAudit3FP' ./internal/service/
```

## 覆盖的路径

- `/v1/messages` 流式与非流式（mimic=true / false）
- `/v1/messages/count_tokens`
- 测连风格 payload（`generateSessionStringFromFingerprint`）
- 三个账号、多种下游客户端头（真 CC、新 UA、空头）
- failover 同一原始 body 换账号，不泄漏 device / account_uuid / session
- 缓存 flush 后身份不变（DB/store 为事实源）
- 100 个 goroutine 并发首次创建只有一套身份
- 1000 个账号 seed/ClientID 无重复
- RNG 失败不写部分账号
- 手动再生只改目标账号，旧缓存不能复活
- 本机 TLS ClientHello 捕获：同传输策略两次握手稳定（不宣称每账号独有 JA3）

## 未覆盖

- 真实 Anthropic / 外部 JA3 指纹网站
- 完整 HTTP 往返的用量 `/api/oauth/usage` 与 OAuth token 刷新（D9：刷新保持 axios/Chrome，不混入 CLI 矩阵）
- 真实连接池 failover 的跨进程场景（本文件用本机模拟上游头/body）
- Docker / 真实反代 / 真实 IPv6
