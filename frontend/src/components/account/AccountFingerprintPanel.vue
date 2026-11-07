<template>
  <section class="rounded-lg border border-gray-200 p-4 dark:border-dark-600" data-testid="account-fingerprint-panel">
    <h3 class="mb-3 text-sm font-medium text-gray-900 dark:text-gray-100">
      {{ t('admin.accounts.fingerprint.title') }}
    </h3>
    <p v-if="loading" class="text-sm text-gray-500" data-testid="fingerprint-loading">
      {{ t('admin.accounts.fingerprint.loading') }}
    </p>
    <p v-else-if="loadError" class="text-sm text-red-600" data-testid="fingerprint-load-error">
      {{ loadError }}
    </p>
    <template v-else-if="summary && !summary.applicable">
      <p class="text-sm text-gray-600 dark:text-gray-300" data-testid="fingerprint-not-applicable">
        {{ summary.message || t('admin.accounts.fingerprint.notApplicable') }}
      </p>
    </template>
    <template v-else-if="summary">
      <div
        v-if="summary.conflict"
        class="mb-3 rounded-md bg-amber-50 p-3 text-sm text-amber-800 dark:bg-amber-900/30 dark:text-amber-200"
        data-testid="fingerprint-conflict"
      >
        {{ t('admin.accounts.fingerprint.conflictWarning') }}
      </div>
      <div
        v-if="summary.passthrough_user_id"
        class="mb-3 rounded-md bg-amber-50 p-3 text-sm text-amber-800 dark:bg-amber-900/30 dark:text-amber-200"
        data-testid="fingerprint-passthrough"
      >
        {{ t('admin.accounts.fingerprint.passthroughWarning') }}
      </div>
      <div
        v-if="summary.account_uuid_changed"
        class="mb-3 rounded-md bg-amber-50 p-3 text-sm text-amber-800 dark:bg-amber-900/30 dark:text-amber-200"
        data-testid="fingerprint-uuid-changed"
      >
        {{ t('admin.accounts.fingerprint.accountUuidChangedWarning') }}
      </div>
      <dl class="grid grid-cols-1 gap-2 text-sm sm:grid-cols-2" data-testid="fingerprint-summary">
        <div>
          <dt class="text-gray-500">{{ t('admin.accounts.fingerprint.generation') }}</dt>
          <dd class="font-mono">{{ summary.generation ?? '—' }}</dd>
        </div>
        <div>
          <dt class="text-gray-500">{{ t('admin.accounts.fingerprint.source') }}</dt>
          <dd>{{ sourceLabel(summary.source) }}</dd>
        </div>
        <div class="sm:col-span-2">
          <dt class="text-gray-500">{{ t('admin.accounts.fingerprint.userAgent') }}</dt>
          <dd class="break-all font-mono text-xs">{{ summary.user_agent || '—' }}</dd>
        </div>
        <div>
          <dt class="text-gray-500">{{ t('admin.accounts.fingerprint.os') }}</dt>
          <dd>{{ summary.os || '—' }}</dd>
        </div>
        <div>
          <dt class="text-gray-500">{{ t('admin.accounts.fingerprint.arch') }}</dt>
          <dd>{{ summary.arch || '—' }}</dd>
        </div>
        <div>
          <dt class="text-gray-500">{{ t('admin.accounts.fingerprint.runtime') }}</dt>
          <dd>{{ summary.runtime || '—' }}</dd>
        </div>
        <div>
          <dt class="text-gray-500">{{ t('admin.accounts.fingerprint.runtimeVersion') }}</dt>
          <dd>{{ summary.runtime_version || '—' }}</dd>
        </div>
        <div>
          <dt class="text-gray-500">{{ t('admin.accounts.fingerprint.clientIdPrefix') }}</dt>
          <dd class="font-mono">{{ summary.client_id_prefix || '—' }}</dd>
        </div>
        <div>
          <dt class="text-gray-500">{{ t('admin.accounts.fingerprint.tlsProfile') }}</dt>
          <dd>{{ tlsProfileLabel }}</dd>
        </div>
        <div>
          <dt class="text-gray-500">{{ t('admin.accounts.fingerprint.tlsBinding') }}</dt>
          <dd>{{ tlsBindingLabel }}</dd>
        </div>
        <div>
          <dt class="text-gray-500">{{ t('admin.accounts.fingerprint.updatedAt') }}</dt>
          <dd>{{ summary.updated_at || '—' }}</dd>
        </div>
        <div>
          <dt class="text-gray-500">{{ t('admin.accounts.fingerprint.accountUuidPresent') }}</dt>
          <dd>{{ summary.account_uuid_present ? t('admin.accounts.fingerprint.yes') : t('admin.accounts.fingerprint.no') }}</dd>
        </div>
      </dl>
      <div v-if="summary.regenerable" class="mt-4 space-y-3">
        <button
          v-if="!confirming"
          type="button"
          class="btn btn-secondary"
          data-testid="fingerprint-regenerate"
          :disabled="regenerating"
          @click="confirming = true"
        >
          {{ t('admin.accounts.fingerprint.regenerate') }}
        </button>
        <div v-else class="rounded-md border border-amber-200 bg-amber-50 p-3 dark:border-amber-800 dark:bg-amber-900/20">
          <p class="mb-3 text-sm text-amber-900 dark:text-amber-100" data-testid="fingerprint-regenerate-warning">
            {{ t('admin.accounts.fingerprint.regenerateWarning') }}
          </p>
          <div class="flex gap-2">
            <button
              type="button"
              class="btn btn-primary"
              data-testid="fingerprint-regenerate-confirm"
              :disabled="regenerating"
              @click="confirmRegenerate"
            >
              {{ t('admin.accounts.fingerprint.regenerateConfirm') }}
            </button>
            <button
              type="button"
              class="btn btn-secondary"
              data-testid="fingerprint-regenerate-cancel"
              :disabled="regenerating"
              @click="confirming = false"
            >
              {{ t('admin.accounts.fingerprint.regenerateCancel') }}
            </button>
          </div>
        </div>
      </div>
    </template>
    <TotpStepUpDialog :controller="stepUp" />
  </section>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { adminAPI } from '@/api/admin'
import type { FingerprintSource, FingerprintSummary } from '@/api/admin/accounts'
import TotpStepUpDialog from '@/components/auth/TotpStepUpDialog.vue'
import { isStepUpBlocked, isStepUpCancelled, stepUpBlockedMessage, useStepUp } from '@/composables/useStepUp'
import { useAppStore } from '@/stores/app'

const props = defineProps<{ accountId: number }>()

const { t } = useI18n()
const appStore = useAppStore()
const stepUp = useStepUp()

const loading = ref(false)
const loadError = ref('')
const summary = ref<FingerprintSummary | null>(null)
const confirming = ref(false)
const regenerating = ref(false)

const tlsProfileLabel = computed(() => {
  if (!summary.value) return '—'
  const name = summary.value.tls_profile_name
  const id = summary.value.tls_profile_id
  if (name && id != null) return `${name} (#${id})`
  return name || (id != null ? String(id) : '—')
})

const tlsBindingLabel = computed(() => {
  if (summary.value?.tls_binding === 'explicit') return t('admin.accounts.fingerprint.tlsBindingExplicit')
  if (summary.value?.tls_binding === 'auto') return t('admin.accounts.fingerprint.tlsBindingAuto')
  return summary.value?.tls_binding || '—'
})

function sourceLabel(source?: FingerprintSource): string {
  if (source === 'created') return t('admin.accounts.fingerprint.sourceCreated')
  if (source === 'migrated_redis') return t('admin.accounts.fingerprint.sourceMigratedRedis')
  if (source === 'migrated_generated') return t('admin.accounts.fingerprint.sourceMigratedGenerated')
  if (source === 'regenerated') return t('admin.accounts.fingerprint.sourceRegenerated')
  return source || '—'
}

async function load(): Promise<void> {
  loading.value = true
  loadError.value = ''
  try {
    summary.value = await adminAPI.accounts.getFingerprint(props.accountId)
  } catch (error: unknown) {
    const err = error as { message?: string }
    loadError.value = err.message || t('admin.accounts.fingerprint.loadFailed')
    summary.value = null
  } finally {
    loading.value = false
  }
}

function newIdempotencyKey(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }
  return `fp-regen-${props.accountId}-${Date.now()}`
}

async function confirmRegenerate(): Promise<void> {
  const current = summary.value
  if (!current?.regenerable || typeof current.generation !== 'number') return
  regenerating.value = true
  const idempotencyKey = newIdempotencyKey()
  const expectedGeneration = current.generation
  try {
    const next = await stepUp.run(() =>
      adminAPI.accounts.regenerateFingerprint(
        props.accountId,
        { confirm: true, expected_generation: expectedGeneration },
        { idempotencyKey }
      )
    )
    summary.value = next
    confirming.value = false
    appStore.showSuccess(t('admin.accounts.fingerprint.regenerateSuccess'))
  } catch (error: unknown) {
    if (isStepUpCancelled(error)) return
    const err = error as { reason?: string; message?: string; metadata?: { current_generation?: number } }
    if (err.reason === 'FINGERPRINT_GENERATION_CONFLICT') {
      await load()
      appStore.showError(t('admin.accounts.fingerprint.generationConflict'))
      return
    }
    if (isStepUpBlocked(error)) {
      appStore.showError(stepUpBlockedMessage(error, t))
      return
    }
    appStore.showError(err.message || t('admin.accounts.fingerprint.regenerateFailed'))
  } finally {
    regenerating.value = false
  }
}

watch(
  () => props.accountId,
  () => {
    confirming.value = false
    void load()
  },
  { immediate: true }
)
</script>
