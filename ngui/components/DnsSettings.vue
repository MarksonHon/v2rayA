<script lang="ts" setup>
const { t } = useI18n()

interface DnsServerEntry {
  address: string
  domains: string[]
  outbound: string
}

const props = defineProps<{
  modelValue: DnsServerEntry[]
  dnsMode: string
  nodeResolveDns: string
}>()

const emit = defineEmits<{
  'update:modelValue': [value: DnsServerEntry[]]
  'update:dnsMode': [value: string]
  'update:nodeResolveDns': [value: string]
}>()

const dialogVisible = $ref(false)

// 本地编辑副本
let localServers = $ref<DnsServerEntry[]>([])
let localDnsMode = $ref('')
let localNodeResolveDns = $ref('')

const open = () => {
  localServers = JSON.parse(JSON.stringify(props.modelValue ?? []))
  localDnsMode = props.dnsMode ?? 'UseIP'
  localNodeResolveDns = props.nodeResolveDns ?? ''
  dialogVisible = true
}

defineExpose({ open })

const addRow = () => {
  localServers.push({ address: '', domains: [], outbound: 'direct' })
}

const removeRow = (index: number) => {
  localServers.splice(index, 1)
}

// domains 字段每行一条，也允许逗号分隔
const domainsToStr = (domains: string[]) => (domains ?? []).join('\n')

const strToDomains = (str: string): string[] => {
  if (!str || str.trim() === '')
    return []
  // 支持换行或逗号作为分隔符
  return str.split(/[\n,]/).map(s => s.trim()).filter(Boolean)
}

const handleDomainInput = (index: number, val: string) => {
  localServers[index].domains = strToDomains(val)
}

const confirm = () => {
  emit('update:modelValue', JSON.parse(JSON.stringify(localServers)))
  emit('update:dnsMode', localDnsMode)
  emit('update:nodeResolveDns', localNodeResolveDns)
  dialogVisible = false
}
</script>

<template>
  <ElDialog v-model="dialogVisible" :title="$t('dns.title')" width="720px" destroy-on-close>
    <div class="mb-4">
      <span class="mr-2 font-medium">{{ $t('dns.queryStrategy') }}</span>
      <ElSelect v-model="localDnsMode" size="small">
        <ElOption value="UseIP" label="UseIP" />
        <ElOption value="UseIPv4" label="UseIPv4" />
        <ElOption value="UseIPv6" label="UseIPv6" />
      </ElSelect>
    </div>

    <ElTable :data="localServers" border size="small">
      <ElTableColumn :label="$t('dns.server')" min-width="200">
        <template #default="{ row }">
          <ElInput v-model="row.address" size="small" :placeholder="$t('dns.serverPlaceholder')" />
        </template>
      </ElTableColumn>

      <ElTableColumn :label="$t('dns.domains')" min-width="220">
        <template #default="{ row, $index }">
          <ElInput
            type="textarea"
            :autosize="{ minRows: 1, maxRows: 6 }"
            size="small"
            :model-value="domainsToStr(row.domains)"
            :placeholder="$t('dns.domainsPlaceholder')"
            @update:model-value="handleDomainInput($index, $event)"
          />
        </template>
      </ElTableColumn>

      <ElTableColumn :label="$t('dns.outbound')" width="130">
        <template #default="{ row }">
          <ElSelect v-model="row.outbound" size="small">
            <ElOption value="direct" :label="$t('dns.direct')" />
            <ElOption value="proxy" :label="$t('dns.proxy')" />
          </ElSelect>
        </template>
      </ElTableColumn>

      <ElTableColumn :label="$t('operations.name')" width="72" align="center">
        <template #default="{ $index }">
          <ElButton type="danger" size="small" @click="removeRow($index)">
            {{ $t('operations.delete') }}
          </ElButton>
        </template>
      </ElTableColumn>
    </ElTable>

    <ElButton class="mt-3" size="small" @click="addRow">
      + {{ $t('dns.addServer') }}
    </ElButton>

    <div class="mt-4">
      <div class="mb-1 font-medium">{{ $t('dns.nodeResolveDns') }}</div>
      <div class="mb-2 text-xs text-gray-500">{{ $t('dns.nodeResolveDnsHint') }}</div>
      <ElInput
        v-model="localNodeResolveDns"
        size="small"
        :placeholder="$t('dns.nodeResolveDnsPlaceholder')"
      />
    </div>

    <template #footer>
      <ElButton @click="dialogVisible = false">{{ $t('operations.cancel') }}</ElButton>
      <ElButton type="primary" @click="confirm">{{ $t('operations.confirm') }}</ElButton>
    </template>
  </ElDialog>
</template>
