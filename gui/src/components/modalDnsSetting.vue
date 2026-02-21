<template>
  <div class="modal-card dns-modal">
    <header class="modal-card-head">
      <p class="modal-card-title">{{ $t("dns.title") }}</p>
    </header>
    <section class="modal-card-body">
      <!-- queryStrategy -->
      <b-field :label="$t('dns.queryStrategy')" horizontal custom-class="dns-field-label">
        <b-select v-model="localDnsMode" size="is-small">
          <option value="UseIP">UseIP</option>
          <option value="UseIPv4">UseIPv4</option>
          <option value="UseIPv6">UseIPv6</option>
        </b-select>
      </b-field>

      <!-- nodeResolveDns -->
      <b-field
        :label="$t('dns.nodeResolveDns')"
        :message="$t('dns.nodeResolveDnsHint')"
        horizontal
        custom-class="dns-field-label"
      >
        <input
          v-model="localNodeResolveDns"
          class="input is-small"
          style="max-width: 380px"
          :placeholder="$t('dns.nodeResolveDnsPlaceholder')"
        />
      </b-field>

      <!-- DNS server table -->
      <table class="table is-bordered is-fullwidth is-narrow dns-table">
        <thead>
          <tr>
            <th>{{ $t("dns.server") }}</th>
            <th>{{ $t("dns.domains") }}</th>
            <th style="width: 160px">{{ $t("dns.outbound") }}</th>
            <th style="width: 60px">{{ $t("operations.name") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(row, index) in localServers" :key="index">
            <td>
              <input
                v-model="row.address"
                class="input is-small"
                :placeholder="$t('dns.serverPlaceholder')"
              />
            </td>
            <td>
              <textarea
                v-model="row.domainsStr"
                class="textarea is-small dns-domains-textarea"
                :placeholder="$t('dns.domainsPlaceholder')"
                rows="2"
              ></textarea>
            </td>
            <td>
              <div class="select is-small is-fullwidth">
                <select v-model="row.outbound">
                  <option value="direct">{{ $t("dns.direct") }}</option>
                  <option v-for="tag in outboundTags" :key="tag" :value="tag">{{ tag }}</option>
                </select>
              </div>
            </td>
            <td class="has-text-centered">
              <button class="button is-danger is-small" @click="removeRow(index)">
                {{ $t("operations.delete") }}
              </button>
            </td>
          </tr>
        </tbody>
      </table>

      <button class="button is-small" style="margin-top: 8px" @click="addRow">
        + {{ $t("dns.addServer") }}
      </button>
    </section>
    <footer class="modal-card-foot flex-end">
      <button class="button" @click="$emit('close')">
        {{ $t("operations.cancel") }}
      </button>
      <button class="button is-primary" @click="handleClickSubmit">
        {{ $t("operations.save") }}
      </button>
    </footer>
  </div>
</template>

<script>
export default {
  name: "ModalDnsSetting",
  props: {
    dnsServers: {
      type: Array,
      default: () => [],
    },
    dnsMode: {
      type: String,
      default: "UseIP",
    },
    nodeResolveDns: {
      type: String,
      default: "",
    },
  },
  data() {
    return {
      localServers: [],
      localDnsMode: "UseIP",
      localNodeResolveDns: "",
      outboundTags: [],
    };
  },
  created() {
    const servers = this.dnsServers && this.dnsServers.length
      ? this.dnsServers
      : [
          { address: "localhost", domains: ["geosite:private"], outbound: "direct" },
          { address: "119.29.29.29", domains: ["geosite:cn"], outbound: "direct" },
          { address: "8.8.8.8", domains: [], outbound: "direct" },
        ];
    // 将 domains 数组转成每行一条的原始字符串，在编辑期间不做解析
    this.localServers = servers.map((s) => ({
      ...JSON.parse(JSON.stringify(s)),
      domainsStr: (s.domains || []).join("\n"),
    }));
    this.localDnsMode = this.dnsMode || "UseIP";
    this.localNodeResolveDns = this.nodeResolveDns || "";
    // 加载出站列表（排除 direct/block 等内置标签）
    this.$axios({ url: apiRoot + "/outbounds" }).then((res) => {
      if (res.data && res.data.code === "SUCCESS" && res.data.data.outbounds) {
        this.outboundTags = res.data.data.outbounds.filter(
          (tag) => tag !== "direct" && tag !== "block" && tag !== "dns-out"
        );
      }
    });
  },
  methods: {
    strToDomains(str) {
      if (!str || str.trim() === "") return [];
      return str.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
    },
    addRow() {
      this.localServers.push({ address: "", domains: [], domainsStr: "", outbound: "direct" });
    },
    removeRow(index) {
      this.localServers.splice(index, 1);
    },
    handleClickSubmit() {
      // 提交时才将原始字符串解析成 domains 数组
      const dnsServers = this.localServers.map(({ domainsStr, ...rest }) => ({
        ...rest,
        domains: this.strToDomains(domainsStr),
      }));
      this.$emit("update-dns", {
        dnsServers,
        dnsMode: this.localDnsMode,
        nodeResolveDns: this.localNodeResolveDns,
      });
      this.$emit("close");
    },
  },
};
</script>

<style lang="scss" scoped>
.dns-modal {
  width: 65rem;
  max-width: 95vw;
}

.dns-table {
  font-size: 13px;

  th {
    font-weight: 600;
  }

  td {
    vertical-align: middle;
    padding: 4px 6px;
  }

  .dns-domains-textarea {
    font-size: 12px;
    min-height: 56px;
    resize: vertical;
    line-height: 1.4;
  }
}

.dns-field-label {
  width: 7em;
  padding: 0 !important;
  text-align: left !important;
}
</style>
