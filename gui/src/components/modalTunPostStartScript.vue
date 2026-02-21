<template>
  <div class="modal-card" style="max-width: 500px; margin: auto">
    <header class="modal-card-head">
      <p class="modal-card-title">{{ $t("setting.tunPostStartScript") }}</p>
    </header>
    <section class="modal-card-body">
      <b-message type="is-warning" style="margin-bottom: 1rem">
        {{ $t("setting.messages.tunPostStartScript") }}
      </b-message>
      <b-field>
        <b-input
          v-model="localScript"
          type="textarea"
          :placeholder="$t('setting.tunPostStartScriptPlaceholder')"
          custom-class="code-font"
          rows="10"
        />
      </b-field>
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
  name: "modalTunPostStartScript",
  props: {
    script: {
      type: String,
      default: "",
    },
  },
  data() {
    return {
      localScript: this.script,
    };
  },
  methods: {
    handleClickSubmit() {
      this.$emit("update-script", this.localScript);
      this.$emit("close");
    },
  },
};
</script>
