<script setup lang="ts">
import { useDomainStore } from "@/stores/domain";
import { useIpv4Store } from "@/stores/ips";
import { ref, onMounted } from "vue";

const domain = ref("");
const ipv4 = ref("");
const ports = ref("");

const domainStore = useDomainStore();
const ipv4Store = useIpv4Store();

onMounted(() => {
  domainStore.fetchUserDomains();
  ipv4Store.fetchUserIps();
});

const canRegister = () =>
  isValidDomain(domain.value) &&
  isValidIpv4(ipv4.value) &&
  isValidPort(ports.value);

const isValidDomain = (domain: string): boolean =>
  domain.match(
    /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/
  ) !== null;
const isValidIpv4 = (ipv4: string): boolean =>
  ipv4.match(/^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$/) !==
  null;
const isValidPort = (ports: string): boolean =>
  ports.match(/^\d+(,\d+)*$/) !== null;

const register = () => {
  if (!isValidDomain(domain.value)) {
    domainStore.errors = "Invalid domain name given";
    return;
  }
  if (!isValidPort(ports.value)) {
    domainStore.errors = "Invalid port(s) given";
    return;
  }
  if (!isValidIpv4(ipv4.value)) {
    domainStore.errors = "Invalid IPv4 given";
    return;
  }

  domainStore.register(domain.value);
  ipv4Store.register(ipv4.value, ports.value);
};
</script>

<template>
  <div>
    <div v-if="domainStore.domains.size > 0" class="px-4">
      <p class="mb-4 message is-info">Your registered domains.</p>
      <ul>
        <li
          class="mb-4 text-xl"
          v-for="domain in domainStore.domains.values()"
          :key="domain.id_"
        >
          <div class="flex flex-col">
            <span>{{ domain.domain }}</span>
          </div>
        </li>
      </ul>
      <p class="my-4 message is-info">Your domain scans.</p>
      <ul>
        <li v-for="scan in domainStore.scans.values()" :key="scan.id_">
          <div class="card flex flex-row justify-between px-4 py-2">
            <span>{{
              domainStore.domains.get(scan.user_domain_id)?.domain
            }}</span>
            <span>{{ scan.state }}</span>
            <span>{{ scan.created_at }}</span>
          </div>
        </li>
      </ul>
      <div class="table-container">
        <table class="table is-fullwidth is-hoverable is-striped">
          <thead>
            <tr>
              <th>Query type</th>
              <th>Query records</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="result in domainStore.scanResults.values()"
              :key="result.id_"
            >
              <td>{{ result.record_type }}</td>
              <td style="white-space: pre">
                {{ result.record_values.join("\n") }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
    <div v-if="ipv4Store.ips.size > 0" class="px-4">
      <p class="my-4 message is-info">Your registered Ipv4(s) & Port(s).</p>
      <ul>
        <li
          class="my-1 text-xl"
          v-for="ipv4 in ipv4Store.ips.values()"
          :key="ipv4.id_"
        >
          <div class="flex flex-col">
            <span>Address(s): {{ ipv4.ipv4_addrs }}</span>
            <span>Port(s): {{ ipv4.ports }}</span>
          </div>
        </li>
      </ul>
      <p class="my-4 message is-info">Your Ipv4 scans.</p>
      <ul>
        <li v-for="scan in ipv4Store.scans.values()" :key="scan.id_">
          <p>ID: {{ scan.id_ }}</p>
          <p>State: {{ scan.state }}</p>
        </li>
      </ul>
      <div class="table-container">
        <table class="table is-fullwidth is-hoverable is-striped">
          <thead>
            <tr>
              <th>Host</th>
              <th>Host State</th>
              <th>Port</th>
              <th>Protocol</th>
              <th>Port State</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="result in ipv4Store.scanResults.values()"
              :key="result.id_"
            >
              <td>{{ result.host }}</td>
              <td>{{ result.host_state }}</td>
              <td>{{ result.port }}</td>
              <td>{{ result.protocol }}</td>
              <td>{{ result.port_state }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
    <div
      v-if="domainStore.domains.size === 0"
      class="flex flex-col items-center"
    >
      <p class="mb-2 message is-info">
        No registered domains found. Please register one below.
      </p>
      <div class="field">
        <label for="domain" class="label"></label>
        <div class="control">
          <input
            class="input is-primary"
            type="text"
            id="domain"
            placeholder="google.com"
            v-model="domain"
            required
          />
        </div>
        <p class="help">Please enter your domain</p>
      </div>
      <div class="field">
        <label for="ipv4" class="label"></label>
        <div class="control">
          <input
            class="input is-primary"
            type="text"
            id="ipv4"
            placeholder="8.8.8.8"
            v-model="ipv4"
            required
          />
        </div>
        <p class="help">Please enter your IPv4 address</p>
      </div>
      <div class="field">
        <label for="ipv4" class="label"></label>
        <div class="control">
          <input
            class="input is-primary"
            type="text"
            id="ports"
            placeholder="80,443"
            v-model="ports"
            required
          />
        </div>
        <p class="help">Please enter the port(s)</p>
      </div>
      <div class="control mt-2">
        <button
          @click="register"
          class="button is-primary"
          :class="{
            'is-loading': domainStore.isRequesting || ipv4Store.isRequesting,
          }"
          :disabled="!canRegister"
        >
          Register
        </button>
      </div>
      <p class="mt-2 message is-danger">{{ domainStore.errors }}</p>
    </div>
  </div>
</template>

<style>
button,
input[type="text"] {
  width: 500px;
}
</style>
