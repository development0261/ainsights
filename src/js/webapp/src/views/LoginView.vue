<script setup lang="ts">
import { ref, onBeforeMount } from "vue";
import { useRouter } from "vue-router";
import { useAuthStore } from "@/stores/auth";

const router = useRouter();

onBeforeMount(() => {
  if (window.localStorage.getItem("accessToken") !== null)
    router.push({ path: "/dashboard" });
});

const email = ref("");
const password = ref("");
const isRequesting = ref(false);

const canLogin = () => !isRequesting.value && email.value && password.value;
const auth = useAuthStore();

const login = () => {
  if (!canLogin) return;

  auth.login(email.value, password.value);
};
</script>

<template>
  <div class="login">
    <div class="field">
      <label for="email" class="label"></label>
      <div class="control">
        <input
          class="input is-primary"
          type="email"
          id="email"
          placeholder="Email"
          v-model="email"
          required
        />
      </div>
      <p class="help">Please enter your email</p>
    </div>
    <div class="field">
      <label for="password" class="label"></label>
      <div class="control">
        <input
          class="input is-primary"
          type="password"
          id="password"
          placeholder="Password"
          v-model="password"
          required
        />
      </div>
      <p class="help">Please enter your password</p>
    </div>
    <div class="control mt-2">
      <button
        @click="login"
        class="button is-primary"
        :class="{
          'is-loading': auth.isRequesting,
        }"
        :disabled="!canLogin"
      >
        Login
      </button>
    </div>
    <p class="mt-2 message is-danger">{{ auth.errors }}</p>
  </div>
</template>

<style>
.login {
  @apply h-full flex flex-col items-center justify-center;
}

.login button,
.login input {
  width: 500px;
}
</style>
