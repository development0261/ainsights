<script setup lang="ts">
import { useAuthStore } from "@/stores/auth";

const auth = useAuthStore();
</script>

<template>
  <div class="flex flex-col items-center">
    <div class="field">
      <label for="user_id" class="label">User ID</label>
      <div class="control">
        <input
          class="input is-primary"
          type="text"
          id="user_id"
          required
          disabled
          :value="auth.user.user_id"
        />
      </div>
      <p class="help">Your unique user id.</p>
    </div>
    <div class="field">
      <label for="email" class="label">Email</label>
      <div class="control">
        <input
          class="input is-primary"
          type="email"
          id="email"
          placeholder="Email"
          required
          disabled
          :value="auth.user.email"
        />
      </div>
      <p class="help">Your registered email address.</p>
    </div>
  </div>
</template>

<style>
input[type="email"] {
  width: 500px;
}
</style>
