<script setup lang="ts">
import { useAuthStore } from "@/stores/auth";
import { RouterView, RouterLink } from "vue-router";

const auth = useAuthStore();
</script>

<template>
  <div class="dashboard">
    <nav class="navbar" role="navigation" aria-label="main navigation">
      <div class="navbar-end">
        <div class="navbar-item">
          <div class="buttons">
            <!-- <a @click.prevent="logout" class="button is-light"> Log out </a> -->
          </div>
        </div>
      </div>
    </nav>

    <aside class="menu">
      <p class="menu-label">General</p>
      <ul class="menu-list">
        <li><RouterLink to="/dashboard/cyberrisk">Cyber Risk</RouterLink></li>
      </ul>
      <p class="menu-label">Account</p>
      <ul class="menu-list">
        <li><RouterLink to="/dashboard/profile">Profile</RouterLink></li>
        <li><a @click.prevent="auth.logout">Logout</a></li>
      </ul>
    </aside>

    <RouterView class="subapp" />
  </div>
</template>

<style>
.dashboard {
  width: 100%;
  height: 100%;

  display: grid;

  grid-template-columns: 144px auto;
  grid-template-rows: 80px auto;
}

.navbar,
.menu,
.subapp {
  padding: 0.5rem;
}

.navbar {
  grid-column: 1 / -1;
  grid-row: 1 / 1;

  display: flex;
  flex-direction: row;
  align-items: center;
  justify-content: flex-end;
}

.menu {
  grid-column: 1 / 1;
  grid-row: 2 / 2;
}

.subapp {
  grid-column: 2 / 2;
  grid-row: 2 / 2;
}
</style>
