import { defineStore } from "pinia";
import router from "../router";

interface AuthUser {
  id_: string;
  email: string;
  access_token: string;
}

export const useAuthStore = defineStore({
  id: "authStore",
  state: () => ({
    user: JSON.parse(localStorage.getItem("user") || "{}"),
    errors: "",
    isRequesting: false,
    returnUrl: "/dashboard/cyberrisk",
  }),
  getters: {
    isAuthenticated: (state) => Object.keys(state.user).length !== 0,
  },

  actions: {
    logout() {
      this.user = {};
      localStorage.removeItem("user");

      router.push({ path: "/login" });
    },

    login(email: string, password: string) {
      this.isRequesting = true;
      this.errors = "";

      const baseUrl = import.meta.env.VITE_API_URL;
      fetch(`${baseUrl || ""}/api/v1/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: email,
          password: password,
        }),
      })
        .then((response) => {
          if (response.status === 201) return response.json();
          throw new Error();
        })
        .then((auth: AuthUser) => {
          this.isRequesting = false;
          this.user = auth;

          window.localStorage.setItem("user", JSON.stringify(auth));

          router.push({ path: this.returnUrl });
        })
        .catch((err) => {
          this.errors = "Invalid email/password";
        })
        .finally(() => {
          this.isRequesting = false;
        });
    },
  },
});
