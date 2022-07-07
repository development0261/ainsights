import { useAuthStore } from "@/stores/auth";
import { createRouter, createWebHistory } from "vue-router";
import LoginView from "../views/LoginView.vue";

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: "/",
      name: "home",
      redirect: "/login",
    },
    {
      path: "/login",
      name: "login",
      component: LoginView,
    },
    {
      path: "/dashboard",
      name: "dashboard",
      component: () => import("../views/DashboardView.vue"),
      children: [
        {
          path: "cyberrisk",
          component: () => import("../components/Cyberrisk.vue"),
        },
        {
          path: "profile",
          component: () => import("../components/Profile.vue"),
        },
      ],
    },
  ],
});

router.beforeEach((to) => {
  const auth = useAuthStore();

  if (auth.isAuthenticated && to.path === "/login") {
    return "/dashboard";
  }

  if (!auth.isAuthenticated && to.path !== "/login") {
    auth.returnUrl = to.fullPath;
    return "/login";
  }
});

export default router;
