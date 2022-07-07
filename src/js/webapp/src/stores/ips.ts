import { defineStore } from "pinia";
import { useAuthStore } from "./auth";

interface Ipv4 {
  id_: string;
  user_id: string;
  ipv4_addrs: string;
  ports: string;
  created_at: string;
  updated_at: string;
}

interface Ipv4Scan {
  id_: string;
  state: string;
}

interface PortScanResult {
  id_: string;
  scan_id: string;
  host: string;
  host_state: string;
  port: string;
  port_state: string;
  protocol: string;
}

export const useIpv4Store = defineStore({
  id: "ipv4Store",
  state: () => ({
    ips: new Map<string, Ipv4>(),
    scans: new Map<string, Ipv4Scan>(),
    scanResults: new Map<string, PortScanResult>(),
    errors: "",
    isRequesting: false,
  }),
  getters: {},
  actions: {
    register(ipv4Addrs: string, ports: string) {
      const auth = useAuthStore();

      const baseUrl = import.meta.env.VITE_API_URL;
      fetch(`${baseUrl || ""}/api/v1/ips`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${auth.user.access_token}`,
        },
        body: JSON.stringify({
          ipv4_addrs: ipv4Addrs,
          ports: ports,
        }),
      })
        .then((response) => {
          if (response.status === 201) return response.json();
          throw new Error();
        })
        .then((ipv4s: Array<Ipv4>) => {
          ipv4s.forEach((ipv4) => this.ips.set(ipv4.id_, ipv4));
        })
        .catch((err) => {
          this.errors = "Invalid IPv4 or Port(s)";
        })
        .finally(() => {
          this.isRequesting = false;
        });
    },
    fetchUserIps() {
      const auth = useAuthStore();
      this.isRequesting = true;
      this.errors = "";

      const baseUrl = import.meta.env.VITE_API_URL;
      fetch(`${baseUrl || ""}/api/v1/ips`, {
        method: "GET",
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${auth.user.access_token}`,
        },
      })
        .then((response) => {
          if (response.status !== 200) throw new Error();
          return response.json();
        })
        .then((ips: Array<Ipv4>) => {
          ips.forEach((ip) => this.ips.set(ip.id_, ip));
          this.fetchIpScans();
        })
        .catch((err) => {
          this.errors = err;
        })
        .finally(() => {
          this.isRequesting = false;
        });
    },
    fetchIpScans() {
      const auth = useAuthStore();
      this.isRequesting = true;
      this.errors = "";

      const baseUrl = import.meta.env.VITE_API_URL;
      Promise.all(
        Array.from(this.ips.values()).map((ipv4) => {
          return fetch(`${baseUrl || ""}/api/v1/ips/${ipv4.id_}/scans`, {
            method: "GET",
            headers: {
              Accept: "application/json",
              Authorization: `Bearer ${auth.user.access_token}`,
            },
          })
            .then((response) => {
              if (response.status !== 200) throw new Error();
              return response.json();
            })
            .then((scans: Array<Ipv4Scan>) => {
              scans.forEach((scan) => this.scans.set(scan.id_, scan));
            })
            .catch((err) => {
              this.errors = err;
            })
            .finally(() => {
              this.isRequesting = false;
            });
        })
      ).finally(() => {
        this.fetchScanResults();
      });
    },
    fetchScanResults() {
      const auth = useAuthStore();
      this.isRequesting = true;
      this.errors = "";

      const baseUrl = import.meta.env.VITE_API_URL;
      this.scans.forEach((scan) => {
        fetch(`${baseUrl || ""}/api/v1/port_scans/${scan.id_}/results`, {
          method: "GET",
          headers: {
            Accept: "application/json",
            Authorization: `Bearer ${auth.user.access_token}`,
          },
        })
          .then((response) => {
            if (response.status !== 200) throw new Error();
            return response.json();
          })
          .then((results: Array<PortScanResult>) => {
            results.forEach((result) =>
              this.scanResults.set(result.id_, result)
            );
          })
          .catch((err) => {
            this.errors = err;
          })
          .finally(() => {
            this.isRequesting = false;
          });
      });
    },
  },
});
