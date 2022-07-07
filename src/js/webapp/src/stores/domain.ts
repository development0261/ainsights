import { defineStore } from "pinia";
import { useAuthStore } from "./auth";

interface Domain {
  id_: string;
  user_id: string;
  domain: string;
  created_at: string;
  updated_at: string;
}

interface Scan {
  id_: string;
  state: string;
  user_domain_id: string;
  created_at: string;
  updated_at: string;
}

interface ScanResult {
  id_: string;
  scan_id: string;
  record_type: string;
  record_value: string;
}

interface ScanResultSet {
  id_: string;
  scan_id: string;
  record_type: string;
  record_values: Array<string>;
}

export const useDomainStore = defineStore({
  id: "domainStore",
  state: () => ({
    domains: new Map<string, Domain>(),
    scans: new Map<string, Scan>(),
    scanResults: new Map<string, ScanResultSet>(),
    errors: "",
    isRequesting: false,
  }),
  getters: {},
  actions: {
    register(domain: string) {
      const auth = useAuthStore();

      const baseUrl = import.meta.env.VITE_API_URL;
      fetch(`${baseUrl || ""}/api/v1/domains`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${auth.user.access_token}`,
        },
        body: JSON.stringify({
          domain: domain,
        }),
      })
        .then((response) => {
          if (response.status === 201) return response.json();
          throw new Error();
        })
        .then((domains: Array<Domain>) => {
          domains.forEach((domain) => this.domains.set(domain.id_, domain));
        })
        .catch((err) => {
          this.errors = "Invalid domain";
        })
        .finally(() => {
          this.isRequesting = false;
        });
    },
    fetchUserDomains() {
      const auth = useAuthStore();
      this.isRequesting = true;
      this.errors = "";

      const baseUrl = import.meta.env.VITE_API_URL;
      fetch(`${baseUrl || ""}/api/v1/domains`, {
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
        .then((domains: Array<Domain>) => {
          domains.forEach((domain) => this.domains.set(domain.id_, domain));
          this.fetchDomainScans();
        })
        .catch((err) => {
          this.errors = err;
        })
        .finally(() => {
          this.isRequesting = false;
        });
    },

    fetchDomainScans() {
      const auth = useAuthStore();
      this.isRequesting = true;
      this.errors = "";

      const baseUrl = import.meta.env.VITE_API_URL;
      Promise.all(
        Array.from(this.domains.values()).map((domain) => {
          return fetch(`${baseUrl || ""}/api/v1/domains/${domain.id_}/scans`, {
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
            .then((scans: Array<Scan>) => {
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
        fetch(`${baseUrl || ""}/api/v1/domain_scans/${scan.id_}/results`, {
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
          .then((results: Array<ScanResult>) => {
            let resultSet: Array<ScanResultSet> = [];
            for (let result of results) {
              let found = false;
              for (let rs of resultSet) {
                if (result.record_type === rs.record_type) {
                  rs.record_values.push(result.record_value);
                  found = true;
                  break;
                }
              }
              if (!found)
                resultSet.push({
                  id_: result.id_,
                  scan_id: result.scan_id,
                  record_type: result.record_type,
                  record_values: [result.record_value],
                });
            }
            resultSet.forEach((rs) => this.scanResults.set(rs.id_, rs));
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
