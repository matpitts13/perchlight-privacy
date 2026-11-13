// The config the tests run against: one site from "privacy.json"; most tests add sites through the API.
export const TEST_CONFIG = {
  sites: {
    cfg: { host: "config-site.com", pages: ["/about"], every: "1d" },
  },
  alerts: { email: ["ops@example.com"], webhooks: ["discord", "json"] },
  retention: { scansPerSite: 5 },
};
