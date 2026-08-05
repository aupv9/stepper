// k6 load test for the IAM gateway hot path (cache-hit introspection).
//
// Usage:
//   1. Start the gateway in dev mode:  make service
//   2. Export a dev token from the logs: export IAM_TOKEN=<token>
//   3. k6 run -e BASE_URL=http://localhost:8080 -e IAM_TOKEN=$IAM_TOKEN loadtest/k6.js
//
// Thresholds encode the performance budget: p99 < 20ms end-to-end on the
// cache-hit path, <1% errors. Tune to your hardware before gating CI on it.
import http from "k6/http";
import { check } from "k6";

const BASE_URL = __ENV.BASE_URL || "http://localhost:8080";
const TOKEN = __ENV.IAM_TOKEN || "";

export const options = {
  scenarios: {
    steady: {
      executor: "constant-arrival-rate",
      rate: 200,
      timeUnit: "1s",
      duration: "30s",
      preAllocatedVUs: 50,
    },
  },
  thresholds: {
    http_req_duration: ["p(99)<20"],
    http_req_failed: ["rate<0.01"],
  },
};

export default function () {
  const authed = http.get(`${BASE_URL}/api/public`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
  });
  check(authed, {
    "authorized request succeeds": (r) => r.status === 200,
  });

  const denied = http.get(`${BASE_URL}/api/public`);
  check(denied, {
    "unauthenticated request challenged": (r) =>
      r.status === 401 && r.headers["Www-Authenticate"] !== undefined,
  });
}
