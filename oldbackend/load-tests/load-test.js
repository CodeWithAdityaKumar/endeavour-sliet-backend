import http from 'k6/http';
import { check, sleep } from 'k6';

// Backend URL target (local Hono server on port 4000 or production target)
const BASE_URL = __ENV.TARGET_URL || 'http://localhost:4000';

export const options = {
  stages: [
    { duration: '10s', target: 20 }, // Ramp-up to 20 VUs
    { duration: '20s', target: 50 }, // Sustained load at 50 VUs
    { duration: '10s', target: 100 }, // Peak stress at 100 VUs
    { duration: '10s', target: 0 },   // Ramp-down to 0 VUs
  ],
  thresholds: {
    http_req_failed: ['rate<0.05'], // HTTP errors should be under 5%
    http_req_duration: ['p(95)<500'], // 95% of requests should be below 500ms
  },
};

export default function () {
  // Test 1: Health Check Endpoint
  const healthRes = http.get(`${BASE_URL}/`);
  check(healthRes, {
    'Health Check status is 200': (r) => r.status === 200,
    'Operational message returned': (r) => r.json('status') === 'operational',
  });

  sleep(0.5);

  // Test 2: Public Settings Endpoint
  const settingsRes = http.get(`${BASE_URL}/api/settings`);
  check(settingsRes, {
    'Settings status is 200': (r) => r.status === 200,
  });

  sleep(0.5);

  // Test 3: New Candidate Registration Simulation
  const randomId = Math.floor(Math.random() * 1000000);
  const regPayload = JSON.stringify({
    Name: `LoadTest Candidate ${randomId}`,
    Email: `loadtest_${randomId}@example.com`,
    Contact: `98765${Math.floor(10005 + Math.random() * 89995)}`,
    RegNo: `26${Math.floor(1000 + Math.random() * 8999)}`,
    Tenth_Percentage: '90',
    Twelveth_Percentage: '92',
    Gender: 'Male',
    Programme: 'B.E',
    Year: 'Second',
    Branch: 'Computer',
    Photo: 'https://res.cloudinary.com/demo/image/upload/v1600000000/sample.jpg',
    Resume: 'https://res.cloudinary.com/demo/image/upload/v1600000000/sample.pdf',
    'Tech/Social_Media': 'Technical',
    Why: 'Load testing system performance with k6'
  });

  const regParams = {
    headers: {
      'Content-Type': 'application/json',
    },
  };

  const regRes = http.post(`${BASE_URL}/api/register`, regPayload, regParams);
  check(regRes, {
    'Registration status is 201 or 400': (r) => r.status === 201 || r.status === 400,
  });

  sleep(1);
}
