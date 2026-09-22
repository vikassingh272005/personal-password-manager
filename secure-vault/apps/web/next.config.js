/** @type {import('next').NextConfig} */

// The web app proxies /api/* to the Rust API. In local development that is
// localhost:3001 (the dev launcher's default); in containerized deployments
// the web container reaches the API over the compose network as
// http://api:3001. Configure with API_ORIGIN when running `next start`.
const API_ORIGIN = process.env.API_ORIGIN || 'http://localhost:3001';

const nextConfig = {
  reactStrictMode: true,
  // Emit .next/standalone for the production container (docker/web.Dockerfile).
  output: 'standalone',
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${API_ORIGIN}/api/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
