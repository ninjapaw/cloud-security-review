import { defineConfig } from 'astro/config';
import react from '@astrojs/react';

export default defineConfig({
  output: 'static',
  markdown: { syntaxHighlight: false },
  integrations: [react()],
  security: {
    csp: {
      directives: [
        "default-src 'self'",
        "connect-src 'self'",
        "frame-src 'self' blob:",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
      ],
      styleDirective: { resources: ["'self'", "'unsafe-inline'"] },
    },
  },
});
