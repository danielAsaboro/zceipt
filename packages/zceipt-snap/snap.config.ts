import type { SnapConfig } from '@metamask/snaps-cli';
import { resolve } from 'path';

const config: SnapConfig = {
  input: resolve(__dirname, 'src/index.tsx'),
  server: { port: 8080 },
  polyfills: { buffer: false },
  customizeWebpackConfig: (config) => {
    // The Zceipt wasm rides inside the bundle: a snap can't fetch files.
    config.module?.rules?.push({ test: /\.wasm$/, type: 'asset/inline' });
    return config;
  },
};

export default config;
