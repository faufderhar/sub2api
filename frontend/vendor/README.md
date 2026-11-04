# frontend/vendor

Third-party packages committed to the repo as offline tarballs, so installs and builds (including Docker and offline environments) never hit external CDNs.

## xlsx-0.20.3.tgz (SheetJS Community Edition)

- Version: 0.20.3
- Source URL: https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz
  (SheetJS stopped publishing new versions to the npm registry after 0.18.5; official releases are on cdn.sheetjs.com only)
- License: Apache-2.0
- Referenced as: `frontend/package.json` -> `"xlsx": "file:vendor/xlsx-0.20.3.tgz"`, with the integrity locked in `pnpm-lock.yaml`
- Size: 2409319 bytes
- sha512 integrity (SRI, matches the `resolution.integrity` field in pnpm-lock.yaml):
  `sha512-oLDq3jw7AcLqKWH2AhCpVTZl8mf6X2YReP+Neh0SJUzV/BdZYjth94tG5toiMB1PPrYtxOCfaoUCkvtuH+3AJA==`
- sha256:
  `8dc73fc3b00203e72d176e85b50938627c7b086e607c682e8d3c22c02bb99fe8`

Verify:

```bash
cd frontend/vendor
sha256sum xlsx-0.20.3.tgz
echo "sha512-$(openssl dgst -sha512 -binary xlsx-0.20.3.tgz | base64 -w0)"
```

Upgrade steps: download the new version's tgz from the official URL above into this directory, update the file name in package.json, run `pnpm install` to refresh the lockfile, then update the version and checksums in this file.
