# Release integrity and verification

Maelys Sandbox Policy releases use three independent integrity layers:

1. a maintainer-signed annotated Git tag authorizes the release;
2. adjacent SHA-256 files detect changes to downloaded assets;
3. GitHub artifact attestations bind each asset to this repository, workflow
   and source commit through keyless Sigstore provenance.

Verify an archive with:

```sh
sha256sum -c maelys-sandbox-policy-0.4.0-linux-x86_64.tar.gz.sha256
gh attestation verify maelys-sandbox-policy-0.4.0-linux-x86_64.tar.gz \
  --repo maelys-dev/maelys-sandbox-policy
```

On macOS use `shasum -a 256` and compare the recorded value. `SHA256SUMS` in
the GitHub release covers all tarballs, Debian packages and RPM packages.

Linux publishes a runtime package containing `maelys-policy` and a development
package containing the two static libraries, public headers, schema and
pkg-config metadata. The platform tarball contains the same complete install
tree under `/usr/local`.
