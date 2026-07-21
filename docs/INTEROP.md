# Third-party interoperability

wolfCert's EST (RFC 7030) and SCEP (RFC 8894) clients and test server are exercised against independent implementations under `tests/interop/`. These scripts are **hand-run and best-effort** - they are driven by the nightly `Interop` GitHub workflow (`.github/workflows/interop.yml`) but are not part of `ctest`.

## Best-effort / skip convention

Every interop script sources `tests/interop/lib/common.sh`, whose `need <bin>` helper exits **77** when a required third-party binary is missing. The workflow treats 77 as a neutral skip (a dependency that could not be installed), so a genuinely-absent tool does not fail the job. Any *other* non-zero exit is a real interop regression and fails loudly.

Because a failed dependency *build* also ends in a 77 skip (the binary never lands in `PATH`), a broken build recipe can masquerade as a green run. Keep the dependency build steps in `interop.yml` working, not just the scripts.

## Targets

| Script | Peer | What it checks |
|---|---|---|
| `openssl_pkcs7_xcheck.sh` | OpenSSL `cms`/`x509` | Lower-bound cross-check of wolfCert-produced PKCS#7 / certs. Always present. |
| `scep_micromdm.sh` | micromdm/scep (`apt install scep`) | D2 wolfcert-client -> scepserver, D1 scepclient -> wolfcert-server. |
| `est_globalsign.sh` | globalsign/est (Go) | wolfcert-client <-> globalsign estserver/estclient, both directions. |
| `est_libest.sh` | cisco/libest (built from source) | wolfcert-client -> libest estserver, libest estclient -> wolfcert-server. |
| `est_stepca.sh` | smallstep/step-ca (Go) | EST probe + SCEP enrollment against step-ca. |

## Dependency build notes

- **cisco/libest** is archived and written for OpenSSL 1.x. On a modern OpenSSL 3.0 host it needs two build tweaks (applied in `interop.yml`): `--disable-safec` (its configure now demands an explicit safec choice) and a force-included compat header defining `FIPS_mode()` / `FIPS_mode_set()` as no-ops (OpenSSL 3.0 removed both symbols, which libest still references).
- **smallstep/step-ca** links `libpcsclite` via cgo (PC/SC, for its PIV/YubiKey provisioners); install `libpcsclite-dev` before `go install`, or the build aborts at pkg-config.

## Notes

1. **micromdm D1 signed-attribute set.** `wolfcert-server`'s SCEP CertRep emits the full RFC 8894 signed-attribute set (including `recipientNonce`). On a malloc-enabled wolfSSL its PKCS#7 encoder grows the signed-attribute array on the heap past the inline `MAX_SIGNED_ATTRIBS_SZ`, so D1 passes as-is. Only a `WOLFSSL_NO_MALLOC` build needs wolfSSL rebuilt with `-DMAX_SIGNED_ATTRIBS_SZ>=9`.

2. **micromdm content encryption.** micromdm content-encrypts its `pkcsPKIEnvelope` with single DES-CBC (`1.3.14.3.2.7`), which wolfSSL compiles out by default (`NO_DES3`). The `full` CI wolfSSL build enables `--enable-des3` so `wc_PKCS7_DecodeEnvelopedData` can decode both directions.

3. **Server-side TLS is native.** The EST/SCEP test server terminates TLS itself via `--tls-cert` / `--tls-key`; no external fronting terminator is needed. Scripts mint a throwaway loopback identity for it.

4. **step-ca has no open-source EST.** RFC 7030 EST endpoints ship only in Smallstep's commercial Certificate Manager; open-source `step-ca` returns HTTP 404 on `/.well-known/est/*`. `est_stepca.sh` probes the endpoint and skips EST if absent, then exercises SCEP.

5. **step-ca needs an RSA CA for SCEP.** SCEP (RFC 8894) is RSA-only: the client encrypts the `pkcsPKIEnvelope` to the RA/CA public key with CMS key transport, and the CA decrypts it with the matching private key - neither works with an ECC key. wolfCert only builds a `KeyTransRecipientInfo` (RSA); an ECC RA cert is rejected up front with `WOLFCERT_ERR_UNSUPPORTED` (rather than failing deep in wolfSSL's encoder with `BAD_KEYWRAP_ALG_E`, `-239`). Because `step ca init` creates an **ECDSA** chain by default, `est_stepca.sh` swaps in an RSA root + intermediate (per Smallstep's own guidance) so the intermediate - which step-ca uses as the SCEP decrypter - and every cert `GetCACert` returns are RSA. The provisioner is set to AES-128-CBC (`--encryption-algorithm-identifier 1`) for the CertRep so wolfCert can decrypt it.

With the RSA chain in place the pkcsPKIEnvelope encrypts and step-ca issues the cert, but step-ca's SCEP is built on `github.com/smallstep/scep` (the micromdm library), so its CertRep carries the same `DigestInfo` signature quirk as micromdm and verifying it hits the same wolfSSL PKCS#7 gap as the micromdm interop (`VerifySignedData` / `ASN_SIG_CONFIRM_E`, `-229`). `est_stepca.sh` [2] is therefore a **strict** assertion, like the micromdm interop: it stays red until wolfSSL PR #10928 reaches `master`, then self-heals to a PASS.
