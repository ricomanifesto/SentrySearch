# Supabase database trust

`supabase-prod-ca-2021.crt` is the public **Supabase Root 2021 CA**. It contains
no private key or credentials. It is an explicit database trust anchor, not a
replacement for the operating system's certificate store.

## Provenance

- Downloaded over verified HTTPS on 2026-10-04 from
  [Supabase's production CA download](https://supabase-downloads.s3-ap-southeast-1.amazonaws.com/prod/ssl/prod-ca-2021.crt).
- The URL is published in the [Supabase dashboard's certificate configuration](https://github.com/supabase/supabase/blob/b2cf3693dd74216ecc27506390931d35dc929c9c/apps/studio/hooks/custom-content/custom-content.json).
- [Supabase's SSL guidance](https://supabase.com/docs/guides/platform/ssl-enforcement)
  recommends `verify-full` with the downloaded CA.
- Subject and issuer: `C=US, ST=Delware, L=New Castle, O=Supabase Inc, CN=Supabase Root 2021 CA`
  (`Delware` is spelled this way in the certificate).
- Validity: 2021-04-28 10:56:53 UTC through 2031-04-26 10:56:53 UTC.
- Certificate SHA-256 (DER):
  `807025ad50d4ed219d2c9c7d299c004f824eb00cf7f65afef607d07b72e6cafa`
- File SHA-256 (PEM):
  `700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7`

The download's certificate was verified against the Supabase session pooler on
2026-10-04 using a PostgreSQL TLS handshake with both chain and hostname checks.
The system trust store alone did not trust that chain. This check used no database
credentials and made no SQL requests.

## Deployment and renewal

See [Railway database TLS configuration](../docs/storage-release.md#railway-database-tls).
Keep this certificate in the deployed source tree. There is no startup download,
implicit CA fallback, or change to `verify-full`.

For CA rotation, retrieve the replacement from Supabase's official dashboard
source over verified HTTPS, review its identity and validity, verify the deployed
hostname against it, and update this file and the pinned fingerprint test together.
Review any trust overlap explicitly; do not trust a certificate merely because
the database endpoint presents it. Rebuild the image and verify readiness after
the approved change. Do not replace this root with a short-lived leaf certificate.
