# Annotation cheat sheet

Full rules: `docs/annotation-protocol.md`. This file is the spreadsheet-side
quick reference -- keep open next to your CSV.

## representability_type (pick one)

  PACKAGE         vuln in a language-ecosystem package (PyPI/npm/Maven/...)
  BINARY          vuln in an installed binary / distro package / OS binary
  RUNTIME_CONFIG  exists only when a specific runtime config is in place
  SERVICE         daemon vuln where network exposure is part of exploitability
  APPLIANCE       vendor appliance (Cisco / Fortinet / F5 / VMware / etc.)
  CLOUD           cloud-account / managed-service misconfiguration
  OTHER           none of the above (explain in `notes`)

If two fit, pick the one EARLIEST in this list.

## scanner_modality (pick one)

  SBOM     OSV-Scanner / Trivy / Grype / Dependabot
  HOST     host scanner / Lynis / CIS / Tenable host plug-ins
  NETWORK  nmap / Nessus / OpenVAS / Greenbone
  RUNTIME  Falco / runtime EDR / container-runtime scanner
  CSPM     Wiz / Prisma / AWS Config / Azure Defender
  NONE     no scanner class can decide it

## common pairings

  PACKAGE        -> SBOM
  BINARY         -> HOST
  RUNTIME_CONFIG -> RUNTIME (or HOST for static configs)
  SERVICE        -> NETWORK
  APPLIANCE      -> NETWORK (or out-of-band asset inventory)
  CLOUD          -> CSPM
  OTHER          -> usually NONE

Allowed values are also encoded as the first data row of every CSV
(the row starting with `_VALID_VALUES:`). Treat that row as a header
extension, not as data.
