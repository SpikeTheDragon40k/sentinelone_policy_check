# SentinelOne Policy Exporter & Compliance Checker

A secure, OS-agnostic tool written in pure Python (standard library only) that
exports SentinelOne group policies from one or more consoles and verifies them
against an organizational security baseline (`policy_matrix.txt`).

Works on **Linux, macOS and Windows**. No third-party dependencies.

## Features

- **Multi-tenant support** — export several SentinelOne consoles in a single run
- **Complete policy export** — raw JSON per group plus flattened CSVs (per account and global)
- **Built-in compliance check** — produces a single CSV listing only the **non-compliant**
  policies, each attributed to its `Tenant → Account → Site → Group`, so every
  divergence from the baseline is immediately visible and actionable
- **No hardcoded secrets** — API tokens are read from environment variables
  (`.env` supported), never stored in the script or committed to repositories
- **Robust by design** — TLS certificate verification enforced, automatic retries
  with backoff for rate limits and network errors, configurable timeouts,
  safe file names, and response validation
- **Zero dependencies** — runs with the Python standard library on any platform

## Requirements

- Python **3.9+**
- A SentinelOne **API token** with read access (`Console → Settings → API Token`)

## Installation

```bash
git clone https://github.com/SpikeTheDragon40k/sentinelone_policy_check
cd sentinelone_policy_check

# Set up your environment (single tenant)
cp .env.example .env
```

Edit `.env` and fill in your token and tenant URL:

```
S1_API_TOKEN=<your-token>
S1_TENANT_URL=https://<your-console>.sentinelone.net/web/api/v2.1
S1_BASELINE=./policy_matrix.txt
```

## Usage

```bash
python3 sentinelone_export.py
```

Or pass everything explicitly:

```bash
S1_API_TOKEN=<token> \
S1_TENANT_URL=https://<console>.sentinelone.net/web/api/v2.1 \
python3 sentinelone_export.py \
  --output ./SentinelOne_Policies \
  --baseline ./policy_matrix.txt
```

### Command-line options

| Option | Description |
| --- | --- |
| `-o, --output <dir>` | Output directory (default: `./SentinelOne_Policies`) |
| `-b, --baseline <file>` | Path to the baseline CSV (default: `$S1_BASELINE`) |
| `--no-compliance` | Skip the compliance check |
| `--timeout <sec>` | HTTP request timeout (default: 30) |
| `--retries <n>` | Retries per API call (default: 3) |
| `-v, --verbose` | Verbose logging |

## Configuration reference

### Single tenant

| Variable | Description |
| --- | --- |
| `S1_API_TOKEN` | SentinelOne API token |
| `S1_TENANT_URL` | Tenant API base URL, e.g. `https://euce1-109.sentinelone.net/web/api/v2.1` |

### Multi tenant

Sets both variables to export multiple consoles in a single run (this overrides
the single-tenant variables):

| Variable | Description |
| --- | --- |
| `S1_API_TOKENS` | JSON object mapping tenant name → token |
| `S1_TENANT_URLS` | JSON object mapping tenant name → base URL |

Example:

```bash
S1_API_TOKENS='{"euce1-104":"token_1","euce1-109":"token_2"}'
S1_TENANT_URLS='{"euce1-104":"https://euce1-104.sentinelone.net/web/api/v2.1","euce1-109":"https://euce1-109.sentinelone.net/web/api/v2.1"}'
```

### Optional

| Variable | Description |
| --- | --- |
| `S1_OUTPUT_DIR` | Output directory (default: `./SentinelOne_Policies`) |
| `S1_BASELINE` | Path to the baseline CSV (e.g. `./policy_matrix.txt`) |
| `S1_TIMEOUT` | HTTP request timeout in seconds (default: 30) |
| `S1_RETRIES` | Max retries per API call (default: 3) |

A `config.example.json` is also provided as a reference for tenant URL layout;
tokens are always supplied through environment variables.

## Output

```
SentinelOne_Policies/
├── <tenant>/
│   ├── <Account>/
│   │   ├── <Site>_<Group>_<groupId>.json      # raw group policy
│   │   └── <Account>_Policies.csv             # flattened policy rows
│   └── <tenant>_AllPolicies.csv               # global CSV (all groups)
└── non_compliant_policies.csv                 # only non-compliant settings
```

CSVs use `;` as the field delimiter (Excel-friendly).

## Compliance check

The baseline `policy_matrix.txt` is a static CSV with the format
`Section;Setting;Default Value;ExpectedValue`, defining the target
configuration for the estate. The script compares every exported group policy
against it and writes **one** comparison file, `non_compliant_policies.csv`,
containing only the settings that differ — with full `Tenant`, `Account`, `Site`
and `Group` context so each deviation is attributable to a specific policy.

Example row:

```
euce1-109;Acme Corp;HQ Site;Servers - Production;Protection Mode;Suspicious Threats;Detect;Protect
```

**Columns:** `Tenant;AccountName;SiteName;GroupName;Section;Setting;CurrentValue;ExpectedValue`

Keep the baseline up to date: whenever new settings or values appear in the
console, update `policy_matrix.txt` accordingly.

## License

GNU 3.0
