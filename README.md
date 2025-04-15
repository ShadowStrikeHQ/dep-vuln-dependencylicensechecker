# dep-vuln-DependencyLicenseChecker
A command-line tool that analyzes project dependencies and flags those with licenses incompatible with a specified policy (e.g., GPL dependencies in a commercial project). Uses SPDX license identifiers and the 'license-expression' library for evaluation. - Focused on Maps declared software dependencies in project manifest files (e.g., requirements.txt, package.json) to known vulnerabilities in public databases (e.g., NIST NVD, OSV). Generates a report detailing vulnerable dependencies and suggested remediation steps, such as updating to patched versions. Supports multiple dependency file formats and vulnerability data sources.

## Install
`git clone https://github.com/ShadowStrikeHQ/dep-vuln-dependencylicensechecker`

## Usage
`./dep-vuln-dependencylicensechecker [params]`

## Parameters
- `-h`: Show help message and exit
- `--license_policy`: No description provided
- `--vulnerability_db`: No description provided
- `--output`: No description provided

## License
Copyright (c) ShadowStrikeHQ
