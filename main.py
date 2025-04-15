import argparse
import logging
import json
import os
import sys
from typing import List, Dict, Any
from packaging import requirements
import requests

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API_BASE_URL = "https://api.osv.dev/v1/query"

class DependencyVulnerabilityChecker:
    """
    A tool to analyze project dependencies, identify vulnerabilities, and flag license incompatibilities.
    """

    def __init__(self, dependency_file: str, license_policy: str, vulnerability_db: str):
        """
        Initializes the DependencyVulnerabilityChecker.

        Args:
            dependency_file: Path to the dependency file (e.g., requirements.txt, package.json).
            license_policy: License policy to enforce (e.g., "MIT", "GPL-2.0-or-later").
            vulnerability_db: Source of vulnerability data (e.g., "nvd", "osv").
        """
        self.dependency_file = dependency_file
        self.license_policy = license_policy
        self.vulnerability_db = vulnerability_db
        self.dependencies: List[Dict[str, str]] = []

    def load_dependencies(self) -> None:
        """
        Loads dependencies from the specified dependency file.
        Supports requirements.txt for now.
        """
        try:
            if self.dependency_file.endswith(".txt"):  # requirements.txt
                with open(self.dependency_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            try:
                                req = requirements.Requirement(line)
                                self.dependencies.append({"name": req.name, "version": str(req.specifier)})
                            except Exception as e:
                                logging.warning(f"Could not parse dependency line: {line}. Error: {e}")
            elif self.dependency_file.endswith(".json"): #package.json
                with open(self.dependency_file, "r") as f:
                    data = json.load(f)
                if "dependencies" in data:
                    for name, version in data["dependencies"].items():
                        self.dependencies.append({"name": name, "version": version})
                if "devDependencies" in data:
                    for name, version in data["devDependencies"].items():
                        self.dependencies.append({"name": name, "version": version})


            else:
                raise ValueError("Unsupported dependency file format. Only .txt and .json supported.")
        except FileNotFoundError:
            logging.error(f"Dependency file not found: {self.dependency_file}")
            raise
        except Exception as e:
            logging.error(f"Error loading dependencies: {e}")
            raise

    def check_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Checks for vulnerabilities in the loaded dependencies using the specified vulnerability database.

        Returns:
            A list of dictionaries, where each dictionary represents a vulnerable dependency
            and contains information about the vulnerability.
        """
        vulnerable_dependencies: List[Dict[str, Any]] = []
        for dep in self.dependencies:
            try:
                if self.vulnerability_db == "nvd":
                    vulnerabilities = self._check_vulnerabilities_nvd(dep["name"], dep["version"])
                elif self.vulnerability_db == "osv":
                    vulnerabilities = self._check_vulnerabilities_osv(dep["name"], dep["version"])
                else:
                    raise ValueError(f"Unsupported vulnerability database: {self.vulnerability_db}")

                if vulnerabilities:
                    vulnerable_dependencies.append({
                        "name": dep["name"],
                        "version": dep["version"],
                        "vulnerabilities": vulnerabilities
                    })
            except Exception as e:
                logging.error(f"Error checking vulnerabilities for {dep['name']}: {e}")

        return vulnerable_dependencies

    def _check_vulnerabilities_nvd(self, package_name: str, package_version: str) -> List[Dict[str, str]]:
        """
        Checks for vulnerabilities using the NIST NVD API.

        Args:
            package_name: Name of the package.
            package_version: Version of the package.

        Returns:
            A list of vulnerabilities (dictionaries) found for the given package and version.
        """
        url = f"{NVD_API_BASE_URL}?keyword={package_name}"
        try:
            response = requests.get(url, timeout=10)  # Added timeout for network requests
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            data = response.json()

            vulnerabilities = []
            if "vulnerabilities" in data:
                for item in data["vulnerabilities"]:
                    cve = item["cve"]
                    if "configurations" in cve:
                        for config in cve["configurations"]:
                            if "nodes" in config:
                                for node in config["nodes"]:
                                    if "cpeMatch" in node:
                                        for cpe in node["cpeMatch"]:
                                            if package_name in cpe["criteria"]:
                                                #Simple version check. Enhance with semver if needed.
                                                if package_version in cpe["criteria"]:
                                                    vulnerability = {
                                                        "cve_id": cve["id"],
                                                        "description": cve["descriptions"][0]["value"],
                                                        "cvssv3": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")

                                                    }
                                                    vulnerabilities.append(vulnerability)


            return vulnerabilities
        except requests.exceptions.RequestException as e:
            logging.error(f"Error querying NVD API: {e}")
            raise
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding JSON from NVD API: {e}")
            raise
        except Exception as e:
            logging.error(f"Error processing NVD data: {e}")
            raise


    def _check_vulnerabilities_osv(self, package_name: str, package_version: str) -> List[Dict[str, str]]:
        """
        Checks for vulnerabilities using the OSV API.

        Args:
            package_name: Name of the package.
            package_version: Version of the package.

        Returns:
            A list of vulnerabilities (dictionaries) found for the given package and version.
        """
        url = OSV_API_BASE_URL
        payload = {
            "package": {
                "name": package_name,
                "version": package_version
            }
        }
        try:
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            data = response.json()

            vulnerabilities = []
            if "vulns" in data:
                for vuln in data["vulns"]:
                    vulnerability = {
                        "id": vuln["id"],
                        "summary": vuln["summary"],
                        "details": vuln["details"],
                        "severity": vuln.get("severity", "N/A")
                    }
                    vulnerabilities.append(vulnerability)

            return vulnerabilities
        except requests.exceptions.RequestException as e:
            logging.error(f"Error querying OSV API: {e}")
            raise
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding JSON from OSV API: {e}")
            raise
        except Exception as e:
            logging.error(f"Error processing OSV data: {e}")
            raise


    def generate_report(self, vulnerable_dependencies: List[Dict[str, Any]]) -> str:
        """
        Generates a report detailing the vulnerable dependencies.

        Args:
            vulnerable_dependencies: A list of dictionaries representing vulnerable dependencies.

        Returns:
            A string containing the report.
        """
        if not vulnerable_dependencies:
            return "No vulnerabilities found."

        report = "Vulnerability Report:\n"
        for dep in vulnerable_dependencies:
            report += f"  Package: {dep['name']} (Version: {dep['version']})\n"
            for vuln in dep["vulnerabilities"]:
                report += f"    - Vulnerability ID: {vuln.get('id', vuln.get('cve_id', 'N/A'))}\n"
                report += f"      Description: {vuln.get('summary', vuln.get('description', 'N/A'))}\n"
                report += f"      Severity: {vuln.get('severity', vuln.get('cvssv3', 'N/A'))}\n"

        return report


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        An argparse.ArgumentParser object.
    """
    parser = argparse.ArgumentParser(description="Dependency Vulnerability Checker")
    parser.add_argument("dependency_file", help="Path to the dependency file (e.g., requirements.txt, package.json)")
    parser.add_argument("--license_policy", help="License policy to enforce (e.g., MIT, GPL-2.0-or-later)", default="MIT")
    parser.add_argument("--vulnerability_db", help="Source of vulnerability data (nvd or osv)", default="nvd", choices=["nvd", "osv"])
    parser.add_argument("--output", help="Path to save the report (optional).  If not provided the report will be printed to stdout.", required=False)
    return parser


def main() -> None:
    """
    Main function to execute the dependency vulnerability checker.
    """
    try:
        parser = setup_argparse()
        args = parser.parse_args()

        checker = DependencyVulnerabilityChecker(args.dependency_file, args.license_policy, args.vulnerability_db)
        checker.load_dependencies()
        vulnerable_dependencies = checker.check_vulnerabilities()
        report = checker.generate_report(vulnerable_dependencies)

        if args.output:
            try:
                with open(args.output, "w") as f:
                    f.write(report)
                print(f"Report saved to {args.output}")
            except Exception as e:
                logging.error(f"Error writing to output file: {e}")
                print(report)
        else:
            print(report)

    except ValueError as e:
        logging.error(e)
        sys.exit(1)
    except FileNotFoundError as e:
        logging.error(e)
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        logging.error(f"Network error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.exception("An unexpected error occurred:") # Include traceback in the log
        sys.exit(1)


if __name__ == "__main__":
    main()