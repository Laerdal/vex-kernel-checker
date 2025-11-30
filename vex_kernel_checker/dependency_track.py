"""
Dependency-Track integration for VEX Kernel Checker.

Provides functionality to:
- Download VEX/vulnerability data from Dependency-Track
- Upload analyzed VEX results back to Dependency-Track
"""

import base64
import json
import re
from typing import Dict, Optional
from urllib.parse import urlparse

import requests

from .logging_utils import get_logger


class DependencyTrackClient:
    """Client for interacting with Dependency-Track API."""

    def __init__(
        self,
        api_url: str,
        api_key: str,
        project_uuid: Optional[str] = None,
        timeout: int = 30,
        verbose: bool = False,
    ):
        """
        Initialize the Dependency-Track client.

        Args:
            api_url: API URL of Dependency-Track (e.g., https://deptrack.example.com/api)
            api_key: API key for authentication
            project_uuid: Optional project UUID (can also be extracted from URLs)
            timeout: Request timeout in seconds
            verbose: Enable verbose logging
        """
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.project_uuid = project_uuid
        self.timeout = timeout
        self.verbose = verbose
        self.logger = get_logger(__name__)

    def _get_headers(self) -> Dict[str, str]:
        """Get common headers for API requests."""
        return {
            "X-Api-Key": self.api_key,
            "Accept": "application/json",
        }

    def _extract_project_uuid(self, url: str) -> Optional[str]:
        """
        Extract project UUID from a Dependency-Track URL.

        Supports URLs like:
        - https://deptrack.example.com/api/v1/bom/cyclonedx/project/{uuid}
        - https://deptrack.example.com/projects/{uuid}

        Args:
            url: URL that may contain a project UUID

        Returns:
            Extracted UUID or None
        """
        # Pattern for UUID (standard format)
        uuid_pattern = (
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        )

        # Try to find UUID in URL path
        match = re.search(uuid_pattern, url)
        if match:
            return match.group(0)

        return None

    def download_vex(
        self,
        url: Optional[str] = None,
        project_uuid: Optional[str] = None,
    ) -> Dict:
        """
        Download VEX/vulnerability data from Dependency-Track.

        This fetches the CycloneDX BOM and then separately fetches vulnerabilities
        from the vulnerability endpoint, merging them into a complete VEX document.

        Args:
            url: Full URL to fetch VEX data (optional if project_uuid provided)
            project_uuid: Project UUID (optional if url provided or set in constructor)

        Returns:
            VEX data as dictionary (CycloneDX format with vulnerabilities)

        Raises:
            ValueError: If neither URL nor project UUID is available
            requests.RequestException: If the request fails
        """
        # Determine project UUID
        if url:
            # Try to extract project UUID from URL if not already set
            if not self.project_uuid:
                self.project_uuid = self._extract_project_uuid(url)
        elif project_uuid:
            self.project_uuid = project_uuid

        if not self.project_uuid:
            raise ValueError(
                "No URL or project UUID provided. "
                "Specify --dt-url, --dt-project-uuid, or dt_project_uuid in config."
            )

        # Step 1: Fetch the BOM (for components)
        bom_url = f"{self.api_url}/v1/bom/cyclonedx/project/{self.project_uuid}"

        if self.verbose:
            print(f"📥 Downloading BOM from Dependency-Track: {bom_url}")

        self.logger.info(f"Fetching BOM data from: {bom_url}")

        # Use CycloneDX-specific Accept header for BOM export
        headers = self._get_headers()
        headers["Accept"] = "application/vnd.cyclonedx+json"

        try:
            response = requests.get(
                bom_url,
                headers=headers,
                timeout=self.timeout,
            )
        except requests.exceptions.ConnectionError as e:
            error_msg = str(e)
            if "NameResolutionError" in error_msg or "Failed to resolve" in error_msg:
                raise ConnectionError(
                    f"Cannot resolve Dependency-Track host. Check your --dt-api-url and network connection. "
                    f"URL: {bom_url}"
                ) from e
            raise ConnectionError(
                f"Cannot connect to Dependency-Track. Check your --dt-api-url and network connection. "
                f"URL: {bom_url}"
            ) from e

        if response.status_code == 401:
            raise PermissionError("Authentication failed. Check your Dependency-Track API key.")
        elif response.status_code == 403:
            raise PermissionError(
                "Access denied. Your API key may not have permission to access this project."
            )
        elif response.status_code == 404:
            raise ValueError(f"Project not found. Check the project UUID: {self.project_uuid}")

        response.raise_for_status()
        vex_data = response.json()

        # Validate it's CycloneDX format
        if vex_data.get("bomFormat") != "CycloneDX":
            self.logger.warning(
                "Downloaded data may not be in CycloneDX format. "
                f"bomFormat: {vex_data.get('bomFormat')}"
            )

        # Step 2: Get project metrics to understand expected vulnerability counts
        if self.verbose:
            self._show_project_metrics(self.project_uuid)

        # Step 3: Fetch vulnerabilities from the finding endpoint
        vulns = self._fetch_project_vulnerabilities(self.project_uuid)

        if vulns:
            # Convert DT vulnerabilities to CycloneDX format and add to VEX
            cdx_vulns = self._convert_vulnerabilities_to_cyclonedx(vulns)
            vex_data["vulnerabilities"] = cdx_vulns

        vuln_count = len(vex_data.get("vulnerabilities", []))
        if self.verbose:
            print(f"✅ Downloaded {vuln_count} vulnerabilities from Dependency-Track")

        self.logger.info(f"Downloaded VEX with {vuln_count} vulnerabilities")

        return vex_data

    def _show_project_metrics(self, project_uuid: str) -> None:
        """
        Fetch and display project metrics to understand expected vulnerability counts.

        Args:
            project_uuid: Project UUID
        """
        metrics_url = f"{self.api_url}/v1/metrics/project/{project_uuid}/current"

        try:
            response = requests.get(
                metrics_url,
                headers=self._get_headers(),
                timeout=self.timeout,
            )

            if response.status_code == 200:
                metrics = response.json()
                print(f"📊 Project metrics:")
                print(f"   Components: {metrics.get('components', 'N/A')}")
                print(f"   Vulnerable components: {metrics.get('vulnerableComponents', 'N/A')}")
                print(f"   Vulnerabilities: {metrics.get('vulnerabilities', 'N/A')}")
                print(f"   Critical: {metrics.get('critical', 'N/A')}")
                print(f"   High: {metrics.get('high', 'N/A')}")
                print(f"   Medium: {metrics.get('medium', 'N/A')}")
                print(f"   Low: {metrics.get('low', 'N/A')}")
                print(f"   Unassigned: {metrics.get('unassigned', 'N/A')}")
                print(f"   Findings total: {metrics.get('findingsTotal', 'N/A')}")
                print(f"   Findings audited: {metrics.get('findingsAudited', 'N/A')}")
                print(f"   Findings unaudited: {metrics.get('findingsUnaudited', 'N/A')}")
                print(f"   Suppressed: {metrics.get('suppressed', 'N/A')}")
            else:
                print(f"   Could not fetch metrics: HTTP {response.status_code}")
        except Exception as e:
            print(f"   Could not fetch metrics: {e}")

    def _fetch_project_vulnerabilities(
        self, project_uuid: str, include_suppressed: bool = True
    ) -> list:
        """
        Fetch vulnerabilities (findings) for a project from Dependency-Track.

        Uses the /v1/finding/project/{uuid} endpoint which returns all findings
        (vulnerabilities associated with components) for a project.

        Note: The /v1/finding/project endpoint does NOT support pagination
        (see GitHub issue #2588). It returns all findings in a single response.

        Args:
            project_uuid: Project UUID
            include_suppressed: If True, fetch both active and suppressed findings.
                               Default is True to include all findings for analysis.

        Returns:
            List of finding dictionaries (each contains vulnerability and component info)
        """
        # Use the finding endpoint - this returns all vulnerability findings for a project
        # Note: This endpoint does NOT support pagination (returns all at once)
        finding_url = f"{self.api_url}/v1/finding/project/{project_uuid}"

        all_findings = []

        # First fetch active (non-suppressed) findings
        if self.verbose:
            print(f"📥 Fetching active findings from: {finding_url}")

        self.logger.info(f"Fetching findings from: {finding_url}")

        try:
            response = requests.get(
                finding_url,
                headers=self._get_headers(),
                timeout=120,  # Longer timeout for potentially large response
            )
        except requests.exceptions.ConnectionError as e:
            self.logger.warning(f"Failed to fetch findings: {e}")
            return []

        if response.status_code != 200:
            if self.verbose:
                print(f"   Warning: Finding endpoint returned {response.status_code}")
                if response.text:
                    print(f"   Response: {response.text[:500]}")
            self.logger.warning(f"Failed to fetch findings: {response.status_code}")
            return []

        # Get total count from header
        total_count = response.headers.get("X-Total-Count")
        if self.verbose:
            print(f"   X-Total-Count header (active): {total_count}")

        active_findings = response.json()
        all_findings.extend(active_findings)

        if self.verbose:
            print(f"   Fetched {len(active_findings)} active findings")

        # Now fetch suppressed findings if requested
        if include_suppressed:
            suppressed_url = f"{finding_url}?suppressed=true"
            if self.verbose:
                print(f"📥 Fetching suppressed findings from: {suppressed_url}")

            try:
                response = requests.get(
                    suppressed_url,
                    headers=self._get_headers(),
                    timeout=120,
                )

                if response.status_code == 200:
                    suppressed_findings = response.json()
                    if self.verbose:
                        print(f"   Fetched {len(suppressed_findings)} suppressed findings")
                    all_findings.extend(suppressed_findings)
                else:
                    if self.verbose:
                        print(
                            f"   Warning: Suppressed findings endpoint returned {response.status_code}"
                        )
            except requests.exceptions.RequestException as e:
                if self.verbose:
                    print(f"   Warning: Could not fetch suppressed findings: {e}")

        if self.verbose:
            print(f"   Total findings fetched: {len(all_findings)}")
            if all_findings and len(all_findings) > 0:
                # Show sample finding structure
                sample = all_findings[0]
                vuln = sample.get("vulnerability", {})
                comp = sample.get("component", {})
                print(
                    f"   Sample finding - CVE: {vuln.get('vulnId')}, Component: {comp.get('name')}"
                )

        return all_findings

    def _convert_vulnerabilities_to_cyclonedx(self, dt_vulns: list) -> list:
        """
        Convert Dependency-Track vulnerabilities to CycloneDX format.

        Deduplicates vulnerabilities by ID, merging affected components.

        Args:
            dt_vulns: List of Dependency-Track vulnerability dictionaries

        Returns:
            List of CycloneDX vulnerability dictionaries (unique by ID)
        """
        # Group findings by vulnerability ID to deduplicate
        vuln_map = {}  # vulnId -> (vuln_data, list of affected components, analysis)

        for dt_vuln in dt_vulns:
            vuln = dt_vuln.get("vulnerability", dt_vuln)
            vuln_id = vuln.get("vulnId", "")

            if not vuln_id:
                continue

            component = dt_vuln.get("component", {})
            analysis = dt_vuln.get("analysis", {})

            if vuln_id not in vuln_map:
                vuln_map[vuln_id] = {
                    "vuln": vuln,
                    "components": [],
                    "analysis": analysis,  # Use first analysis found
                }

            # Add component to affected list
            if component:
                comp_ref = component.get("purl") or component.get("uuid", "")
                if comp_ref and comp_ref not in [
                    c.get("ref") for c in vuln_map[vuln_id]["components"]
                ]:
                    vuln_map[vuln_id]["components"].append({"ref": comp_ref})

            # Prefer non-empty analysis
            if analysis and not vuln_map[vuln_id]["analysis"]:
                vuln_map[vuln_id]["analysis"] = analysis

        cdx_vulns = []

        # Map DT severity to CycloneDX severity enum
        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "INFO": "info",
            "INFORMATIONAL": "info",
            "NONE": "none",
            "UNASSIGNED": "unknown",
            "UNKNOWN": "unknown",
        }

        for vuln_id, data in vuln_map.items():
            vuln = data["vuln"]
            components = data["components"]
            analysis = data["analysis"]

            cdx_vuln = {
                "id": vuln.get("vulnId", ""),
                "source": {
                    "name": vuln.get("source", "NVD"),
                },
            }

            # Add description if available
            if vuln.get("description"):
                cdx_vuln["description"] = vuln.get("description")

            # Add CVSS scores and severity as ratings
            # CycloneDX severity enum: critical, high, medium, low, info, none, unknown
            ratings = []

            if vuln.get("cvssV3BaseScore"):
                rating = {
                    "method": "CVSSv3",
                    "score": vuln.get("cvssV3BaseScore"),
                }
                if vuln.get("cvssV3Vector"):
                    rating["vector"] = vuln.get("cvssV3Vector")
                # Add severity from DT if available
                if vuln.get("severity"):
                    sev = vuln.get("severity", "").upper()
                    rating["severity"] = severity_map.get(sev, "unknown")
                ratings.append(rating)

            if vuln.get("cvssV2BaseScore"):
                rating = {
                    "method": "CVSSv2",
                    "score": vuln.get("cvssV2BaseScore"),
                }
                if vuln.get("cvssV2Vector"):
                    rating["vector"] = vuln.get("cvssV2Vector")
                ratings.append(rating)

            # If no CVSS scores but we have severity, add a simple rating
            if not ratings and vuln.get("severity"):
                sev = vuln.get("severity", "").upper()
                ratings.append({"severity": severity_map.get(sev, "unknown")})

            if ratings:
                cdx_vuln["ratings"] = ratings

            # Add references if available
            if vuln.get("references"):
                refs = []
                for ref in vuln.get("references", []):
                    if isinstance(ref, dict):
                        refs.append(
                            {"id": ref.get("url", ""), "source": {"url": ref.get("url", "")}}
                        )
                    elif isinstance(ref, str):
                        refs.append({"id": ref, "source": {"url": ref}})
                if refs:
                    cdx_vuln["references"] = refs

            # Add affected components (merged from all findings with this CVE)
            if components:
                cdx_vuln["affects"] = components

            # Add analysis if available
            if analysis:
                cdx_analysis = {}
                state = analysis.get("state")
                if state:
                    # Map DT states to CycloneDX states
                    state_map = {
                        "NOT_AFFECTED": "not_affected",
                        "EXPLOITABLE": "exploitable",
                        "IN_TRIAGE": "in_triage",
                        "RESOLVED": "resolved",
                        "FALSE_POSITIVE": "false_positive",
                    }
                    cdx_analysis["state"] = state_map.get(state, state.lower())

                justification = analysis.get("justification")
                if justification:
                    cdx_analysis["justification"] = justification.lower()

                detail = analysis.get("details")
                if detail:
                    cdx_analysis["detail"] = detail

                response_list = analysis.get("response")
                if response_list:
                    cdx_analysis["response"] = response_list

                if cdx_analysis:
                    cdx_vuln["analysis"] = cdx_analysis

            cdx_vulns.append(cdx_vuln)

        return cdx_vulns

    def upload_vex(
        self,
        vex_data: Dict,
        url: Optional[str] = None,
        project_uuid: Optional[str] = None,
        project_name: Optional[str] = None,
        project_version: Optional[str] = None,
    ) -> bool:
        """
        Upload analyzed VEX data back to Dependency-Track.

        Uses the /v1/vex endpoint which is designed for VEX uploads (not /v1/bom).
        Supports both multipart form upload and JSON payload.

        Args:
            vex_data: Analyzed VEX data dictionary (CycloneDX format)
            url: Optional upload URL (defaults to /v1/vex endpoint)
            project_uuid: Project UUID (optional if project_name provided)
            project_name: Project name (optional if project_uuid provided)
            project_version: Project version (required with project_name)

        Returns:
            True if upload successful

        Raises:
            ValueError: If neither project UUID nor project name is available
            requests.RequestException: If the request fails
        """
        # Determine project UUID
        uuid = project_uuid or self.project_uuid

        # If no UUID but we have name, look up the project
        if not uuid and project_name:
            project = self.find_project(name=project_name, version=project_version)
            if project:
                uuid = project.get("uuid")

        # Determine upload URL - use /v1/vex for VEX uploads
        if url:
            upload_url = url
        else:
            upload_url = f"{self.api_url}/v1/vex"

        if self.verbose:
            print(f"📤 Uploading VEX to Dependency-Track: {upload_url}")

        self.logger.info(f"Uploading VEX data to: {upload_url}")

        # Prepare VEX JSON
        vex_json = json.dumps(vex_data, indent=2, ensure_ascii=False)

        # Use multipart form upload (more reliable with DT)
        # This matches: curl -F "project=uuid" -F "vex=@file.json" /api/v1/vex
        headers = {"X-Api-Key": self.api_key}

        if uuid:
            # Upload with project UUID
            files = {"vex": ("vex.json", vex_json, "application/json")}
            data = {"project": uuid}
        elif project_name:
            # Upload with project name/version
            files = {"vex": ("vex.json", vex_json, "application/json")}
            data = {"projectName": project_name}
            if project_version:
                data["projectVersion"] = project_version
        else:
            raise ValueError(
                "No project UUID or project name available for upload. "
                "Specify --dt-project-uuid or --dt-project-name."
            )

        try:
            response = requests.post(
                upload_url,
                headers=headers,
                files=files,
                data=data,
                timeout=120,  # Longer timeout for large VEX uploads
            )
        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(
                f"Cannot connect to Dependency-Track for upload. " f"URL: {upload_url}"
            ) from e

        if response.status_code == 401:
            raise PermissionError("Authentication failed. Check your Dependency-Track API key.")
        elif response.status_code == 403:
            raise PermissionError("Access denied. Your API key may not have BOM_UPLOAD permission.")
        elif response.status_code == 404:
            raise ValueError(f"Project not found. Check the project UUID: {uuid}")
        elif response.status_code == 400:
            # Get error details from response
            error_detail = response.text[:500] if response.text else "No details"
            if self.verbose:
                print(f"   Upload error response: {error_detail}")
            raise ValueError(f"Bad request - VEX format may be invalid. Details: {error_detail}")

        response.raise_for_status()

        vuln_count = len(vex_data.get("vulnerabilities", []))
        if self.verbose:
            print(f"✅ Successfully uploaded {vuln_count} vulnerabilities to Dependency-Track")

        self.logger.info(f"Successfully uploaded VEX with {vuln_count} vulnerabilities")

        return True

    def get_project_info(self, project_uuid: Optional[str] = None) -> Dict:
        """
        Get project information from Dependency-Track.

        Args:
            project_uuid: Project UUID (optional if already set)

        Returns:
            Project information dictionary
        """
        uuid = project_uuid or self.project_uuid
        if not uuid:
            raise ValueError("No project UUID available.")

        url = f"{self.api_url}/v1/project/{uuid}"

        if self.verbose:
            print(f"📋 Fetching project info: {uuid}")

        response = requests.get(
            url,
            headers=self._get_headers(),
            timeout=self.timeout,
        )

        response.raise_for_status()

        return response.json()

    def list_projects(self, name_filter: Optional[str] = None) -> list:
        """
        List projects from Dependency-Track.

        Args:
            name_filter: Optional filter by project name (uses server-side filtering)

        Returns:
            List of project dictionaries
        """
        url = f"{self.api_url}/v1/project"

        # Use server-side name filter if provided (more efficient than client-side)
        params = {}
        if name_filter:
            params["name"] = name_filter

        if self.verbose:
            filter_info = f" (filter: '{name_filter}')" if name_filter else ""
            print(f"📋 Listing Dependency-Track projects from: {url}{filter_info}")
        else:
            self.logger.debug(f"Listing projects from: {url}")

        try:
            response = requests.get(
                url,
                headers=self._get_headers(),
                params=params,
                timeout=self.timeout,
            )
        except requests.exceptions.ConnectionError as e:
            # Provide user-friendly error for connection issues
            error_msg = str(e)
            if "NameResolutionError" in error_msg or "Failed to resolve" in error_msg:
                raise ConnectionError(
                    f"Cannot resolve Dependency-Track host. Check your --dt-api-url and network connection. "
                    f"URL: {url}"
                ) from e
            raise ConnectionError(
                f"Cannot connect to Dependency-Track. Check your --dt-api-url and network connection. "
                f"URL: {url}"
            ) from e

        if self.verbose:
            total_count = response.headers.get("X-Total-Count", "unknown")
            print(f"   Response status: {response.status_code}, total matching: {total_count}")

        if response.status_code == 401:
            raise PermissionError("Authentication failed. Check your Dependency-Track API key.")
        elif response.status_code == 403:
            raise PermissionError(
                "Access denied. Your API key may not have permission to list projects."
            )

        response.raise_for_status()

        try:
            projects = response.json()
        except json.JSONDecodeError as e:
            # Server returned non-JSON response
            content_preview = response.text[:500] if response.text else "(empty)"
            raise ValueError(
                f"Dependency-Track returned invalid JSON response.\n"
                f"URL: {url}\n"
                f"Status: {response.status_code}\n"
                f"Content: {content_preview}"
            ) from e

        if self.verbose:
            print(f"   Returned {len(projects)} projects in response")

        return projects

    def find_project(
        self,
        name: str,
        version: Optional[str] = None,
        parent_name: Optional[str] = None,
        parent_uuid: Optional[str] = None,
        latest: bool = True,
    ) -> Optional[Dict]:
        """
        Find a project by name and optionally parent.

        Args:
            name: Project name to find
            version: Optional project version. If not specified and latest=True,
                     returns the most recently modified project with that name.
            parent_name: Optional parent project name
            parent_uuid: Optional parent project UUID
            latest: If True and no version specified, return the latest version

        Returns:
            Project dictionary if found, None otherwise
        """
        # If version specified, use lookup endpoint (faster)
        if version:
            params = {"name": name, "version": version}
            url = f"{self.api_url}/v1/project/lookup"

            if self.verbose:
                print(f"🔍 Looking up project: {name} v{version}")

            try:
                response = requests.get(
                    url,
                    headers=self._get_headers(),
                    params=params,
                    timeout=self.timeout,
                )

                if response.status_code == 200:
                    project = response.json()

                    # If parent filter specified, verify it matches
                    if parent_name or parent_uuid:
                        parent = project.get("parent")
                        if parent:
                            if parent_uuid and parent.get("uuid") != parent_uuid:
                                return None
                            if parent_name and parent.get("name") != parent_name:
                                return None
                        else:
                            # Project has no parent but we wanted one
                            if parent_name or parent_uuid:
                                return None

                    self.project_uuid = project.get("uuid")
                    return project

                elif response.status_code == 404:
                    return None

            except requests.RequestException:
                pass

        # List all projects with this name and find the best match
        if self.verbose:
            search_details = f"name='{name}'"
            if version:
                search_details += f", version='{version}'"
            if parent_uuid:
                search_details += f", parent_uuid='{parent_uuid}'"
            if parent_name:
                search_details += f", parent_name='{parent_name}'"
            print(
                f"🔍 Looking up project: {search_details}"
                + (" (latest version)" if latest and not version else "")
            )

        projects = self.list_projects(name_filter=name)

        if self.verbose:
            print(f"   Found {len(projects)} projects containing '{name}' in name")
            for p in projects[:10]:  # Show first 10
                parent_info = (
                    f" (parent: {p.get('parent', {}).get('uuid', 'none')})"
                    if p.get("parent")
                    else ""
                )
                print(f"     - {p.get('name')} v{p.get('version', 'N/A')}{parent_info}")
            if len(projects) > 10:
                print(f"     ... and {len(projects) - 10} more")

        # Filter to exact name matches and apply parent filter
        matching_projects = []
        for project in projects:
            project_name = project.get("name", "")
            if project_name != name:
                if self.verbose:
                    print(f"   Skipping '{project_name}' - name doesn't match exactly")
                continue

            # Check parent if specified
            if parent_name or parent_uuid:
                parent = project.get("parent")
                if not parent:
                    if self.verbose:
                        print(f"   Skipping '{project_name}' - no parent (need parent filter)")
                    continue
                if parent_uuid and parent.get("uuid") != parent_uuid:
                    if self.verbose:
                        print(
                            f"   Skipping '{project_name}' - parent UUID mismatch: {parent.get('uuid')} != {parent_uuid}"
                        )
                    continue
                if parent_name and parent.get("name") != parent_name:
                    if self.verbose:
                        print(
                            f"   Skipping '{project_name}' - parent name mismatch: {parent.get('name')} != {parent_name}"
                        )
                    continue

            matching_projects.append(project)

        if not matching_projects:
            return None

        # If latest=True and no version specified, sort by lastBomImport (most recent first)
        if latest and not version:
            # Sort by lastBomImport timestamp (descending), fallback to name
            matching_projects.sort(key=lambda p: p.get("lastBomImport") or "", reverse=True)
            if self.verbose and len(matching_projects) > 1:
                latest_version = matching_projects[0].get("version", "unknown")
                print(f"   Found {len(matching_projects)} versions, using latest: {latest_version}")

        # Return the first matching project (latest if sorted, or first found)
        project = matching_projects[0]
        self.project_uuid = project.get("uuid")
        return project

    def get_or_create_project(
        self,
        name: str,
        version: Optional[str] = None,
        parent_uuid: Optional[str] = None,
        parent_name: Optional[str] = None,
    ) -> Dict:
        """
        Get existing project or create a new one.

        Args:
            name: Project name
            version: Optional project version
            parent_uuid: Optional parent project UUID
            parent_name: Optional parent project name (used to lookup parent UUID)

        Returns:
            Project dictionary
        """
        # First try to find existing project
        project = self.find_project(
            name=name,
            version=version,
            parent_name=parent_name,
            parent_uuid=parent_uuid,
        )

        if project:
            if self.verbose:
                print(f"✅ Found existing project: {name} ({project.get('uuid')})")
            return project

        # Resolve parent UUID from name if needed
        if parent_name and not parent_uuid:
            parent_project = self.find_project(name=parent_name)
            if parent_project:
                parent_uuid = parent_project.get("uuid")
            else:
                raise ValueError(f"Parent project not found: {parent_name}")

        # Create new project
        if self.verbose:
            print(f"📝 Creating new project: {name}")

        url = f"{self.api_url}/v1/project"

        payload = {
            "name": name,
            "active": True,
        }
        if version:
            payload["version"] = version
        if parent_uuid:
            payload["parent"] = {"uuid": parent_uuid}

        headers = self._get_headers()
        headers["Content-Type"] = "application/json"

        response = requests.put(
            url,
            headers=headers,
            json=payload,
            timeout=self.timeout,
        )

        response.raise_for_status()

        project = response.json()
        self.project_uuid = project.get("uuid")

        if self.verbose:
            print(f"✅ Created project: {name} ({self.project_uuid})")

        return project


def download_from_dependency_track(
    url: Optional[str] = None,
    api_url: Optional[str] = None,
    api_key: Optional[str] = None,
    project_uuid: Optional[str] = None,
    output_file: Optional[str] = None,
    verbose: bool = False,
) -> Dict:
    """
    Convenience function to download VEX from Dependency-Track.

    Args:
        url: Full URL to fetch VEX data
        api_url: API URL of Dependency-Track instance (e.g., https://deptrack.example.com/api)
        api_key: API key for authentication
        project_uuid: Project UUID
        output_file: Optional file to save downloaded VEX
        verbose: Enable verbose output

    Returns:
        Downloaded VEX data dictionary
    """
    if not api_key:
        raise ValueError("Dependency-Track API key is required (--dt-api-key)")

    # Determine API URL
    if url:
        parsed = urlparse(url)
        # Extract base URL up to /api if present
        path_parts = parsed.path.split("/api/")
        if len(path_parts) > 1:
            api_url = f"{parsed.scheme}://{parsed.netloc}/api"
        else:
            api_url = f"{parsed.scheme}://{parsed.netloc}"
    elif not api_url:
        raise ValueError("Either --dt-url or --dt-api-url is required")

    client = DependencyTrackClient(
        api_url=api_url,
        api_key=api_key,
        project_uuid=project_uuid,
        verbose=verbose,
    )

    vex_data = client.download_vex(url=url, project_uuid=project_uuid)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(vex_data, f, indent=2, ensure_ascii=False)
        if verbose:
            print(f"💾 Saved VEX to: {output_file}")

    return vex_data


def upload_to_dependency_track(
    vex_data: Dict,
    url: Optional[str] = None,
    api_url: Optional[str] = None,
    api_key: Optional[str] = None,
    project_uuid: Optional[str] = None,
    verbose: bool = False,
) -> bool:
    """
    Convenience function to upload VEX to Dependency-Track.

    Args:
        vex_data: VEX data dictionary to upload
        url: Optional upload URL
        api_url: API URL of Dependency-Track instance (e.g., https://deptrack.example.com/api)
        api_key: API key for authentication
        project_uuid: Project UUID
        verbose: Enable verbose output

    Returns:
        True if upload successful
    """
    if not api_key:
        raise ValueError("Dependency-Track API key is required (--dt-api-key)")

    if not api_url:
        raise ValueError("Dependency-Track API URL is required (--dt-api-url)")

    if not project_uuid:
        raise ValueError("Project UUID is required for upload (--dt-project-uuid)")

    client = DependencyTrackClient(
        api_url=api_url,
        api_key=api_key,
        project_uuid=project_uuid,
        verbose=verbose,
    )

    return client.upload_vex(vex_data, url=url, project_uuid=project_uuid)
