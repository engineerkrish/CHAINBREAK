
import requests

OSV_API = "https://api.osv.dev/v1/query"

def fetch_vulnerabilities(package_name, ecosystem="PyPI"):
    response = requests.post(
        OSV_API,
        json={
            "package": {
                "name": package_name,
                "ecosystem": ecosystem,
            }
        },
        timeout=20,
    )
    response.raise_for_status()
    return response.json().get("vulns", [])

if __name__ == "__main__":
    package = "requests"
    print(f"Fetching OSV advisories for {package}...")

    try:
        vulnerabilities = fetch_vulnerabilities(package)

        print(f"\nFound {len(vulnerabilities)} advisories.\n")

        for vuln in vulnerabilities[:10]:
            print(f"ID: {vuln.get('id', 'Unknown')}")
            print(f"Summary: {vuln.get('summary', 'No summary provided')}")
            print("-" * 50)

    except requests.RequestException as error:
        print(f"OSV API request failed: {error}")
