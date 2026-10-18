
import os
import requests
from dotenv import load_dotenv
from falkordb import FalkorDB

load_dotenv()

db = FalkorDB(
    host=os.environ["FALKORDB_HOST"],
    port=int(os.environ["FALKORDB_PORT"]),
    username=os.environ["FALKORDB_USERNAME"],
    password=os.environ["FALKORDB_PASSWORD"],
    ssl=False,
    socket_connect_timeout=10,
    socket_timeout=20,
)

graph = db.select_graph(os.getenv("FALKORDB_GRAPH", "chainbreak"))

response = requests.post(
    "https://api.osv.dev/v1/query",
    json={"package": {"name": "requests", "ecosystem": "PyPI"}},
    timeout=20,
)
response.raise_for_status()
vulnerabilities = response.json().get("vulns", [])

for vuln in vulnerabilities:
    vuln_id = vuln.get("id")
    if not vuln_id:
        continue

    graph.query(
        """
        MERGE (v:Vulnerability {id: $id})
        SET v.title = $title,
            v.source = 'OSV',
            v.package = 'requests',
            v.ecosystem = 'PyPI',
            v.synthetic = false
        """,
        {
            "id": vuln_id,
            "title": vuln.get("summary") or vuln_id,
        },
    )

    graph.query(
        """
        MERGE (p:Package {name: 'requests', ecosystem: 'PyPI'})
        MERGE (v:Vulnerability {id: $id})
        MERGE (v)-[:AFFECTS]->(p)
        """,
        {"id": vuln_id},
    )

print(f"Imported {len(vulnerabilities)} OSV advisories into FalkorDB.")
print("Next, query the graph to verify the imported nodes.")
