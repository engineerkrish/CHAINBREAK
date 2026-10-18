import os
from dotenv import load_dotenv
from falkordb import FalkorDB

load_dotenv()

def get_graph():
    host = os.environ["FALKORDB_HOST"]
    port = int(os.getenv("FALKORDB_PORT", "49363"))
    username = os.environ["FALKORDB_USERNAME"]
    password = os.environ["FALKORDB_PASSWORD"]
    use_ssl = os.getenv("FALKORDB_SSL", "true").lower() == "true"

    db = FalkorDB(
        host=host,
        port=port,
        username=username,
        password=password,
        ssl=use_ssl,
    )
    return db.select_graph(os.getenv("FALKORDB_GRAPH", "chainbreak"))

if __name__ == "__main__":
    try:
        graph = get_graph()
        result = graph.query(
            "MATCH (v:Vulnerability {id: 'CVE-DEMO-001'}) "
            "RETURN v.id AS id, v.severity AS severity"
        )
        print("Connection successful!")
        print("Vulnerability:", result.result_set)
    except Exception as exc:
        print(f"Connection failed: {type(exc).__name__}: {exc}")
