
import os
from dotenv import load_dotenv
from falkordb import FalkorDB

load_dotenv()

db = FalkorDB(
    host=os.environ["FALKORDB_HOST"],
    port=int(os.environ["FALKORDB_PORT"]),
    username=os.environ["FALKORDB_USERNAME"],
    password=os.environ["FALKORDB_PASSWORD"],
        ssl=True,
    socket_timeout=10,
)

graph = db.select_graph("chainbreak")
result = graph.query("RETURN 'CHAINBREAK connected!' AS message")
print(result.result_set)
