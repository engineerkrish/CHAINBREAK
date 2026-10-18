Project: CHAINBREAK
Track: Agents That Act on Connected Data
Graph Database: FalkorDB
Repository: https://github.com/engineerkrish/CHAINBREAK
AI Assistance Disclosure
AI coding assistants were used to support development, debugging, and documentation. The submitted implementation should be reviewed and understood by the project contributor.
Built for the FalkorDB graph hackathon.

# CHAINBREAK

### Graph-Powered Software Supply-Chain Vulnerability Investigation

CHAINBREAK uses **FalkorDB** to trace vulnerability relationships across packages, repositories, and services. It combines graph-based impact analysis, remediation simulations, and human approval controls in one interactive dashboard.

> **Track:** Agents That Act on Connected Data

## The Problem

A vulnerability in a software dependency can affect multiple repositories and services. A vulnerability list alone cannot reveal the complete downstream impact.

CHAINBREAK uses graph relationships to identify represented dependencies and help developers understand potential impact before choosing a remediation strategy.

## Key Features

- **Vulnerability Inventory:** Retrieve vulnerability records from FalkorDB.
- **Blast-Radius Analysis:** Trace connections from vulnerabilities to packages, repositories, and services.
- **Graph Investigation:** Query connected dependency data to identify represented impact paths.
- **Remediation Simulation:** Compare hypothetical remediation strategies using illustrative risk-reduction estimates.
- **Human Approval:** Submit, approve, or reject remediation requests.
- **Safety Controls:** Remediation is simulated only. No production changes are executed.
- **Interactive Dashboard:** Explore vulnerabilities, attack paths, infrastructure, simulations, approvals, and configuration.

## Architecture

```text
React + Vite Dashboard
        |
        | HTTP / JSON
        v
FastAPI Backend
        |
        +---- Vulnerability Inventory
        |
        +---- Graph Investigation
        |          |
        |          v
        |       FalkorDB
        |          |
        |          v
        |    Connected Dependency Evidence
        |
        +---- Remediation Simulator
        |
        +---- Human Approval Workflow
Technology Stack
Component	Technology
Frontend	React, Vite, Tailwind CSS
Backend	Python, FastAPI
Graph Database	FalkorDB
Graph Query Language	Cypher
Configuration	Environment variables, python-dotenv


Graph Data Model
CHAINBREAK represents software supply-chain relationships using nodes and directed edges.
Nodes
- Vulnerability — vulnerability identifier, severity, and title.
- Package — affected software package and version.
- Repository — repository using the package.
- Service — service associated with the repository.
Relationships
(Vulnerability)-[:AFFECTS]->(Package)
(Package)-[:USED_BY]->(Repository)
(Repository)-[:DEPLOYED_IN]->(Service)

These relationships allow CHAINBREAK to traverse the graph and identify downstream entities connected to a vulnerability.
Demo data notice: The infrastructure path uses synthetic demonstration data. It does not establish that a real company or production service is affected.
Example Cypher Query
The following query retrieves a vulnerability and its connected packages, repositories, and services.
MATCH (v:Vulnerability {id: $vulnerability_id})
OPTIONAL MATCH (v)-[:AFFECTS]->(p:Package)
OPTIONAL MATCH (p)-[:USED_BY]->(r:Repository)
OPTIONAL MATCH (r)-[:DEPLOYED_IN]->(s:Service)
RETURN
    v.id AS vulnerability,
    v.severity AS severity,
    v.title AS title,
    collect(DISTINCT p.name) AS packages,
    collect(DISTINCT r.name) AS repositories,
    collect(DISTINCT s.name) AS services

The vulnerability identifier is passed as a query parameter.
FalkorDB is central to vulnerability retrieval and connected-impact analysis. The remediation simulator and approval workflow are separate application components.
Safety and Limitations
- Remediation recommendations are hypothetical.
- Risk-reduction figures are illustrative estimates, not measured security outcomes.
- Approval requests do not execute real remediation actions.
- Approval state is stored in application memory and may be lost when the backend restarts.
- Synthetic infrastructure relationships must not be interpreted as verified real-world exposure.
- CHAINBREAK is a demonstration and decision-support tool, not a replacement for security verification.
Setup
Prerequisites
- Python 3.11 or later
- Node.js and npm
- A reachable FalkorDB instance
1. Clone the repository
git clone https://github.com/engineerkrish/CHAINBREAK.git
cd CHAINBREAK

2. Configure the backend
Create a local .env file using .env.example as a template.
Configure the following values for your FalkorDB instance:
FALKORDB_HOST=your-falkordb-host
FALKORDB_PORT=your-port
FALKORDB_USERNAME=falkordb
FALKORDB_PASSWORD=your-password
FALKORDB_GRAPH=chainbreak
FALKORDB_SSL=false

Use the SSL setting appropriate for your database provider.
Never commit your .env file or database credentials.
3. Install Python dependencies
Create and activate a virtual environment, then run:
python -m pip install -r requirements.txt

4. Start the backend
uvicorn app.main:app --reload

The API is available at:
- API: http://127.0.0.1:8000
- Interactive API documentation: http://127.0.0.1:8000/docs
5. Start the frontend
Open another terminal:
cd frontend
npm install
npm run dev

Open the local URL printed by Vite.
6. Verify the connection
Check the API health endpoint:
http://127.0.0.1:8000/health

Ensure FalkorDB is reachable and the required graph data has been loaded.
Project Structure
CHAINBREAK/
├── app/
│   ├── approvals.py
│   ├── database.py
│   ├── main.py
│   └── simulator.py
├── frontend/
│   ├── src/
│   ├── package.json
│   └── vite.config.js
├── .env.example
├── .gitignore
├── import_osv.py
├── import_to_graph.py
├── requirements.txt
└── README.md
