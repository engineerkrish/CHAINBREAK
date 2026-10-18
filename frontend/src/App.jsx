
import React, { useEffect, useState } from 'react'
import {
  Shield, LayoutDashboard, Bug, GitBranch, Wrench, ClipboardCheck,
  Settings, Search, Bell, ChevronDown, ArrowUpRight, ArrowDownRight,
  Activity, Package, Server, AlertTriangle, CheckCircle2, Clock,
  Zap, CircleDot, Menu, RefreshCw, ExternalLink, ShieldCheck
} from 'lucide-react'
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip,
  CartesianGrid
} from 'recharts'
import './index.css'
import './App.css'

const activityData = [
  { day: 'Mon', findings: 18, resolved: 12 },
  { day: 'Tue', findings: 25, resolved: 17 },
  { day: 'Wed', findings: 20, resolved: 14 },
  { day: 'Thu', findings: 34, resolved: 22 },
  { day: 'Fri', findings: 27, resolved: 24 },
  { day: 'Sat', findings: 39, resolved: 29 },
  { day: 'Sun', findings: 31, resolved: 26 },
]

const findings = []

const navGroups = [
  { title: 'WORKSPACE', items: [
    { label: 'Overview', icon: LayoutDashboard },
    { label: 'Vulnerabilities', icon: Bug, badge: '17' },
    { label: 'Attack Paths', icon: GitBranch },
    { label: 'Remediation', icon: Wrench },
    { label: 'Approvals', icon: ClipboardCheck, badge: '1' },
  ]},
  { title: 'SYSTEM', items: [
    { label: 'Infrastructure', icon: Server },
    { label: 'Settings', icon: Settings },
  ]},
]

function MetricCard({ icon: Icon, label, value, note, tone = 'violet', detail }) {
  return (
    <div className="metric-card">
      <div className="metric-top">
        <div className={`metric-icon ${tone}`}><Icon size={19} /></div>
        <span className="metric-note">{note}</span>
      </div>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      <div className="metric-detail">{detail}</div>
    </div>
  )
}

function App() {
  const [active, setActive] = useState('Overview')
  const [query, setQuery] = useState('')
  const [apiStatus, setApiStatus] = useState('Checking')
  const [apiData, setApiData] = useState(null)
  const [mobileNav, setMobileNav] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(new Date())
  const [vulnerabilities, setVulnerabilities] = useState([])
  const [vulnerabilitiesLoading, setVulnerabilitiesLoading] = useState(true)
  const [vulnerabilitiesError, setVulnerabilitiesError] = useState('')
  const [blastRadius, setBlastRadius] = useState(null)
  const [blastRadiusLoading, setBlastRadiusLoading] = useState(false)
  const [blastRadiusError, setBlastRadiusError] = useState('')
  const [simulation, setSimulation] = useState(null)
  const [simulationLoading, setSimulationLoading] = useState(false)
  const [simulationError, setSimulationError] = useState('')
  const [approvals, setApprovals] = useState([])
  const [approvalLoading, setApprovalLoading] = useState(false)
  const [approvalError, setApprovalError] = useState('')
  const [requestedBy, setRequestedBy] = useState('Security Lead')
  const [decisionBy, setDecisionBy] = useState('Security Lead')
  const [notice, setNotice] = useState('')

  useEffect(() => {
    let alive = true
    async function checkApi() {
      try {
        const response = await fetch('http://127.0.0.1:8000/health')
        if (!response.ok) throw new Error('API unavailable')
        const data = await response.json()
        if (alive) {
          setApiStatus('Connected')
          setApiData(data)
          setLastUpdated(new Date())
        }
      } catch {
        if (alive) setApiStatus('Offline')
      }
    }
    checkApi()
    const timer = setInterval(checkApi, 30000)
    return () => { alive = false; clearInterval(timer) }
  }, [])

  useEffect(() => {
    let alive = true

    async function loadVulnerabilities() {
      try {
        const response = await fetch(
          'http://127.0.0.1:8000/vulnerabilities'
        )

        if (!response.ok) {
          throw new Error(`API returned ${response.status}`)
        }

        const data = await response.json()

        if (alive) {
          setVulnerabilities(data.vulnerabilities || [])
          setVulnerabilitiesError('')
        }
      } catch (error) {
        if (alive) {
          setVulnerabilitiesError(
            error.message || 'Failed to load vulnerabilities'
          )
        }
      } finally {
        if (alive) {
          setVulnerabilitiesLoading(false)
        }
      }
    }

    loadVulnerabilities()

    return () => {
      alive = false
    }
  }, [])

useEffect(() => {
  if (active !== 'Attack Paths') return

  let alive = true

  async function loadBlastRadius() {
    setBlastRadiusLoading(true)
    setBlastRadiusError('')

    try {
      const response = await fetch(
        'http://127.0.0.1:8000/blast-radius/CVE-DEMO-001'
      )

      if (!response.ok) {
        throw new Error(`API returned ${response.status}`)
      }

      const data = await response.json()

      if (alive) {
        setBlastRadius(data)
      }
    } catch (error) {
      if (alive) {
        setBlastRadiusError(
          error.message || 'Failed to load attack path'
        )
      }
    } finally {
      if (alive) {
        setBlastRadiusLoading(false)
      }
    }
  }

  loadBlastRadius()

  return () => {
    alive = false
  }
}, [active])


  async function runSimulation() {
    setSimulationLoading(true); setSimulationError('')
    try {
      const response = await fetch('http://127.0.0.1:8000/simulate-remediation', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ severity: blastRadius?.severity || 'CRITICAL', service_criticality: 'HIGH', affected_services: Math.max(blastRadius?.services?.length || 1, 1) }),
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.detail || `API returned ${response.status}`)
      setSimulation(data)
    } catch (error) { setSimulationError(error.message || 'Simulation failed') }
    finally { setSimulationLoading(false) }
  }

  async function loadApprovals() {
    setApprovalLoading(true); setApprovalError('')
    try {
      const response = await fetch('http://127.0.0.1:8000/approvals')
      const data = await response.json()
      if (!response.ok) throw new Error(data.detail || `API returned ${response.status}`)
      setApprovals(data.approvals || [])
    } catch (error) { setApprovalError(error.message || 'Could not load approvals') }
    finally { setApprovalLoading(false) }
  }

  async function createApproval(action, vulnerabilityId = 'CVE-DEMO-001') {
    setNotice(''); setApprovalError('')
    try {
      const response = await fetch('http://127.0.0.1:8000/approvals', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, vulnerability_id: vulnerabilityId, requested_by: requestedBy }),
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.detail || `API returned ${response.status}`)
      setNotice(`Approval request created: ${data.approval_id}`)
      await loadApprovals()
    } catch (error) { setApprovalError(error.message || 'Could not create approval') }
  }

  async function decideApproval(approvalId, decision) {
    setApprovalError('')
    try {
      const response = await fetch(`http://127.0.0.1:8000/approvals/${approvalId}/decision`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision, decided_by: decisionBy, reason: 'Reviewed in CHAINBREAK dashboard' }),
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.detail || `API returned ${response.status}`)
      setNotice(`Approval ${decision.toLowerCase()}. Remediation was not executed.`)
      await loadApprovals()
    } catch (error) { setApprovalError(error.message || 'Could not update approval') }
  }

  useEffect(() => { if (active === 'Approvals') loadApprovals() }, [active])

  const filteredFindings = vulnerabilities
  .map((item) => ({
    id: item.id,
    name: item.title || 'Untitled advisory',
    package:
      item.id === 'CVE-DEMO-001'
        ? 'log-parser@1.4.2 (demo)'
        : 'requests (advisory source)',
    severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(
      (item.severity || '').toUpperCase()
    )
      ? item.severity.toUpperCase()
      : 'UNKNOWN',
    service:
      item.id === 'CVE-DEMO-001'
        ? 'payment-api (demo)'
        : 'Not mapped',
    age: 'Not provided',
  }))
  .filter((item) =>
    `${item.id} ${item.name} ${item.package} ${item.service} ${item.severity}`
      .toLowerCase()
      .includes(query.toLowerCase())
  )
  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNav ? 'sidebar-open' : ''}`}>
        <div className="brand">
          <div className="brand-mark"><Shield size={22} strokeWidth={2.4} /></div>
          <div><div className="brand-name">CHAIN<span>BREAK</span></div><div className="brand-caption">SUPPLY CHAIN INTELLIGENCE</div></div>
          <button className="mobile-close icon-button" onClick={() => setMobileNav(false)}>×</button>
        </div>

        <div className="workspace-switch">
          <div className="workspace-avatar">AC</div>
          <div className="workspace-text"><strong>Acme Security</strong><span>Demo workspace</span></div>
          <ChevronDown size={15} className="muted-icon" />
        </div>

        {navGroups.map(group => (
          <div className="nav-group" key={group.title}>
            <div className="nav-heading">{group.title}</div>
            {group.items.map(item => {
              const Icon = item.icon
              return (
                <button key={item.label}
                  className={`nav-item ${active === item.label ? 'nav-active' : ''}`}
                  onClick={() => { setActive(item.label); setMobileNav(false) }}>
                  <Icon size={18} />
                  <span>{item.label}</span>
                  {item.badge && <span className="nav-badge">{item.badge}</span>}
                </button>
              )
            })}
          </div>
        ))}

        <div className="sidebar-bottom">
          <div className="security-card">
            <div className="security-card-icon"><ShieldCheck size={19} /></div>
            <strong>Security posture</strong>
            <div className="posture-score"><span>Risk overview</span><b>Demo</b></div>
            <div className="posture-track"><div /></div>
            <span className="security-caption">Illustrative demo data</span>
          </div>
          <div className="profile-row">
            <div className="profile-avatar">SL</div>
            <div className="profile-info"><strong>Security Lead</strong><span>Administrator</span></div>
            <Settings size={17} className="muted-icon" />
          </div>
        </div>
      </aside>

      {mobileNav && <div className="mobile-overlay" onClick={() => setMobileNav(false)} />}

      <main className="main-area">
        <header className="topbar">
          <div className="topbar-left">
            <button className="icon-button menu-toggle" onClick={() => setMobileNav(true)}><Menu size={20} /></button>
            <div className="breadcrumb">Workspace <span>/</span> <strong>{active}</strong></div>
          </div>
          <div className="topbar-actions">
            <label className="search-box">
              <Search size={17} />
              <input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search findings..." />
              <kbd>⌘ K</kbd>
            </label>
            <button className="icon-button notification-button" title="Notifications"><Bell size={18} /><i /></button>
            <div className="topbar-divider" />
            <div className="top-profile"><div className="profile-avatar">SL</div><span>Security Lead</span><ChevronDown size={15} /></div>
          </div>
        </header>

        <div className="page-content">
          <section className="page-heading">
            <div>
              <div className="eyebrow"><span className="live-dot" /> SECURITY OPERATIONS CENTER</div>
              <h1>{active === 'Overview' ? 'Security overview' : active}</h1>
              <p>Map vulnerabilities to the infrastructure they could impact.</p>
            </div>
            <div className="heading-actions">
              <span className={`connection-pill ${apiStatus === 'Connected' ? 'connected' : apiStatus === 'Offline' ? 'offline' : ''}`}>
                <span className="status-dot" /> API {apiStatus}
              </span>
              <button className="secondary-button" onClick={() => window.location.reload()}><RefreshCw size={15} /> Refresh</button>
            </div>
          </section>

                    {active === 'Vulnerabilities' ? (
            <section className="panel findings-panel vulnerabilities-page">
              <div className="panel-heading findings-heading">
                <div>
                  <h3>Vulnerability findings</h3>
                  <p>Live advisory records returned by the CHAINBREAK API</p>
                </div>
                <span className="status-chip status-demo">
                  {vulnerabilities.length} records
                </span>
              </div>

              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>ADVISORY</th>
                      <th>ID</th>
                      <th>PACKAGE</th>
                      <th>SEVERITY</th>
                      <th>IMPACT</th>
                    </tr>
                  </thead>
                  <tbody>
                    {vulnerabilitiesLoading ? (
                      <tr>
                        <td colSpan="5" className="empty-state">
                          Loading vulnerabilities...
                        </td>
                      </tr>
                    ) : vulnerabilitiesError ? (
                      <tr>
                        <td colSpan="5" className="empty-state">
                          {vulnerabilitiesError}
                        </td>
                      </tr>
                    ) : filteredFindings.length ? (
                      filteredFindings.map((item) => (
                        <tr key={item.id}>
                          <td>
                            <div className="finding-cell">
                              <div className="finding-icon sev-medium">
                                <Bug size={16} />
                              </div>
                              <strong>{item.name}</strong>
                            </div>
                          </td>
                          <td><code>{item.id}</code></td>
                          <td><code>{item.package}</code></td>
                          <td>
                            <span
                              className={`severity-pill sev-pill-${
                                ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(item.severity)
                                  ? item.severity.toLowerCase()
                                  : 'medium'
                              }`}
                            >
                              <span />
                              {item.severity}
                            </span>
                          </td>
                          <td>
                            <span className="service-name">
                              <Server size={14} />
                              {item.service}
                            </span>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan="5" className="empty-state">
                          No matching vulnerability records.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              <div className="table-footer">
                <span>Showing {filteredFindings.length} of {vulnerabilities.length} records</span>
                <span className="footer-note">
                  <CircleDot size={12} /> Unmapped infrastructure is not assumed vulnerable
                </span>
              </div>
            </section>
                    ) : active === 'Attack Paths' ? (
            <section className="panel workspace-panel">
              <div className="panel-heading"><div><h3>Blast-radius analysis</h3><p>Live dependency and deployment relationships from FalkorDB</p></div><button className="secondary-button" onClick={() => setActive('Vulnerabilities')}>Choose finding</button></div>
              {blastRadiusLoading ? <p className="page-message">Tracing graph relationships...</p> : blastRadiusError ? <p className="page-message error-message">{blastRadiusError}</p> : blastRadius ? <>
                <div className="path-summary"><span className="severity-pill sev-pill-critical"><span />{blastRadius.severity || 'UNKNOWN'}</span><strong>{blastRadius.vulnerability}</strong><p>{blastRadius.title}</p></div>
                <div className="attack-chain">
                  <div className="chain-node"><Bug size={20}/><small>VULNERABILITY</small><strong>{blastRadius.vulnerability}</strong></div><ArrowDownRight className="chain-arrow"/>
                  <div className="chain-node"><Package size={20}/><small>AFFECTED PACKAGE</small><strong>{(blastRadius.packages || []).filter(Boolean).join(', ') || 'No package mapped'}</strong></div><ArrowDownRight className="chain-arrow"/>
                  <div className="chain-node"><GitBranch size={20}/><small>REPOSITORY</small><strong>{(blastRadius.repositories || []).filter(Boolean).join(', ') || 'No repository mapped'}</strong></div><ArrowDownRight className="chain-arrow"/>
                  <div className="chain-node"><Server size={20}/><small>DEPLOYED SERVICE</small><strong>{(blastRadius.services || []).filter(Boolean).join(', ') || 'No service mapped'}</strong></div>
                </div>
                <div className="notice-box"><Shield size={16}/><span>{blastRadius.note} Demo topology is synthetic; advisory records alone do not prove production exposure.</span></div>
              </> : <p className="page-message">No blast-radius data available.</p>}
            </section>
          ) : active === 'Remediation' ? (
            <section className="panel workspace-panel">
              <div className="panel-heading"><div><h3>Remediation planner</h3><p>Compare proposed actions before requesting approval</p></div><button className="primary-button" onClick={runSimulation} disabled={simulationLoading}>{simulationLoading ? 'Simulating...' : 'Run simulation'}</button></div>
              <div className="notice-box"><Shield size={16}/><span>Simulation only. Estimates do not modify infrastructure.</span></div>
              {simulationError && <p className="page-message error-message">{simulationError}</p>}
              {!simulation && !simulationLoading && <p className="page-message">Run the simulation to rank remediation options using the backend risk model.</p>}
              {simulation && <><div className="metric-strip"><div><small>Estimated base risk</small><strong>{simulation.estimated_base_risk}</strong></div><div><small>Severity</small><strong>{simulation.severity}</strong></div><div><small>Affected services</small><strong>{simulation.affected_services}</strong></div></div>
                <div className="option-list">{simulation.recommendations?.map((item, index) => <article className="option-card" key={item.name}><div className="option-rank">0{index + 1}</div><div className="option-main"><strong>{item.name}</strong><p>{item.description}</p><small>Risk reduction {item.estimated_risk_reduction_percent}% · Estimated risk after {item.estimated_risk_after} · Approval required</small></div><button className="secondary-button" onClick={() => { setActive('Approvals'); createApproval(item.name) }}>Request approval</button></article>)}</div><p className="page-message">{simulation.notice}</p></>}
            </section>
          ) : active === 'Approvals' ? (
            <section className="panel workspace-panel">
              <div className="panel-heading"><div><h3>Approval queue</h3><p>Authorization records only — no automated execution</p></div><button className="secondary-button" onClick={loadApprovals} disabled={approvalLoading}>{approvalLoading ? 'Loading...' : 'Refresh queue'}</button></div>
              <div className="approval-toolbar"><label>Requester <input value={requestedBy} onChange={e => setRequestedBy(e.target.value)} /></label><label>Reviewer <input value={decisionBy} onChange={e => setDecisionBy(e.target.value)} /></label><button className="primary-button" onClick={() => createApproval('Upgrade vulnerable package')}>+ New approval request</button></div>
              {notice && <p className="success-message">{notice}</p>}{approvalError && <p className="page-message error-message">{approvalError}</p>}
              {approvalLoading ? <p className="page-message">Loading approval records...</p> : approvals.length ? <div className="option-list">{approvals.map(item => <article className="option-card" key={item.approval_id}><div className="option-main"><strong>{item.action}</strong><p>{item.vulnerability_id} · Requested by {item.requested_by}</p><small>Status: {item.status} · Execution: {item.execution_status}</small></div>{item.status === 'PENDING' && <div className="button-pair"><button className="primary-button" onClick={() => decideApproval(item.approval_id, 'APPROVED')}>Approve</button><button className="secondary-button" onClick={() => decideApproval(item.approval_id, 'REJECTED')}>Reject</button></div>}</article>)}</div> : <p className="page-message">No approval records found. Create a request to start the approval workflow.</p>}
            </section>
          ) : active === 'Infrastructure' ? (
            <section className="panel workspace-panel">
              <div className="panel-heading"><div><h3>Infrastructure inventory</h3><p>Entities in the current demo blast-radius path</p></div><span className="status-chip status-demo">Graph-backed</span></div>
              {blastRadius ? <div className="inventory-grid">{[['Packages', blastRadius.packages], ['Repositories', blastRadius.repositories], ['Services', blastRadius.services]].map(([label, values]) => <div className="inventory-card" key={label}><span>{label}</span><strong>{(values || []).filter(Boolean).length}</strong>{(values || []).filter(Boolean).map(value => <code key={value}>{value}</code>)}</div>)}</div> : <p className="page-message">Open Attack Paths to load graph inventory, then return here.</p>}
              <div className="notice-box"><Shield size={16}/><span>The current topology contains synthetic demo infrastructure. Unmapped advisory records are not assumed to affect production services.</span></div>
            </section>
          ) : active === 'Settings' ? (
            <section className="panel workspace-panel">
              <div className="panel-heading"><div><h3>Workspace settings</h3><p>Connection and safety configuration</p></div></div>
              <div className="settings-list"><div><span>API endpoint</span><code>http://127.0.0.1:8000</code><b className={apiStatus === 'Connected' ? 'text-success' : 'text-muted'}>{apiStatus}</b></div><div><span>Graph database</span><strong>FalkorDB</strong><b>Configured in backend environment</b></div><div><span>Approval gate</span><strong>Required for every recommendation</strong><b>No remediation executes from this UI</b></div><div><span>Data labeling</span><strong>Advisories + synthetic demo topology</strong><b>Production impact must be verified</b></div></div>
              <button className="secondary-button" onClick={() => window.location.reload()}><RefreshCw size={15}/> Reload dashboard</button>
            </section>
          ) : (
            <>
              <section className="hero-banner">
            <div className="hero-grid-pattern" />
            <div className="hero-copy">
              <div className="hero-tag"><Zap size={13} /> GRAPH-POWERED SECURITY</div>
              <h2>See the impact.<br /><span>Break the attack chain.</span></h2>
              <p>Trace a vulnerability from package to repository to production service — and plan a safer fix.</p>
              <button className="hero-button" onClick={() => setActive('Attack Paths')}>Explore attack paths <ArrowUpRight size={16} /></button>
            </div>
            <div className="hero-visual" aria-label="Illustrative software supply chain graph">
              <div className="orbit orbit-one" /><div className="orbit orbit-two" />
              <svg className="graph-lines" viewBox="0 0 390 220" fill="none">
                <path d="M65 110 L150 55 L230 100 L325 45 M150 55 L170 165 L230 100 L320 170 M65 110 L170 165 L320 170" stroke="url(#lineGradient)" strokeWidth="1.5" strokeDasharray="5 5" />
                <defs><linearGradient id="lineGradient"><stop stopColor="#8B5CF6" /><stop offset="1" stopColor="#22D3EE" /></linearGradient></defs>
              </svg>
              <div className="graph-node node-vuln"><Bug size={19} /><span>Vulnerability</span><b>CVE-DEMO-001</b></div>
              <div className="graph-node node-package"><Package size={19} /><span>Package</span><b>log-parser</b></div>
              <div className="graph-node node-repo"><GitBranch size={19} /><span>Repository</span><b>payment-service</b></div>
              <div className="graph-node node-service"><Server size={19} /><span>Service</span><b>payment-api</b></div>
              <div className="graph-center-badge"><Activity size={15} /> IMPACT PATH</div>
            </div>
          </section>

          <section className="metrics-grid">
            <MetricCard icon={AlertTriangle} label="Critical findings" value="01" note="Needs review" tone="red" detail="1 illustrative critical path" />
            <MetricCard icon={Package} label="Packages tracked" value="16" note="OSV records" tone="violet" detail="Advisory records imported" />
            <MetricCard icon={Server} label="Impacted services" value="01" note="Demo topology" tone="cyan" detail="Synthetic infrastructure" />
            <MetricCard icon={ClipboardCheck} label="Pending approvals" value="00" note="Queue status" tone="amber" detail="Check approval records below" />
          </section>

          <section className="content-grid">
            <div className="panel activity-panel">
              <div className="panel-heading">
                <div><h3>Finding activity</h3><p>Illustrative weekly trend</p></div>
                <button className="select-button">Last 7 days <ChevronDown size={14} /></button>
              </div>
              <div className="chart-legend"><span><i className="legend-violet" /> Findings</span><span><i className="legend-cyan" /> Resolved</span></div>
              <div className="chart-wrap">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={activityData} margin={{ top: 8, right: 5, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="findingsFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#8B5CF6" stopOpacity={0.25} /><stop offset="100%" stopColor="#8B5CF6" stopOpacity={0} /></linearGradient>
                      <linearGradient id="resolvedFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#22D3EE" stopOpacity={0.17} /><stop offset="100%" stopColor="#22D3EE" stopOpacity={0} /></linearGradient>
                    </defs>
                    <CartesianGrid stroke="#20283A" strokeDasharray="4 5" vertical={false} />
                    <XAxis dataKey="day" tick={{ fill: '#8791A7', fontSize: 11 }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: '#8791A7', fontSize: 11 }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={{ background: '#111827', border: '1px solid #2B3549', borderRadius: 10, color: '#F3F4F6' }} />
                    <Area type="monotone" dataKey="findings" stroke="#9B7BFF" strokeWidth={2.5} fill="url(#findingsFill)" />
                    <Area type="monotone" dataKey="resolved" stroke="#22D3EE" strokeWidth={2} fill="url(#resolvedFill)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="panel posture-panel">
              <div className="panel-heading"><div><h3>Response readiness</h3><p>Demo workflow status</p></div><ShieldCheck size={19} className="accent-icon" /></div>
              <div className="readiness-score"><div className="readiness-ring"><div><strong>3</strong><span>STAGES</span></div></div><div><strong className="readiness-title">Approval-gated</strong><p>Remediation workflow</p><span className="status-chip status-demo">Demo mode</span></div></div>
              <div className="readiness-list">
                <div><span className="readiness-check"><CheckCircle2 size={15} /></span><span>Impact analysis</span><b>Ready</b></div>
                <div><span className="readiness-check"><CheckCircle2 size={15} /></span><span>Approval records</span><b>Tracked</b></div>
                <div><span className="readiness-pending"><Clock size={15} /></span><span>Execute remediation</span><b>Manual</b></div>
              </div>
              <div className="notice-box"><Shield size={16} /><span>Approvals are recorded separately from execution. No production changes are made by this dashboard.</span></div>
            </div>
          </section>

          <section className="panel findings-panel">
            <div className="panel-heading findings-heading">
              <div><h3>Recent findings</h3><p>Advisory records and clearly labeled demo topology</p></div>
              <button className="text-button" onClick={() => setActive('Vulnerabilities')}>View all <ArrowUpRight size={15} /></button>
            </div>
            <div className="table-scroll">
              <table>
                <thead><tr><th>FINDING</th><th>PACKAGE</th><th>SEVERITY</th><th>IMPACTED SERVICE</th><th>DISCOVERED</th><th /></tr></thead>
                <tbody>
  {vulnerabilitiesLoading ? (
    <tr>
      <td colSpan="6" className="empty-state">
        Loading vulnerabilities from FalkorDB...
      </td>
    </tr>
  ) : vulnerabilitiesError ? (
    <tr>
      <td colSpan="6" className="empty-state">
        Unable to load vulnerabilities: {vulnerabilitiesError}
      </td>
    </tr>
  ) : filteredFindings.length > 0 ? (
    filteredFindings.map((item) => (
      <tr key={item.id}>
        <td>
          <div className="finding-cell">
            <div
              className={`finding-icon sev-${
                ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(item.severity)
                  ? item.severity.toLowerCase()
                  : 'medium'
              }`}
            >
              <Bug size={16} />
            </div>
            <div>
              <strong>{item.name}</strong>
              <span>{item.id}</span>
            </div>
          </div>
        </td>

        <td>
          <code>{item.package}</code>
        </td>

        <td>
          <span
            className={`severity-pill sev-pill-${
              ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(item.severity)
                ? item.severity.toLowerCase()
                : 'medium'
            }`}
          >
            <span />
            {item.severity}
          </span>
        </td>

        <td>
          <span className="service-name">
            <Server size={14} />
            {item.service}
          </span>
        </td>

        <td className="time-cell">{item.age}</td>

        <td>
          <button
            className="row-action"
            title="View details"
            onClick={() => setActive('Attack Paths')}
          >
            <ArrowUpRight size={16} />
          </button>
        </td>
      </tr>
    ))
  ) : (
    <tr>
      <td colSpan="6" className="empty-state">
        {query
          ? 'No findings match your search.'
          : 'No vulnerability records found.'}
      </td>
    </tr>
  )}
</tbody>
              </table>
            </div>
            <div className="table-footer"><span>Showing {filteredFindings.length} advisory records</span><span className="footer-note"><CircleDot size={12} /> Data includes synthetic demo infrastructure</span></div>
                                  </section>
            </>
          )}

          <footer className="footer">
            <span>
              CHAINBREAK <b>·</b> Supply Chain Security Intelligence
            </span>

            <span>
              <span
                className={`status-dot ${
                  apiStatus === 'Connected' ? 'status-green' : ''
                }`}
              />
              API {apiStatus} <b>·</b> Updated{' '}
              {lastUpdated.toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit',
              })}
            </span>
          </footer>
        </div>
      </main>
    </div>
  )
}

export default App
