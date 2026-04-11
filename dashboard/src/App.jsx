import { useState, useMemo, useCallback, useRef } from 'react'
import {
  Shield, AlertTriangle, AlertOctagon, CheckCircle,
  Upload, Search, Filter, ChevronDown, ChevronUp,
  Server, Lock, Cloud, Activity, BarChart2, X
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend
} from 'recharts'
import { SAMPLE_REPORT } from './sampleData'
import styles from './App.module.css'

// ─── Severity config ───────────────────────────────────────────────────────
const SEV = {
  CRITICAL: { color: '#ef4444', label: 'Critical', icon: AlertOctagon },
  HIGH:     { color: '#f97316', label: 'High',     icon: AlertTriangle },
  MEDIUM:   { color: '#eab308', label: 'Medium',   icon: AlertTriangle },
  LOW:      { color: '#3b82f6', label: 'Low',      icon: CheckCircle },
  INFO:     { color: '#6b7280', label: 'Info',      icon: CheckCircle },
}

const CHECK_ICONS = {
  'S3-001': Cloud,
  'IAM-001': Lock,
  'IAM-002': Lock,
  'EC2-001': Server,
  'CT-001':  Activity,
}

// ─── Small components ───────────────────────────────────────────────────────

function SeverityBadge({ severity }) {
  const cfg = SEV[severity] || SEV.INFO
  return (
    <span className={styles.badge} style={{ background: cfg.color }}>
      {severity}
    </span>
  )
}

function StatCard({ label, value, color, icon: Icon }) {
  return (
    <div className={styles.statCard} style={{ '--accent-c': color }}>
      <div className={styles.statIcon}><Icon size={22} color={color} /></div>
      <div>
        <div className={styles.statValue} style={{ color }}>{value}</div>
        <div className={styles.statLabel}>{label}</div>
      </div>
    </div>
  )
}

function FindingRow({ finding }) {
  const [open, setOpen] = useState(false)
  const CheckIcon = CHECK_ICONS[finding.check_id] || Shield
  const sevCfg = SEV[finding.severity] || SEV.INFO

  return (
    <>
      <tr
        className={styles.findingRow}
        onClick={() => setOpen(o => !o)}
        style={{ '--sev-color': sevCfg.color }}
      >
        <td><SeverityBadge severity={finding.severity} /></td>
        <td>
          <span className={styles.checkIdPill}>
            <CheckIcon size={13} style={{ marginRight: 4 }} />
            {finding.check_id}
          </span>
        </td>
        <td className={styles.checkName}>{finding.check_name}</td>
        <td className={`${styles.resourceId} mono truncate`} title={finding.resource_id}>
          {finding.resource_id.replace(/^arn:aws:[^:]+::[^:]+:/, '…/')}
        </td>
        <td>{finding.region}</td>
        <td className={styles.descCell}>{finding.description}</td>
        <td>
          <button className={styles.expandBtn} aria-label="Toggle details">
            {open ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>
        </td>
      </tr>
      {open && (
        <tr className={styles.detailRow}>
          <td colSpan={7}>
            <div className={styles.detailGrid}>
              <div>
                <h4>💡 Recommendation</h4>
                <p>{finding.recommendation}</p>
              </div>
              <div>
                <h4>🔬 Technical Details</h4>
                <pre>{JSON.stringify(finding.details, null, 2)}</pre>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ─── Main App ───────────────────────────────────────────────────────────────

export default function App() {
  const [report, setReport] = useState(SAMPLE_REPORT)
  const [search, setSearch] = useState('')
  const [sevFilter, setSevFilter] = useState('ALL')
  const [checkFilter, setCheckFilter] = useState('ALL')
  const [isDragging, setIsDragging] = useState(false)
  const fileInputRef = useRef(null)

  // Load a JSON report file
  const loadReport = useCallback((file) => {
    const reader = new FileReader()
    reader.onload = (e) => {
      try {
        const parsed = JSON.parse(e.target.result)
        setReport(parsed)
        setSearch('')
        setSevFilter('ALL')
        setCheckFilter('ALL')
      } catch {
        alert('Invalid JSON file.')
      }
    }
    reader.readAsText(file)
  }, [])

  const handleFileChange = (e) => {
    if (e.target.files[0]) loadReport(e.target.files[0])
  }

  const handleDrop = (e) => {
    e.preventDefault()
    setIsDragging(false)
    const file = e.dataTransfer.files[0]
    if (file?.name.endsWith('.json')) loadReport(file)
  }

  // Derived data
  const summary = report?.summary || {}
  const findings = report?.findings || []
  const bySeverity = summary.by_severity || {}
  const byCheck    = summary.by_check    || {}

  const pieData = Object.entries(bySeverity)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))

  const barData = Object.entries(byCheck).map(([id, count]) => ({ id, count }))

  const filteredFindings = useMemo(() => {
    const q = search.toLowerCase()
    return findings.filter(f => {
      const sevOk = sevFilter === 'ALL' || f.severity === sevFilter
      const chkOk = checkFilter === 'ALL' || f.check_id === checkFilter
      const txtOk = !q || [f.description, f.resource_id, f.check_name, f.check_id]
        .join(' ').toLowerCase().includes(q)
      return sevOk && chkOk && txtOk
    })
  }, [findings, sevFilter, checkFilter, search])

  const checkIds = [...new Set(findings.map(f => f.check_id))]

  const CustomTooltip = ({ active, payload }) => {
    if (!active || !payload?.length) return null
    return (
      <div className={styles.chartTooltip}>
        <strong>{payload[0].name || payload[0].payload.id}</strong>: {payload[0].value}
      </div>
    )
  }

  return (
    <div className={styles.app}>
      {/* Header */}
      <header className={styles.header}>
        <div className={styles.headerInner}>
          <div className={styles.logo}><Shield size={28} /></div>
          <div>
            <h1 className={styles.title}>AWS Security Audit</h1>
            <p className={styles.subtitle}>Account: <strong>{report?.account_id || '—'}</strong></p>
          </div>
          <div className={styles.headerRight}>
            <div className={styles.scanTimePill}>
              🕐 {report?.scan_time ? new Date(report.scan_time).toLocaleString() : '—'}
            </div>
            <button className={styles.uploadBtn} onClick={() => fileInputRef.current.click()}>
              <Upload size={15} /> Load Report
            </button>
            <input ref={fileInputRef} type="file" accept=".json" onChange={handleFileChange} hidden />
          </div>
        </div>
      </header>

      <main className={styles.main}>

        {/* Drop zone hint */}
        <div
          className={`${styles.dropZone} ${isDragging ? styles.dragging : ''}`}
          onDragOver={e => { e.preventDefault(); setIsDragging(true) }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
        >
          Drop a JSON report here
        </div>

        {/* Stat cards */}
        <section className={styles.statsRow}>
          <StatCard label="Total Findings" value={summary.total ?? 0}   color="#6366f1" icon={Shield} />
          <StatCard label="Critical"        value={bySeverity.CRITICAL ?? 0} color="#ef4444" icon={AlertOctagon} />
          <StatCard label="High"            value={bySeverity.HIGH ?? 0}     color="#f97316" icon={AlertTriangle} />
          <StatCard label="Medium"          value={bySeverity.MEDIUM ?? 0}   color="#eab308" icon={AlertTriangle} />
          <StatCard label="Low"             value={bySeverity.LOW ?? 0}      color="#3b82f6" icon={CheckCircle} />
        </section>

        {/* Charts */}
        <section className={styles.chartsRow}>
          <div className={styles.chartCard}>
            <h3 className={styles.chartTitle}><BarChart2 size={16} /> Findings by Check</h3>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={barData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                <XAxis dataKey="id" tick={{ fill: '#8899b8', fontSize: 12, fontFamily: 'JetBrains Mono' }} />
                <YAxis tick={{ fill: '#8899b8', fontSize: 11 }} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" fill="#6366f1" radius={[5, 5, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className={styles.chartCard}>
            <h3 className={styles.chartTitle}><Shield size={16} /> Severity Distribution</h3>
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%"
                  innerRadius={55} outerRadius={85} paddingAngle={3}>
                  {pieData.map(({ name }) => (
                    <Cell key={name} fill={SEV[name]?.color || '#6b7280'} />
                  ))}
                </Pie>
                <Legend formatter={(v) => <span style={{ color: '#8899b8', fontSize: 12 }}>{v}</span>} />
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </section>

        {/* Findings table */}
        <section className={styles.tableSection}>
          <div className={styles.tableHeader}>
            <h3 className={styles.tableTitle}>
              Findings <span className={styles.findingCount}>{filteredFindings.length} / {findings.length}</span>
            </h3>
            <div className={styles.controls}>
              <div className={styles.searchWrap}>
                <Search size={15} className={styles.searchIcon} />
                <input
                  className={styles.searchInput}
                  placeholder="Search findings…"
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                />
                {search && <button className={styles.clearBtn} onClick={() => setSearch('')}><X size={13} /></button>}
              </div>

              <div className={styles.filterGroup}>
                <Filter size={14} style={{ color: 'var(--text-muted)' }} />
                {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
                  <button
                    key={s}
                    className={`${styles.filterBtn} ${sevFilter === s ? styles.filterActive : ''}`}
                    style={s !== 'ALL' ? { '--fc': SEV[s]?.color } : {}}
                    onClick={() => setSevFilter(s)}
                  >
                    {s}
                  </button>
                ))}
              </div>

              <select
                className={styles.checkSelect}
                value={checkFilter}
                onChange={e => setCheckFilter(e.target.value)}
              >
                <option value="ALL">All Checks</option>
                {checkIds.map(id => <option key={id} value={id}>{id}</option>)}
              </select>
            </div>
          </div>

          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>Severity</th><th>Check ID</th><th>Check Name</th>
                  <th>Resource</th><th>Region</th><th>Description</th><th></th>
                </tr>
              </thead>
              <tbody>
                {filteredFindings.length === 0 ? (
                  <tr><td colSpan={7} className={styles.emptyRow}>No findings match your filters.</td></tr>
                ) : (
                  filteredFindings.map((f, i) => <FindingRow key={i} finding={f} />)
                )}
              </tbody>
            </table>
          </div>
        </section>

      </main>

      <footer className={styles.footer}>
        AWS Security Audit Tool &mdash; {new Date().getFullYear()}
      </footer>
    </div>
  )
}
