import React, { useEffect, useRef, useState } from 'react'

function cls(...a) { return a.filter(Boolean).join(' ') }

export default function App() {
  const fileRef = useRef(null)
  const [kcfgLoaded, setKcfgLoaded] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [results, setResults] = useState(null)
  const [sidebarW, setSidebarW] = useState(360)
  const [dragging, setDragging] = useState(false)
  const [showPolicyPath, setShowPolicyPath] = useState(false)
  const [epIndex, setEpIndex] = useState([])
  const [srcSel, setSrcSel] = useState('')
  const [dstSel, setDstSel] = useState('')
  const [testRunning, setTestRunning] = useState(false)
  const [testError, setTestError] = useState('')
  const [testHits, setTestHits] = useState({ egress: [], ingress: [] })
  const [testResults, setTestResults] = useState([])
  const [testProto, setTestProto] = useState('')
  const [testPort, setTestPort] = useState('')
  const [pwruOutput, setPwruOutput] = useState('')
  const [pwruRunning, setPwruRunning] = useState(false)
  const [relevantPolicies, setRelevantPolicies] = useState([])
  const [relevantError, setRelevantError] = useState('')
  const [liveOutput, setLiveOutput] = useState(false)
  const [lastAction, setLastAction] = useState('')
  const [prevPolicyLines, setPrevPolicyLines] = useState({})
  const [incPolicyLines, setIncPolicyLines] = useState({})
  const [prevPathLines, setPrevPathLines] = useState({ egress: new Set(), ingress: new Set() })
  const [incPathLines, setIncPathLines] = useState({ egress: new Set(), ingress: new Set() })
  const [pcapSrcOut, setPcapSrcOut] = useState('')
  const [pcapDstOut, setPcapDstOut] = useState('')
  const [pcapSrcLoading, setPcapSrcLoading] = useState(false)
  const [pcapDstLoading, setPcapDstLoading] = useState(false)
  const pcapSrcCaptureIdRef = useRef(null)
  const pcapDstCaptureIdRef = useRef(null)

  // On mount, check if server has a default kubeconfig by probing a lightweight endpoint
  useEffect(() => {
    const checkDefaultKubeconfig = async () => {
      try {
        const r = await fetch('/api/endpoints', { credentials: 'same-origin' })
        if (r.ok) {
          setKcfgLoaded(true)
        }
      } catch {}
    }
    checkDefaultKubeconfig()
  }, [])

  const runTcpdump = async (which) => {
    try {
      const p = results?.path || {}
      const node = which === 'src' ? p.src : p.dst
      const ns = String(node?.ns || '').trim()
      const pod = String(node?.pod || '').trim()
      if (!ns || !pod) return
      const captureId = `${ns}-${pod}-${Date.now()}`
      if (which === 'src') {
        setPcapSrcLoading(true)
        setPcapSrcOut('')
        pcapSrcCaptureIdRef.current = captureId
      } else {
        setPcapDstLoading(true)
        setPcapDstOut('')
        pcapDstCaptureIdRef.current = captureId
      }
      const r = await fetch('/api/tcpdump', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ns, pod, durationSeconds: 60, captureId })
      })
      const j = await r.json()
      const cmdLine = j?.args ? `Command: ${j.args.join(' ')}\n\n` : ''
      const text = cmdLine + (j?.stdout || j?.stderr || j?.error || '')
      if (which === 'src') setPcapSrcOut(text); else setPcapDstOut(text)
    } catch (e) {
      const msg = String(e.message || e)
      if (which === 'src') setPcapSrcOut(msg); else setPcapDstOut(msg)
    } finally {
      if (which === 'src') {
        setPcapSrcLoading(false)
        pcapSrcCaptureIdRef.current = null
      } else {
        setPcapDstLoading(false)
        pcapDstCaptureIdRef.current = null
      }
    }
  }

  const stopTcpdump = async (which) => {
    const captureId = which === 'src' ? pcapSrcCaptureIdRef.current : pcapDstCaptureIdRef.current
    if (!captureId) return
    try {
      await fetch('/api/tcpdump/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ captureId })
      })
      // The main tcpdump request will complete and show results
    } catch (e) {
      console.error('Failed to stop capture:', e)
    }
  }

  useEffect(() => {
    if (!dragging) return
    const onMove = (e) => {
      // Constrain sidebar width between 140 and 700px
      const next = Math.min(700, Math.max(140, e.clientX - 24))
      setSidebarW(next)
    }
    const onUp = () => setDragging(false)
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
    return () => {
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
    }
  }, [dragging])

  // Auto-refresh Output when Show Policies or Policy Path is active and Output Live is ON
  useEffect(() => {
    if (!liveOutput) return
    if (lastAction !== 'policies' && lastAction !== 'policy-path') return
    let cancelled = false
    const tick = async () => {
      if (cancelled) return
      if (lastAction === 'policies') await refreshPolicies()
      else if (lastAction === 'policy-path') await refreshPolicyPath()
    }
    // Immediate refresh, then every 5s
    tick()
    const h = setInterval(tick, 5000)
    return () => { cancelled = true; clearInterval(h) }
  }, [liveOutput, lastAction, srcSel, dstSel])

  // When turning live ON in Show Policies, capture current output as baseline to prevent initial mass-highlight
  useEffect(() => {
    if (!(liveOutput && lastAction === 'policies' && results && Array.isArray(results.results))) return
    const baseline = {}
    for (const r of results.results) {
      if (!r || !r.ok) continue
      const lines = String(r.output || '').split('\n')
      const headerIdx = lines.findIndex(l => /\bPOLICY\b/.test(l) && /\bPACKETS\b/.test(l))
      const set = new Set()
      if (headerIdx >= 0) {
        for (let i = headerIdx + 1; i < lines.length; i++) {
          const ln = lines[i]
          if (!ln || !ln.trim()) continue
          if (/^Endpoint ID:/i.test(ln) || /^Path:/i.test(ln) || /\bPOLICY\b/.test(ln)) continue
          set.add(ln)
        }
      }
      baseline[r.pod] = set
    }
    setPrevPolicyLines(baseline)
    setIncPolicyLines({})
  }, [liveOutput, lastAction])

  // When turning live ON in Policy Path, capture current output as baseline
  useEffect(() => {
    if (!(liveOutput && lastAction === 'policy-path' && results)) return
    const egressSet = new Set()
    const ingressSet = new Set()
    const egressBody = String(results.srcGetEgress || '').split('\n').filter(Boolean)
    const ingressBody = String(results.dstGetIngress || '').split('\n').filter(Boolean)
    egressBody.forEach(ln => egressSet.add(ln))
    ingressBody.forEach(ln => ingressSet.add(ln))
    setPrevPathLines({ egress: egressSet, ingress: ingressSet })
    setIncPathLines({ egress: new Set(), ingress: new Set() })
  }, [liveOutput, lastAction])

  // When policies results change, compute which policy rows changed (string diff) per pod
  useEffect(() => {
    if (lastAction !== 'policies' || !results || !Array.isArray(results.results)) return
    const nextPrev = {}
    const nextInc = {}
    for (const r of results.results) {
      if (!r || !r.ok) continue
      const pod = r.pod
      const text = String(r.output || '')
      const lines = text.split('\n')
      const prevSet = prevPolicyLines[pod] || new Set()
      const curSet = new Set()
      const incSet = new Set()
      // find header with Cilium BPF table
      const headerIdx = lines.findIndex(l => /\bPOLICY\b/.test(l) && /\bPACKETS\b/.test(l))
      if (headerIdx >= 0) {
        for (let i = headerIdx + 1; i < lines.length; i++) {
          const ln = lines[i]
          if (!ln || !ln.trim()) continue
          if (/^Endpoint ID:/i.test(ln) || /^Path:/i.test(ln) || /\bPOLICY\b/.test(ln)) continue
          const key = ln
          curSet.add(key)
          if (prevSet.size > 0 && !prevSet.has(key)) incSet.add(key)
        }
      }
      nextPrev[pod] = curSet
      if (incSet.size) nextInc[pod] = incSet
    }
    setPrevPolicyLines(nextPrev)
    setIncPolicyLines(nextInc)
  }, [results, lastAction])

  // When policy-path results change, compute which rows changed
  useEffect(() => {
    if (lastAction !== 'policy-path' || !results) return
    const egressBody = String(results.srcGetEgress || '').split('\n').filter(Boolean)
    const ingressBody = String(results.dstGetIngress || '').split('\n').filter(Boolean)
    const prevEgress = prevPathLines.egress
    const prevIngress = prevPathLines.ingress
    const curEgress = new Set(egressBody)
    const curIngress = new Set(ingressBody)
    const incEgress = new Set()
    const incIngress = new Set()
    if (prevEgress.size > 0) {
      egressBody.forEach(ln => { if (!prevEgress.has(ln)) incEgress.add(ln) })
    }
    if (prevIngress.size > 0) {
      ingressBody.forEach(ln => { if (!prevIngress.has(ln)) incIngress.add(ln) })
    }
    setPrevPathLines({ egress: curEgress, ingress: curIngress })
    setIncPathLines({ egress: incEgress, ingress: incIngress })
  }, [results, lastAction])

  const runPolicyRelevant = () => {
    try {
      setRelevantError('')
      const deriveId = (key) => {
        const top = results?.[key]
        if (top) return top
        const arr = Array.isArray(results?.results) ? results.results : []
        for (const r of arr) { if (r && r.ok && typeof r[key] !== 'undefined') return r[key] }
        return undefined
      }
      const srcIdVal = deriveId('srcIdentity')
      const dstIdVal = deriveId('dstIdentity')
      if (!srcIdVal || !dstIdVal) { setRelevantError('Missing identities; run Policy Path again'); return }
      // Collect identities in egress/ingress tables
      const ok = (results?.results || []).filter(x => x.ok)
      const hdrPrefix = 'IDENTITY'
      const idsIn = (key) => {
        const set = new Set()
        for (const r of ok) {
          const s = r[key]
          if (!s) continue
          const lines = String(s).split('\n')
          for (const line of lines) {
            if (!line || line.startsWith(hdrPrefix)) continue
            const parts = String(line).trim().split(/\s+/)
            if (!parts.length) continue
            let tok = parts[0]; let n = Number(tok)
            if (Number.isNaN(n)) { const m = tok.match(/\((\d+)\)/); if (m) n = Number(m[1]) }
            if (n) set.add(n)
          }
        }
        return set
      }
      const egressIds = idsIn('egressFromSource')
      const ingressIds = idsIn('ingressToDest')
      const rel = new Set()
      if (egressIds.has(Number(dstIdVal))) {
        for (const p of (results?.path?.src?.policies || [])) rel.add(p)
      }
      if (ingressIds.has(Number(srcIdVal))) {
        for (const p of (results?.path?.dst?.policies || [])) rel.add(p)
      }
      setRelevantPolicies(Array.from(rel))
    } catch (e) {
      setRelevantError(String(e.message || e))
    }
  }

  const onPick = () => fileRef.current?.click()

  const onFile = async (e) => {
    const f = e.target.files?.[0]
    if (!f) return
    setError('')
    try {
      const text = await f.text()
      const r = await fetch('/api/kubeconfig', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ kubeconfig: text })
      })
      if (!r.ok) throw new Error((await r.json()).error || 'Upload failed')
      setKcfgLoaded(true)
    } catch (e) {
      setError(String(e.message || e))
    }
  }

  const showEndpoints = async () => {
    setLoading(true)
    setError('')
    setResults(null)
    try {
      const r = await fetch('/api/endpoints', { credentials: 'same-origin' })
      const j = await r.json()
      if (!r.ok) throw new Error(j.error || 'Request failed')
      setResults(j)
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setLoading(false)
    }
  }

  const showPolicies = async () => {
    setLoading(true)
    setError('')
    setResults(null)
    try {
      const r = await fetch('/api/policies', { credentials: 'same-origin' })
      const j = await r.json()
      if (!r.ok) throw new Error(j.error || 'Request failed')
      setResults(j)
      setLastAction('policies')
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setLoading(false)
    }
  }

  // Lightweight re-fetch for live policies refresh (no loading spinner)
  const refreshPolicies = async () => {
    try {
      const r = await fetch('/api/policies', { credentials: 'same-origin' })
      const j = await r.json()
      if (!r.ok) return
      setResults(j)
    } catch {}
  }

  const refreshPolicyPath = async () => {
    if (!srcSel || !dstSel) return
    try {
      const r = await fetch(`/api/policy-path?src=${encodeURIComponent(srcSel)}&dst=${encodeURIComponent(dstSel)}`, {
        credentials: 'same-origin'
      })
      const j = await r.json()
      if (!r.ok) return
      setResults(j)
    } catch {}
  }

  const showSelectors = async () => {
    setLoading(true)
    setError('')
    setResults(null)
    try {
      const r = await fetch('/api/selectors', { credentials: 'same-origin' })
      const j = await r.json()
      if (!r.ok) throw new Error(j.error || 'Request failed')
      setResults(j)
      setLastAction('selectors')
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setLoading(false)
    }
  }

  const showEpPolicies = async () => {
    setLoading(true)
    setError('')
    setResults(null)
    try {
      const r = await fetch('/api/ep-policies', { credentials: 'same-origin' })
      const j = await r.json()
      if (!r.ok) throw new Error(j.error || 'Request failed')
      setResults(j)
      setLastAction('ep-policies')
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setLoading(false)
    }
  }

  const showEpNoPolicy = async () => {
    setLoading(true)
    setError('')
    setResults(null)
    try {
      const r = await fetch('/api/ep-no-policy', { credentials: 'same-origin' })
      const j = await r.json()
      if (!r.ok) throw new Error(j.error || 'Request failed')
      setResults(j)
      setLastAction('ep-no-policy')
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setLoading(false)
    }
  }

  const openPolicyPath = async () => {
    setShowPolicyPath(true)
    setError('')
    setLoading(true)
    try {
      const r = await fetch('/api/ep-index', { credentials: 'same-origin' })
      const j = await r.json()
      if (!r.ok) throw new Error(j.error || 'Request failed')
      setEpIndex(j.endpoints || [])
      setLastAction('policy-path')
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setLoading(false)
    }
  }

  const runPolicyPath = async () => {
    if (!srcSel || !dstSel) { setError('Pick both source and destination endpoints'); return }
    setLoading(true)
    setError('')
    setResults(null)
    setTestHits({ egress: [], ingress: [] })
    setTestError('')
    try {
      const r = await fetch(`/api/policy-path?src=${encodeURIComponent(srcSel)}&dst=${encodeURIComponent(dstSel)}`, { credentials: 'same-origin' })
      const j = await r.json()
      if (!r.ok) throw new Error(j.error || 'Request failed')
      setResults(j)
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setLoading(false)
    }
  }

  const testPolicy = async () => {
    if (!results?.src || !results?.dst) { setTestError('Run Policy Path first'); return }
    setTestRunning(true)
    setTestError('')
    setTestHits({ egress: [], ingress: [] })
    setTestResults([])
    setPwruOutput('Starting pwru...')
    setPwruRunning(true)
    
    // Start pwru and wait for it to be ready
    const pwruPromise = (async () => {
      try {
        const r = await fetch('/api/pwru', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            src: results.src, 
            dst: results.dst, 
            srcIPv4: results.srcIPv4,
            dstIPv4: results.dstIPv4,
            proto: testProto || undefined, 
            port: testPort ? Number(testPort) : undefined 
          }),
          credentials: 'same-origin'
        })
        const j = await r.json()
        if (r.ok && j?.output) {
          setPwruOutput(j.output)
        } else if (j?.error) {
          setPwruOutput(`Error: ${j.error}`)
        }
      } catch (e) {
        setPwruOutput(`Error: ${e.message || e}`)
      } finally {
        setPwruRunning(false)
      }
    })()
    
    // Wait a bit for pwru to start listening (the backend script waits for "PWRU_READY")
    setPwruOutput('Waiting for pwru to be ready...')
    await new Promise(resolve => setTimeout(resolve, 5000))
    
    try {
      setPwruOutput('pwru is listening, running connectivity test...')
      const r = await fetch('/api/policy-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ src: results.src, dst: results.dst, proto: testProto || undefined, port: testPort ? Number(testPort) : undefined }),
        credentials: 'same-origin'
      })
      const j = await r.json()
      if (!r.ok) throw new Error(j.error || 'Request failed')
      if (j?.error) { setTestError(String(j.error)); return }
      if (Array.isArray(j?.tests)) setTestResults(j.tests)
      if (j?.hits) setTestHits({ egress: j.hits.egress || [], ingress: j.hits.ingress || [] })
    } catch (e) {
      setTestError(String(e.message || e))
    } finally {
      setTestRunning(false)
    }
    
    // Wait for pwru to complete and get final output
    await pwruPromise
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800">
      <div className="max-w-[2200px] mx-auto p-6">
        <div className="text-2xl font-semibold text-slate-800">visual-inspector</div>
        <div className="text-sm text-slate-500 mb-6">Kubernetes inspector with Cilium helpers</div>

        <div className="flex gap-3">
          <div style={{ width: sidebarW }}>
            <div className="bg-white border border-slate-200 rounded p-4 sticky top-4">
              <div className="text-sm font-semibold mb-2">Kubeconfig</div>
              <input ref={fileRef} type="file" className="hidden" onChange={onFile} />
              <button onClick={onPick} className={cls(
                'w-full text-sm px-3 py-2 rounded border',
                'bg-slate-100 hover:bg-slate-200 border-slate-300'
              )}>Upload kubeconfig</button>
              {kcfgLoaded && (
                <div className="text-xs text-green-700 mt-2">Kubeconfig loaded for this session.</div>
              )}
              {!!error && <div className="text-xs text-red-700 mt-2">{error}</div>}

              <div className="h-px bg-slate-200 my-4" />

              <div className="text-sm font-semibold mb-2">Actions</div>
              <button
                disabled={!kcfgLoaded || loading}
                onClick={showEndpoints}
                className={cls(
                  'w-full text-sm px-3 py-2 rounded border',
                  'border-slate-300',
                  loading || !kcfgLoaded ? 'bg-slate-100 text-slate-400' : 'bg-blue-600 text-white hover:bg-blue-700'
                )}
              >Show Endpoints</button>
              <button
                disabled={!kcfgLoaded || loading}
                onClick={showPolicies}
                className={cls(
                  'w-full text-sm px-3 py-2 rounded border mt-2',
                  'border-slate-300',
                  loading || !kcfgLoaded ? 'bg-slate-100 text-slate-400' : 'bg-blue-600 text-white hover:bg-blue-700'
                )}
              >Show Policies</button>
              <button
                disabled={!kcfgLoaded || loading}
                onClick={showSelectors}
                className={cls(
                  'w-full text-sm px-3 py-2 rounded border mt-2',
                  'border-slate-300',
                  loading || !kcfgLoaded ? 'bg-slate-100 text-slate-400' : 'bg-blue-600 text-white hover:bg-blue-700'
                )}
              >Show Selectors</button>
              <button
                disabled={!kcfgLoaded || loading}
                onClick={showEpPolicies}
                className={cls(
                  'w-full text-sm px-3 py-2 rounded border mt-2',
                  'border-slate-300',
                  loading || !kcfgLoaded ? 'bg-slate-100 text-slate-400' : 'bg-blue-600 text-white hover:bg-blue-700'
                )}
              >Policies Attached to Endpoint</button>
              <button
                disabled={!kcfgLoaded || loading}
                onClick={showEpNoPolicy}
                className={cls(
                  'w-full text-sm px-3 py-2 rounded border mt-2',
                  'border-slate-300',
                  loading || !kcfgLoaded ? 'bg-slate-100 text-slate-400' : 'bg-blue-600 text-white hover:bg-blue-700'
                )}
              >Endpoint without Policy</button>
              <button
                disabled={!kcfgLoaded || loading}
                onClick={openPolicyPath}
                className={cls(
                  'w-full text-sm px-3 py-2 rounded border mt-2',
                  'border-slate-300',
                  loading || !kcfgLoaded ? 'bg-slate-100 text-slate-400' : 'bg-blue-600 text-white hover:bg-blue-700'
                )}
              >Policy Path</button>
            </div>
            {showPolicyPath && (
              <div className="w-[360px] bg-white border border-slate-200 rounded p-4 min-h-[300px] flex flex-col">
                <div className="text-sm font-semibold mb-2">Policy Path</div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <div className="text-xs font-semibold mb-1">Source Pod</div>
                    <div className="border border-slate-200 rounded h-64 overflow-auto">
                      <ul className="text-xs">
                        {[...epIndex].sort((a, b) => {
                          const aName = String(a.podName || '')
                          const bName = String(b.podName || '')
                          const aHasName = aName && aName !== '(no pod)' && aName !== '/' && !aName.startsWith('/')
                          const bHasName = bName && bName !== '(no pod)' && bName !== '/' && !bName.startsWith('/')
                          if (aHasName && !bHasName) return -1
                          if (!aHasName && bHasName) return 1
                          return aName.localeCompare(bName)
                        }).map(e => (
                          <li key={`src-${e.pod}-${e.id}`}>
                            <button
                              className={cls('w-full text-left px-2 py-1 hover:bg-slate-50', srcSel === e.id ? 'bg-blue-50' : '')}
                              onClick={() => setSrcSel(e.id)}
                              title={`${e.pod}`}
                            >{e.podName || '(no pod)'} #{e.id}</button>
                          </li>
                        ))}
                      </ul>
                    </div>
                {!!testRunning && <div className="text-xs text-slate-500 mt-1">Running policy tests…</div>}
                {!!testError && <div className="text-xs text-red-700 mt-1">{testError}</div>}
                  </div>
                  <div>
                    <div className="text-xs font-semibold mb-1">Destination Pod</div>
                    <div className="border border-slate-200 rounded h-64 overflow-auto">
                      <ul className="text-xs">
                        {[...epIndex].sort((a, b) => {
                          const aName = String(a.podName || '')
                          const bName = String(b.podName || '')
                          const aHasName = aName && aName !== '(no pod)' && aName !== '/' && !aName.startsWith('/')
                          const bHasName = bName && bName !== '(no pod)' && bName !== '/' && !bName.startsWith('/')
                          if (aHasName && !bHasName) return -1
                          if (!aHasName && bHasName) return 1
                          return aName.localeCompare(bName)
                        }).map(e => (
                          <li key={`dst-${e.pod}-${e.id}`}>
                            <button
                              className={cls('w-full text-left px-2 py-1 hover:bg-slate-50', dstSel === e.id ? 'bg-blue-50' : '')}
                              onClick={() => setDstSel(e.id)}
                              title={`${e.pod}`}
                            >{e.podName || '(no pod)'} #{e.id}</button>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  <button
                    disabled={!srcSel || !dstSel || loading}
                    onClick={runPolicyPath}
                    className={cls('text-sm px-3 py-2 rounded border', 'border-slate-300', loading || !srcSel || !dstSel ? 'bg-slate-100 text-slate-400' : 'bg-blue-600 text-white hover:bg-blue-700')}
                  >Run</button>
                  <select
                    value={testProto}
                    onChange={e => setTestProto(e.target.value)}
                    className="text-sm px-2 py-2 border border-slate-300 rounded bg-white flex-none"
                    title="Protocol override"
                  >
                    <option value="">Proto</option>
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                  </select>
                  <input
                    type="number"
                    placeholder="Port"
                    value={testPort}
                    onChange={e => setTestPort(e.target.value)}
                    className="text-sm px-2 py-2 border border-slate-300 rounded w-24 flex-none"
                  />
                  <button
                    disabled={!results || testRunning}
                    onClick={testPolicy}
                    className={cls('text-sm px-3 py-2 rounded border', 'border-slate-300 flex-none', (!results || testRunning) ? 'bg-slate-100 text-slate-400' : 'bg-emerald-600 text-white hover:bg-emerald-700')}
                  >Test Policy</button>
                  <button
                    disabled={!results}
                    onClick={runPolicyRelevant}
                    className={cls('text-sm px-3 py-2 rounded border', 'border-slate-300 flex-none', !results ? 'bg-slate-100 text-slate-400' : 'bg-purple-600 text-white hover:bg-purple-700')}
                  >Filter Policies</button>
                  <button
                    onClick={() => setShowPolicyPath(false)}
                    className={cls('text-sm px-3 py-2 rounded border', 'border-slate-300 bg-slate-100 hover:bg-slate-200 flex-none')}
                  >Close</button>
                </div>
              </div>
            )}
          </div>
          <div
            className={cls('w-1', 'cursor-col-resize', 'bg-slate-200', 'rounded')}
            onMouseDown={() => setDragging(true)}
            title="Drag to resize"
          />
          <div className="flex-1 flex gap-3">
            <div className="bg-white border border-slate-200 rounded p-4 min-h-[300px] min-w-[1000px]">
              <div className="flex items-center justify-between mb-2">
                <div className="text-sm font-semibold">Output</div>
                {!results?.path && lastAction === 'policies' && (
                  <button
                    onClick={() => setLiveOutput(v => !v)}
                    className={cls('text-xs px-2 py-1 rounded border', liveOutput ? 'bg-emerald-50 text-emerald-700 border-emerald-300' : 'bg-slate-100 text-slate-600 border-slate-300')}
                    title="Toggle live output (no-op for now)"
                  >Policy Counters Live: {liveOutput ? 'ON' : 'OFF'}</button>
                )}
              </div>
              {loading && <div className="text-xs text-slate-500">Loading...</div>}
              {!loading && !results && <div className="text-xs text-slate-500">No output yet.</div>}
              {!loading && !!results && (
                <div className="space-y-4">
                  {results.note && (
                    <div className="text-xs text-slate-500">{results.note}</div>
                  )}
                  {results.path && (() => {
                    const ok = (results.results || []).filter(x => x.ok)
                    const hdrPrefix = 'IDENTITY'
                    const collect = (key) => {
                      const rows = new Set()
                      for (const r of ok) {
                        const s = r[key]
                        if (!s) continue
                        const lines = String(s).split('\n')
                        for (const line of lines) {
                          if (!line.trim()) continue
                          if (line.startsWith(hdrPrefix)) continue
                          rows.add(line)
                        }
                      }
                      const header = ['IDENTITY', 'PROTO', 'DPORT', 'ACTION'].join('\t')
                      return [header, ...Array.from(rows)]
                    }
                    const egressLines = collect('egressFromSource')
                    const ingressLines = collect('ingressToDest')
                    const parseRow = (line) => {
                      // columns are padded; identity may be name(id)
                      const parts = line.trim().split(/\s+/)
                      if (parts.length < 4) return null
                      let idTok = parts[0]
                      let idNum = Number(idTok)
                      if (Number.isNaN(idNum)) {
                        const m = idTok.match(/\((\d+)\)/)
                        if (m) idNum = Number(m[1])
                      }
                      const proto = parts[1]
                      const dport = parts[2] === '*' ? 0 : Number(parts[2])
                      return { idNum, proto, dport }
                    }
                    const isHit = (line, where) => {
                      const row = parseRow(line)
                      if (!row || !row.idNum) return false
                      const hits = where === 'egress' ? testHits.egress : testHits.ingress
                      for (const h of (hits || [])) {
                        const protoMatch = String(row.proto).toUpperCase() === '*' || String(h.proto).toUpperCase() === String(row.proto).toUpperCase()
                        const portMatch = Number(row.dport || 0) === 0 || Number(h.dport || 0) === Number(row.dport || 0)
                        const idMatch = Number(h.identity) === Number(row.idNum)
                        if (protoMatch && portMatch && idMatch) return true
                      }
                      return false
                    }
                    const deriveId = (key) => {
                      const top = results[key]
                      if (top) return top
                      const arr = Array.isArray(results.results) ? results.results : []
                      for (const r of arr) { if (r && r.ok && typeof r[key] !== 'undefined') return r[key] }
                      return undefined
                    }
                    const srcIdVal = deriveId('srcIdentity')
                    const dstIdVal = deriveId('dstIdentity')
                    return (
                      <div className="border border-slate-200 rounded p-3 bg-white">
                        <div className="flex items-center justify-between mb-2">
                          <div className="text-sm font-semibold">Policy Path</div>
                          <button
                            onClick={() => setLiveOutput(v => !v)}
                            className={cls('text-xs px-2 py-1 rounded border', liveOutput ? 'bg-emerald-50 text-emerald-700 border-emerald-300' : 'bg-slate-100 text-slate-600 border-slate-300')}
                          >Policy Counters Live: {liveOutput ? 'ON' : 'OFF'}</button>
                        </div>
                        {!!testError && <div className="text-xs text-red-700 mb-2">{testError}</div>}
                        {testRunning && <div className="text-xs text-slate-500 mb-2">Running policy tests...</div>}
                        <div className="flex items-start gap-3">
                          <div className="flex-1 border border-slate-300 rounded p-3 bg-slate-50">
                            <div className="text-xs font-semibold mb-1">Source</div>
                            <div className="text-xs mb-1 truncate">{results.path.src.node || '(node)'} / {results.path.src.pod || '(pod)'}</div>
                            <div className="flex flex-wrap gap-1 mb-2">
                              {relevantError && <span className="text-[10px] text-red-700">{relevantError}</span>}
                              {(() => {
                                const list = Array.isArray(results.path.src.policies) ? results.path.src.policies : []
                                const show = relevantPolicies.length ? list.filter(n => relevantPolicies.includes(n)) : list
                                return show.length ? show.map(p => (
                                  <span key={`src-pol-${p}`} className="text-[10px] px-2 py-0.5 bg-blue-100 text-blue-800 rounded border border-blue-200">{p}</span>
                                )) : <span className="text-[10px] text-slate-500">No policies</span>
                              })()}
                            </div>
                            <div className="mb-2">
                              <button
                                disabled={!results?.path?.src?.ns || !results?.path?.src?.pod}
                                onClick={() => pcapSrcLoading ? stopTcpdump('src') : runTcpdump('src')}
                                className={cls('text-xs px-2 py-1 rounded border', pcapSrcLoading ? 'bg-red-600 text-white border-red-700 hover:bg-red-700' : 'bg-amber-600 text-white border-amber-700 hover:bg-amber-700')}
                              >{pcapSrcLoading ? 'Stop Capture' : 'Packet Capture'}</button>
                            </div>
                            {!!pcapSrcOut && (
                              <pre className="text-[11px] p-2 whitespace-pre-wrap font-mono border border-slate-200 rounded max-h-48 overflow-auto">{pcapSrcOut}</pre>
                            )}
                            {(() => {
                              const hdr = results?.srcGetHeader || ''
                              const body = results?.srcGetEgress || ''
                              if (!hdr && !body) return null
                              const lines = [hdr, ...String(body || '').split('\n').filter(Boolean)]
                              const incSet = incPathLines.egress
                              return (
                                <div className="mb-2">
                                  <div className="text-xs font-semibold mb-1">Egress from Source (EP {results.src}, ID {srcIdVal ?? '-'}) · IPv4 {results.srcIPv4 || '-'}</div>
                                  <pre className="text-[11px] p-2 whitespace-pre font-mono border border-slate-200 rounded">
                                    {lines.map((ln, idx) => {
                                      const isInc = idx > 0 && incSet.has(ln)
                                      return <div key={`eg-${idx}`} className={isInc ? 'bg-green-100 text-green-900' : ''}>{ln}</div>
                                    })}
                                  </pre>
                                </div>
                              )
                            })()}
                          </div>
                          <div className="text-slate-500 select-none pt-6">➡️</div>
                          <div className="flex-1 border border-slate-300 rounded p-3 bg-slate-50">
                            <div className="text-xs font-semibold mb-1">Destination</div>
                            <div className="text-xs mb-1 truncate">{results.path.dst.node || '(node)'} / {results.path.dst.pod || '(pod)'}</div>
                            <div className="flex flex-wrap gap-1 mb-2">
                              {relevantError && <span className="text-[10px] text-red-700">{relevantError}</span>}
                              {(() => {
                                const list = Array.isArray(results.path.dst.policies) ? results.path.dst.policies : []
                                const show = relevantPolicies.length ? list.filter(n => relevantPolicies.includes(n)) : list
                                return show.length ? show.map(p => (
                                  <span key={`dst-pol-${p}`} className="text-[10px] px-2 py-0.5 bg-green-100 text-green-800 rounded border border-green-200">{p}</span>
                                )) : <span className="text-[10px] text-slate-500">No policies</span>
                              })()}
                            </div>
                            <div className="mb-2">
                              <button
                                disabled={!results?.path?.dst?.ns || !results?.path?.dst?.pod}
                                onClick={() => pcapDstLoading ? stopTcpdump('dst') : runTcpdump('dst')}
                                className={cls('text-xs px-2 py-1 rounded border', pcapDstLoading ? 'bg-red-600 text-white border-red-700 hover:bg-red-700' : 'bg-amber-600 text-white border-amber-700 hover:bg-amber-700')}
                              >{pcapDstLoading ? 'Stop Capture' : 'Packet Capture'}</button>
                            </div>
                            {!!pcapDstOut && (
                              <pre className="text-[11px] p-2 whitespace-pre-wrap font-mono border border-slate-200 rounded max-h-48 overflow-auto">{pcapDstOut}</pre>
                            )}
                            {(() => {
                              const hdr = results?.dstGetHeader || ''
                              const body = results?.dstGetIngress || ''
                              if (!hdr && !body) return null
                              const lines = [hdr, ...String(body || '').split('\n').filter(Boolean)]
                              const incSet = incPathLines.ingress
                              return (
                                <div className="mb-2">
                                  <div className="text-xs font-semibold mb-1">Ingress to Dest (EP {results.dst}, ID {dstIdVal ?? '-'}) · IPv4 {results.dstIPv4 || '-'}</div>
                                  <pre className="text-[11px] p-2 whitespace-pre font-mono border border-slate-200 rounded">
                                    {lines.map((ln, idx) => {
                                      const isInc = idx > 0 && incSet.has(ln)
                                      return <div key={`in-${idx}`} className={isInc ? 'bg-green-100 text-green-900' : ''}>{ln}</div>
                                    })}
                                  </pre>
                                </div>
                              )
                            })()}
                          </div>
                        </div>
                        {(() => {
                          // Compact summary of tests (if backend returned them via last /api/policy-test call)
                          const anyHits = (testHits.egress?.length || 0) + (testHits.ingress?.length || 0)
                          if (!anyHits && !testRunning && !testError) {
                            return <div className="text-[11px] text-slate-500 mt-2">No matching rows highlighted. Ensure the chosen port/proto exists in the tables or select another port.</div>
                          }
                          return null
                        })()}
                        {testResults && testResults.length > 0 && (
                          <div className="mt-2">
                            <div className="text-xs font-semibold mb-1">Test results</div>
                            <div className="text-[11px] grid gap-1">
                              {testResults.map((t, i) => (
                                <div key={`t-${i}`} className={cls('rounded border px-2 py-1', t.ok ? 'border-emerald-300 bg-emerald-50' : 'border-red-300 bg-red-50')}>
                                  <div><span className="font-semibold">{t.proto}</span> port <span className="font-semibold">{t.port}</span> — {t.ok ? 'ok' : 'failed'}</div>
                                  {!!t.stderr && <pre className="whitespace-pre-wrap">{t.stderr}</pre>}
                                  {!!t.error && <pre className="whitespace-pre-wrap">{t.error}</pre>}
                                  {!!t.stdout && <pre className="whitespace-pre-wrap">{t.stdout}</pre>}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                        {(pwruOutput || pwruRunning) && (
                          <div className="mt-4">
                            <div className="text-xs font-semibold mb-1">pwru Output {pwruRunning && <span className="text-slate-500">(running...)</span>}</div>
                            <pre className="text-[11px] p-2 whitespace-pre-wrap font-mono border border-slate-200 rounded bg-slate-50 max-h-96 overflow-auto">
                              {pwruOutput || 'Waiting for pwru output...'}
                            </pre>
                          </div>
                        )}
                      </div>
                    )
                  })()}
                  {results.path ? null : (
                    (results.results || []).map((r) => (
                      <div key={r.pod} className="border border-slate-200 rounded">
                        <div className="text-xs font-semibold bg-slate-50 px-2 py-1 border-b border-slate-200">{r.pod}</div>
                        {r.ok ? (
                          <pre className="text-[11px] p-2 whitespace-pre font-mono">
                            {(() => {
                              const lines = String(r.output || '').split('\n')
                              const headerIdx = lines.findIndex(l => /\bPOLICY\b/.test(l) && /\bPACKETS\b/.test(l))
                              const output = []
                              let firstEndpoint = true
                              for (let i = 0; i < lines.length; i++) {
                                const ln = lines[i]
                                let inc = false
                                if (liveOutput && lastAction === 'policies' && headerIdx >= 0 && i > headerIdx) {
                                  if (!/^Endpoint ID:/i.test(ln) && !/^Path:/i.test(ln) && !/\bPOLICY\b/.test(ln) && ln.trim()) {
                                    inc = !!incPolicyLines[r.pod]?.has?.(ln)
                                  }
                                }
                                // Add blank line before each "Endpoint ID:" line (except the first one)
                                if (/^Endpoint ID:/i.test(ln)) {
                                  if (!firstEndpoint) {
                                    output.push(<div key={`pl-${r.pod}-blank-${i}`}>&nbsp;</div>)
                                  }
                                  firstEndpoint = false
                                }
                                output.push(
                                  <div key={`pl-${r.pod}-${i}`} className={inc ? 'bg-yellow-100 text-yellow-900 ring-1 ring-yellow-300 rounded' : ''}>{ln}</div>
                                )
                              }
                              return output
                            })()}
                          </pre>
                        ) : (
                          <div className="text-xs text-red-700 p-2">{r.error}</div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
