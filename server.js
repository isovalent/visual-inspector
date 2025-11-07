import express from 'express'
import session from 'express-session'
import cors from 'cors'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { execFile } from 'child_process'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()
app.use(cors({ origin: true, credentials: true }))
app.use(express.json({ limit: '5mb' }))
app.use(session({ secret: 'visual-inspector-secret', resave: false, saveUninitialized: true }))

// In-memory store keyed by sessionID
const store = new Map()
// Default kubeconfig path (can be overridden by env)
const DEFAULT_KUBECONFIG_PATH = process.env.VI_DEFAULT_KUBECONFIG_PATH || '/Users/pijablon/Downloads/projects/kind/kubeconfig'
// Read default kubeconfig content at startup (best-effort)
let GLOBAL_DEFAULT_KUBECONFIG = ''
try {
  if (DEFAULT_KUBECONFIG_PATH && fs.existsSync(DEFAULT_KUBECONFIG_PATH)) {
    GLOBAL_DEFAULT_KUBECONFIG = fs.readFileSync(DEFAULT_KUBECONFIG_PATH, 'utf8') || ''
    if (GLOBAL_DEFAULT_KUBECONFIG.trim()) {
      console.log(`[visual-inspector] Loaded default kubeconfig from ${DEFAULT_KUBECONFIG_PATH}`)
    }
  }
} catch (e) {
  // non-fatal
}

// Note: GLOBAL_DEFAULT_KUBECONFIG is used on-demand in withTmpKubeconfig; no further init needed

app.post('/api/kubeconfig', (req, res) => {
  const { kubeconfig } = req.body || {}
  if (!kubeconfig || typeof kubeconfig !== 'string' || kubeconfig.trim().length < 10) {
    res.status(400).json({ error: 'Invalid kubeconfig' }); return
  }
  store.set(req.sessionID, { kubeconfig })
  res.json({ ok: true })
})

app.post('/api/policy-relevant', async (req, res) => {
  try {
    const { srcIdentity, dstIdentity, proto, port } = req.body || {}
    if (!srcIdentity || !dstIdentity) { res.status(400).json({ error: 'Missing srcIdentity or dstIdentity' }); return }
    if (!proto || !port) { res.status(400).json({ error: 'Missing proto or port' }); return }
    const out = await withTmpKubeconfig(req.sessionID, async (kcfg) => {
      const pods = await listCiliumPods(kcfg)
      if (!pods.length) return { error: 'No cilium pods found' }
      const pod = pods[0]
      const args = ['exec', '-n', 'kube-system', pod, '--', 'cilium', 'policy', 'trace', '--src-identity', String(srcIdentity), '--dst-identity', String(dstIdentity), '--dport', String(port), '--protocol', String(proto).toUpperCase()]
      try {
        const { stdout, stderr } = await execCmd('kubectl', args, { KUBECONFIG: kcfg })
        const text = `${stdout}\n${stderr}`
        // Extract policy names from labels like k8s:io.cilium.k8s.policy.name=<name>
        const names = new Set()
        const re = /k8s:io\.cilium\.k8s\.policy\.name=([^,\s]+)/g
        let m
        while ((m = re.exec(text)) !== null) { names.add(m[1]) }
        return { ok: true, policies: Array.from(names), raw: stdout }
      } catch (e) {
        return { ok: false, error: String(e.message || e) }
      }
    })
    res.json(out)
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) })
  }
})

app.post('/api/policy-test', async (req, res) => {
  try {
    const { src, dst, proto: protoOverride, port: portOverride } = req.body || {}
    if (!src || !dst) { res.status(400).json({ error: 'Missing src or dst in body' }); return }
    const out = await withTmpKubeconfig(req.sessionID, async (kcfg) => {
      const pods = await listCiliumPods(kcfg)
      if (!pods.length) return { error: 'No cilium pods found' }
      // Build endpoint index: id -> {podName, ns, ip, ciliumPod}
      const epIndex = new Map()
      for (const cPod of pods) {
        try {
          const { stdout } = await execCmd('kubectl', ['exec', '-n', 'kube-system', cPod, '--', 'cilium', 'endpoint', 'list', '-o', 'json'], { KUBECONFIG: kcfg })
          let arr; try { arr = JSON.parse(stdout) } catch { arr = [] }
          for (const ep of (Array.isArray(arr) ? arr : [])) {
            const eid = ep?.id ?? ep?.endpoint?.id ?? ep?.endpointID
            if (eid === undefined || eid === null) continue
            let podName = ''
            let ns = ''
            let ip = ''
            try {
              const ext = ep?.status?.['external-identifiers'] || ep?.status?.externalIdentifiers || ep?.externalIdentifiers || {}
              podName = ext['pod-name'] || ext['k8s-pod-name'] || ext['pod'] || ext['pod_name'] || podName
              ns = ext['k8s-namespace'] || ext['k8s_namespace'] || ext['namespace'] || ext['pod-namespace'] || ext['k8s-pod-namespace'] || ns
            } catch {}

            try {
              const labels = ep?.status?.labels?.security || ep?.labels?.security || ep?.labels || []
              const arrL = Array.isArray(labels) ? labels : []
              for (const l of arrL) {
                const s = String(l || '')
                const p1 = 'k8s:io.kubernetes.pod.namespace='
                const p2 = 'k8s:namespace='
                if (s.startsWith(p1)) { ns = ns || s.slice(p1.length); }
                else if (s.startsWith(p2)) { ns = ns || s.slice(p2.length); }
              }
            } catch {}
            try {
              if (ep?.status?.networking?.addressing?.length) {
                const addr = ep.status.networking.addressing[0]
                ip = addr.ipv4 || addr.ip || ip
              } else if (ep?.networking?.addressing?.length) {
                const addr = ep.networking.addressing[0]
                ip = addr.ipv4 || addr.ip || ip
              }
            } catch {}
            epIndex.set(String(eid), { podName, ns, ip, ciliumPod: cPod })
          }
        } catch {}
      }

      const srcMeta = epIndex.get(String(src)) || {}
      const dstMeta = epIndex.get(String(dst)) || {}
      // If missing fields, try endpoint get for richer data
      const ensureMeta = async (eid, meta) => {
        if (meta.podName && meta.ns && meta.ip) return meta
        for (const cPod of pods) {
          try {
            const { stdout } = await execCmd('kubectl', ['exec', '-n', 'kube-system', cPod, '--', 'cilium', 'endpoint', 'get', String(eid), '-o', 'json'], { KUBECONFIG: kcfg })
            const ep = JSON.parse(stdout)
            const ext = ep?.status?.['external-identifiers'] || ep?.status?.externalIdentifiers || ep?.externalIdentifiers || {}
            meta.podName = meta.podName || ext['pod-name'] || ext['k8s-pod-name'] || ext['pod'] || ext['pod_name'] || ''
            meta.ns = meta.ns || ext['k8s-namespace'] || ext['k8s_namespace'] || ext['namespace'] || ext['pod-namespace'] || ext['k8s-pod-namespace'] || ''
            if (!meta.ns) {
              const labels = ep?.status?.labels?.security || ep?.labels?.security || ep?.labels || []
              const arrL = Array.isArray(labels) ? labels : []
              for (const l of arrL) {
                const s = String(l || '')
                const p1 = 'k8s:io.kubernetes.pod.namespace='
                const p2 = 'k8s:namespace='
                if (s.startsWith(p1)) { meta.ns = s.slice(p1.length); break }
                if (s.startsWith(p2)) { meta.ns = s.slice(p2.length); break }
              }
            }
            if (!meta.ip) {
              if (ep?.status?.networking?.addressing?.length) {
                const addr = ep.status.networking.addressing[0]
                meta.ip = addr.ipv4 || addr.ip || ''
              }
            }
            meta.ciliumPod = meta.ciliumPod || cPod
            break
          } catch {}
        }
        return meta
      }
      await ensureMeta(src, srcMeta)
      await ensureMeta(dst, dstMeta)
      if (!srcMeta.podName || !srcMeta.ns || !dstMeta.podName || !dstMeta.ns || !dstMeta.ip) {
        const miss = { srcPod: !!srcMeta.podName, srcNs: !!srcMeta.ns, dstPod: !!dstMeta.podName, dstNs: !!dstMeta.ns, dstIp: !!dstMeta.ip }
        return { error: 'Could not resolve src/dst pod metadata', detail: miss }
      }

      // Determine destination container ports
      let dstPorts = []
      let podObj = null
      try {
        const { stdout: podJson } = await execCmd('kubectl', ['get', 'pod', '-n', dstMeta.ns, dstMeta.podName, '-o', 'json'], { KUBECONFIG: kcfg })
        podObj = JSON.parse(podJson)
        const containers = Array.isArray(podObj?.spec?.containers) ? podObj.spec.containers : []
        for (const c of containers) {
          const ports = Array.isArray(c?.ports) ? c.ports : []
          for (const p of ports) {
            if (p?.containerPort) {
              dstPorts.push({ port: Number(p.containerPort), proto: String(p.protocol || 'TCP').toUpperCase(), name: p.name || '' })
            }
          }
        }
      } catch {}
      // If no container ports, try matching Services by selector
      if (!dstPorts.length) {
        try {
          const podLabels = podObj?.metadata?.labels || {}
          const { stdout: svcJson } = await execCmd('kubectl', ['get', 'svc', '-n', dstMeta.ns, '-o', 'json'], { KUBECONFIG: kcfg })
          const svcObj = JSON.parse(svcJson)
          const services = Array.isArray(svcObj?.items) ? svcObj.items : []
          const matches = []
          for (const s of services) {
            const sel = s?.spec?.selector || {}
            const keys = Object.keys(sel)
            if (!keys.length) continue
            const ok = keys.every(k => podLabels[k] === sel[k])
            if (!ok) continue
            const ports = Array.isArray(s?.spec?.ports) ? s.spec.ports : []
            for (const sp of ports) {
              let proto = String(sp?.protocol || 'TCP').toUpperCase()
              let target = sp?.targetPort ?? sp?.port
              let portNum = 0
              if (typeof target === 'number') portNum = target
              else if (typeof target === 'string') {
                // try to map named targetPort via container port name
                const containers = Array.isArray(podObj?.spec?.containers) ? podObj.spec.containers : []
                for (const c of containers) {
                  const cports = Array.isArray(c?.ports) ? c.ports : []
                  for (const cp of cports) {
                    if (cp?.name && cp.name === target) {
                      portNum = Number(cp.containerPort || 0)
                      if (!proto && cp?.protocol) proto = String(cp.protocol).toUpperCase()
                    }
                  }
                }
                if (!portNum) {
                  // fallback to service port if mapping failed
                  portNum = Number(sp?.port || 0)
                }
              }
              if (portNum) matches.push({ port: portNum, proto })
            }
          }
          if (matches.length) dstPorts = matches
        } catch {}
      }

      const tests = []
      const addTest = (proto, port) => { if (port) tests.push({ proto: String(proto).toUpperCase(), port: Number(port) }) }
      if (portOverride && protoOverride) addTest(protoOverride, portOverride)
      if (!tests.length) {
        // Prefer TCP
        const tcp = dstPorts.find(p => String(p.proto).toUpperCase() === 'TCP') || dstPorts[0]
        if (tcp) addTest(tcp.proto, tcp.port)
        // If 53 present, also test UDP/53
        if (dstPorts.find(p => p.port === 53)) addTest('UDP', 53)
      }
      if (!tests.length) return { error: 'No destination ports found to test' }

      // Baseline policy get for both src and dst
      const runPolGet = async (meta, eid) => {
        const { stdout } = await execCmd('kubectl', ['exec', '-n', 'kube-system', meta.ciliumPod, '--', 'cilium', 'bpf', 'policy', 'get', String(eid)], { KUBECONFIG: kcfg })
        return stdout
      }
      const beforeSrc = await runPolGet(srcMeta, src)
      const beforeDst = await runPolGet(dstMeta, dst)

      // Run tests via busybox ephemeral container from source pod
      const runCmds = []
      for (const t of tests) {
        let cmd = ''
        if (String(t.proto).toUpperCase() === 'TCP') {
          cmd = `nc -vz -w3 ${dstMeta.ip} ${t.port}`
        } else if (String(t.proto).toUpperCase() === 'UDP') {
          cmd = `echo test | nc -u -w2 ${dstMeta.ip} ${t.port}`
        }
        if (!cmd) continue
        // kubectl debug ephemeral (attach and run once)
        let podArgName = String(srcMeta.podName || '')
        podArgName = podArgName.replace(/^pod\//, '')
        if (podArgName.includes('/')) podArgName = podArgName.split('/').pop()
        const args = ['debug', '-n', srcMeta.ns, `pod/${podArgName}`, '--profile=general', '--image=busybox:1.36', '--attach', '--', 'sh', '-ec', cmd]
        try {
          const { stdout, stderr } = await execCmd('kubectl', args, { KUBECONFIG: kcfg })
          const timedOut = /timed out/i.test(`${stdout}\n${stderr}`)
          runCmds.push({ proto: t.proto, port: t.port, ok: !timedOut, stdout, stderr, args: ['kubectl', ...args] })
        } catch (e) {
          runCmds.push({ proto: t.proto, port: t.port, ok: false, error: String(e.message || e), args: ['kubectl', ...args] })
        }
      }

      const afterSrc = await runPolGet(srcMeta, src)
      const afterDst = await runPolGet(dstMeta, dst)

      // Parse counters and suggest highlight hits based on real counter increases
      const parseRowsToMap = (text) => {
        const map = new Map()
        if (!text) return map
        const lines = String(text).split('\n')
        for (const line of lines) {
          const s = line.trim()
          if (!s) continue
          if (s.toUpperCase().startsWith('IDENTITY') || s.startsWith('DIRECTION')) continue
          const parts = s.split(/\s+/)
          if (parts.length < 4) continue
          let idTok = parts[0]
          let idNum = Number(idTok)
          if (Number.isNaN(idNum)) {
            const m = idTok.match(/\((\d+)\)/)
            if (m) idNum = Number(m[1])
          }
          const proto = parts[1]
          const dport = parts[2] === '*' ? 0 : Number(parts[2])
          // Heuristic: last numeric token on the line is packets counter or bytes; prefer the last number
          let lastNum = 0
          for (let i = parts.length - 1; i >= 0; i--) {
            const v = Number(parts[i])
            if (!Number.isNaN(v)) { lastNum = v; break }
          }
          if (!idNum || (Number.isNaN(dport) && parts[2] !== '*')) continue
          const key = `${idNum}|${String(proto).toUpperCase()}|${dport}`
          map.set(key, (map.get(key) || 0) + lastNum)
        }
        return map
      }
      const diffCounters = (beforeText, afterText) => {
        const b = parseRowsToMap(beforeText)
        const a = parseRowsToMap(afterText)
        const hits = []
        for (const [key, av] of a.entries()) {
          const bv = b.get(key) || 0
          if (av > bv) {
            const [idStr, proto, dportStr] = key.split('|')
            hits.push({ identity: Number(idStr), proto, dport: Number(dportStr) })
          }
        }
        return hits
      }
      let hitsEgress = diffCounters(beforeSrc, afterSrc)
      let hitsIngress = diffCounters(beforeDst, afterDst)

      // We need endpoint identities for merging tested tuples (query each endpoint's hosting cilium pod)
      let srcId, dstId
      try {
        const { stdout: sOut } = await execCmd('kubectl', ['exec', '-n', 'kube-system', srcMeta.ciliumPod, '--', 'cilium', 'endpoint', 'get', String(src), '-o', 'json'], { KUBECONFIG: kcfg })
        const sObj = JSON.parse(sOut)
        srcId = Number(sObj?.status?.identity?.id ?? sObj?.identity?.id)
      } catch {}
      try {
        const { stdout: dOut } = await execCmd('kubectl', ['exec', '-n', 'kube-system', dstMeta.ciliumPod, '--', 'cilium', 'endpoint', 'get', String(dst), '-o', 'json'], { KUBECONFIG: kcfg })
        const dObj = JSON.parse(dOut)
        dstId = Number(dObj?.status?.identity?.id ?? dObj?.identity?.id)
      } catch {}
      // Merge tested tuples to ensure '*' rows can be highlighted even if only opposite direction increments
      if (dstId) {
        for (const t of tests) {
          hitsEgress.push({ identity: Number(dstId), proto: String(t.proto).toUpperCase(), dport: Number(t.port) })
        }
      }
      if (srcId) {
        for (const t of tests) {
          hitsIngress.push({ identity: Number(srcId), proto: String(t.proto).toUpperCase(), dport: Number(t.port) })
        }
      }
      return { tests: runCmds, before: { src: beforeSrc, dst: beforeDst }, after: { src: afterSrc, dst: afterDst }, hits: { egress: hitsEgress, ingress: hitsIngress } }
    })
    res.json(out)
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) })
  }
})

app.post('/api/pwru', async (req, res) => {
  try {
    const { src, dst, srcIPv4, dstIPv4, proto, port, triggerTest } = req.body || {}
    if (!srcIPv4 || !dstIPv4) { 
      res.status(400).json({ error: 'Missing srcIPv4 or dstIPv4' })
      return 
    }
    
    const out = await withTmpKubeconfig(req.sessionID, async (kcfg) => {
      const pods = await listCiliumPods(kcfg)
      if (!pods.length) return { error: 'No cilium pods found' }
      
      // Build filter based on IPs and optional proto/port
      let pcapFilter = `host ${srcIPv4} and host ${dstIPv4}`
      if (proto) {
        pcapFilter += ` and ${String(proto).toLowerCase()}`
        if (port) {
          pcapFilter += ` and port ${port}`
        }
      }
      
      const pod = pods[0]
      const duration = 15 // seconds - longer to capture test traffic
      
      try {
        console.log(`[pwru] Starting pwru on pod ${pod} with filter: ${pcapFilter}`)
        
        // Simpler approach: just run pwru for the full duration
        // The frontend will wait 5 seconds before sending test traffic
        // Note: removed --filter-track-skb as it might be too restrictive
        const pwruScript = `
# Run pwru with timeout
timeout --signal=SIGINT ${duration} pwru --output-tuple --output-limit-lines=200 '${pcapFilter}' 2>&1 || true
`
        
        // Use kubectl debug with the toolbox image that has pwru
        const { stdout, stderr } = await execCmd('kubectl', [
          'debug', '-n', 'kube-system', `pod/${pod}`,
          '--profile=sysadmin',
          '--image=quay.io/isovalent-dev/cilium-debug-toolbox:latest',
          '--target=cilium-agent',
          '--attach',
          '--quiet',
          '--',
          'sh', '-c', pwruScript
        ], { KUBECONFIG: kcfg, maxBuffer: 10 * 1024 * 1024 })
        
        console.log(`[pwru] Completed. stdout length: ${stdout?.length || 0}, stderr length: ${stderr?.length || 0}`)
        console.log(`[pwru] First 500 chars of output: ${(stdout || stderr || '').substring(0, 500)}`)
        
        // Combine stdout and stderr - pwru writes to both
        const combinedOutput = `${stdout || ''}${stderr || ''}`.trim()
        const output = `Command: pwru --output-tuple --output-limit-lines=200 --filter-track-skb '${pcapFilter}'\nFilter: ${pcapFilter}\nDuration: ${duration}s\nSource IP: ${srcIPv4}\nDest IP: ${dstIPv4}\n${proto ? `Proto: ${proto}\n` : ''}${port ? `Port: ${port}\n` : ''}\n${combinedOutput}`.trim()
        
        // Check if we got any actual output
        if (!combinedOutput || combinedOutput.length === 0) {
          return { output: `${output}\n\nNo packets captured matching the filter. This could mean:\n- No traffic occurred during the ${duration}s capture window\n- The filter doesn't match any packets\n- Try running Test Policy again to generate traffic` }
        }
        
        return { output }
      } catch (e) {
        console.error(`[pwru] Error: ${e.message}`)
        // Check if the error message contains pwru output (it writes to stderr)
        const errMsg = String(e.message || e)
        if (errMsg.includes('Attaching kprobes') || errMsg.includes('Listening for events')) {
          // This is actually pwru output, not an error
          return { output: `Command: pwru --output-tuple --output-limit-lines=200 --filter-track-skb '${pcapFilter}'\nFilter: ${pcapFilter}\nDuration: ${duration}s\n\n${errMsg}` }
        }
        return { error: `Failed to run pwru: ${errMsg}` }
      }
    })
    
    res.json(out)
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) })
  }
})

app.get('/api/ep-no-policy', async (req, res) => {
  try {
    const out = await withTmpKubeconfig(req.sessionID, async (kcfg) => {
      const pods = await listCiliumPods(kcfg)
      if (!pods.length) return { pods: [], results: [], note: 'No cilium pods found in kube-system' }

      const results = []
      let srcGetHeader = ''
      let srcGetEgress = ''
      let dstGetHeader = ''
      let dstGetIngress = ''
      const buildSummaries = (text, dirWanted, reservedMap) => {
        const lines = String(text || '').split('\n')
        const headerLine = lines.find(l => /\bPOLICY\b\s+\bDIRECTION\b/i.test(l)) || ''
        const pad = (s, w) => String(s).padEnd(w, ' ')
        let header = ''
        if (headerLine) {
          const hp = headerLine.trim().split(/\s+/)
          if (hp.length >= 11) {
            header = pad(hp[0], 10) + pad(hp[1], 12) + pad(hp[2], 20) + pad(hp[4], 14) + pad(hp[9], 10) + hp[10]
          }
        }
        const rows = []
        for (const ln of lines) {
          if (!ln || !/\b(Ingress|Egress)\b/.test(ln)) continue
          if (!new RegExp(`\\b${dirWanted}\\b`, 'i').test(ln)) continue
          const parts = ln.trim().split(/\s+/)
          if (parts.length >= 8) {
            const labelTok = parts[2] || ''
            if (!/^reserved:/i.test(labelTok)) continue
            const labelName = labelTok.replace(/^reserved:/i, '')
            let identityNum = '?'
            for (const [id, name] of reservedMap.entries()) {
              if (String(name).toLowerCase() === labelName.toLowerCase()) {
                identityNum = String(id)
                break
              }
            }
            const labelDisplay = `${labelName}(${identityNum})`
            const row = pad(parts[0], 10) + pad(parts[1], 12) + pad(labelDisplay, 20) + pad(parts[3], 14) + pad(parts[6], 10) + parts[7]
            rows.push(row)
          }
        }
        return { header, body: rows.join('\n') }
      }
      for (const pod of pods) {
        try {
          // 1) endpoints JSON
          const { stdout: epListJson } = await execCmd('kubectl', ['exec', '-n', 'kube-system', pod, '--', 'cilium', 'endpoint', 'list', '-o', 'json'], { KUBECONFIG: kcfg })
          let epList
          try { epList = JSON.parse(epListJson) } catch { epList = [] }

          // Extract fields consistent with /api/ep-policies
          const endpoints = (Array.isArray(epList) ? epList : []).map((ep) => {
            const endpointId = ep?.id ?? ep?.endpoint?.id ?? ep?.endpointID ?? ''
            const podName = (() => {
              try {
                const ext = ep?.status?.['external-identifiers'] || ep?.status?.externalIdentifiers || {}
                return ext['pod-name'] || ext['k8s-pod-name'] || ext['pod'] || ''
              } catch {}
              return ''
            })()
            const ip = (() => {
              try {
                if (ep?.status?.networking?.addressing?.length) {
                  const addr = ep.status.networking.addressing[0]
                  return addr.ipv4 || addr.ipv6 || addr.ip || ''
                }
                if (ep?.networking?.addressing?.length) {
                  const addr = ep.networking.addressing[0]
                  return addr.ipv4 || addr.ipv6 || addr.ip || ''
                }
              } catch {}
              return ''
            })()
            const derivedPolicyNames = (() => {
              const names = new Set()
              try {
                const l4 = ep?.status?.policy?.realized?.l4 || {}
                for (const dir of ['egress', 'ingress']) {
                  const arr = Array.isArray(l4[dir]) ? l4[dir] : []
                  for (const rule of arr) {
                    const dfr = Array.isArray(rule?.['derived-from-rules']) ? rule['derived-from-rules'] : []
                    for (const labelSet of dfr) {
                      for (const lbl of (Array.isArray(labelSet) ? labelSet : [])) {
                        const idx = typeof lbl === 'string' ? lbl.indexOf('k8s:io.cilium.k8s.policy.name=') : -1
                        if (idx >= 0) {
                          const val = lbl.slice('k8s:io.cilium.k8s.policy.name='.length)
                          if (val) names.add(val)
                        }
                      }
                    }
                  }
                }
              } catch {}
              return Array.from(names)
            })()
            return { endpointId, podName, ip, policies: derivedPolicyNames }
          }).filter((x) => x.endpointId)

          // 2) Filter endpoints without any derived policies
          const noPolicy = endpoints.filter((e) => (e.policies?.length || 0) === 0)

          // 3) Render table (no POLICY NAMES column)
          const pad = (s, n) => String(s).padEnd(n, ' ')
          const hdr = pad('POD_NAME', 60) + pad('ENDPOINT ID', 12) + pad('ENDPOINT IP', 18)
          const rows = [hdr]
          for (const ep of noPolicy) {
            const line = pad(String(ep.podName || ''), 60) + pad(String(ep.endpointId), 12) + pad(ep.ip || '', 18)
            rows.push(line)
          }
          // Add blank line after each endpoint section for better readability
          const output = rows.join('\n') + '\n'
          results.push({ pod, ok: true, output })
        } catch (e) {
          results.push({ pod, ok: false, error: String(e.message || e) })
        }
      }
      return { pods, results }
    })
    res.json(out)
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) })
  }
})

app.get('/api/ep-policies', async (req, res) => {
  try {
    const out = await withTmpKubeconfig(req.sessionID, async (kcfg) => {
      const pods = await listCiliumPods(kcfg)
      if (!pods.length) return { pods: [], results: [], note: 'No cilium pods found in kube-system' }

      const results = []
      for (const pod of pods) {
        try {
          // 1) Get endpoints (JSON) -> map endpointId -> identity, ip, labels
          const { stdout: epListJson } = await execCmd('kubectl', ['exec', '-n', 'kube-system', pod, '--', 'cilium', 'endpoint', 'list', '-o', 'json'], { KUBECONFIG: kcfg })
          let epList
          try { epList = JSON.parse(epListJson) } catch { epList = [] }

          // 1a) Get the host/node IP for this Cilium agent pod
          let ciliumHostIP = ''
          try {
            const { stdout: podJson } = await execCmd('kubectl', ['get', 'pod', '-n', 'kube-system', pod, '-o', 'json'], { KUBECONFIG: kcfg })
            const podObj = JSON.parse(podJson)
            ciliumHostIP = podObj?.status?.hostIP || ''
          } catch {}

          // 1b) Also get plain table to extract LABELS column displayed by CLI
          const labelsByEndpointId = new Map()
          let epListTableCache = ''
          try {
            const { stdout: epListTable } = await execCmd('kubectl', ['exec', '-n', 'kube-system', pod, '--', 'cilium', 'endpoint', 'list'], { KUBECONFIG: kcfg })
            epListTableCache = String(epListTable || '')
            const lines = epListTableCache.split('\n')
            const hdrIdx = lines.findIndex(l => /\bENDPOINT\b/i.test(l) && /\bLABELS\b/i.test(l))
            if (hdrIdx >= 0) {
              const cols = lines[hdrIdx].trim().split(/\s{2,}/)
              const idIdx = cols.findIndex(c => /^ENDPOINT$/i.test(c))
              const labelToken = /[A-Za-z0-9_.-]+:[^\s]+/
              let currentEid = ''
              let skippedSecondHeader = false
              for (let i = hdrIdx + 1; i < lines.length; i++) {
                const ln = lines[i]
                if (!ln || !ln.trim()) continue
                // Skip the second header line that shows ENFORCEMENT columns
                if (!skippedSecondHeader && /ENFORCEMENT/i.test(ln)) { skippedSecondHeader = true; continue }
                const parts = ln.trim().split(/\s{2,}/)
                const startsWithId = /^\s*\d+\b/.test(ln)
                if (startsWithId) {
                  // New endpoint row
                  const idFromParts = (idIdx >= 0 && parts[idIdx]) ? parts[idIdx] : (ln.match(/\b(\d+)\b/)?.[1] || '')
                  if (idFromParts) currentEid = String(idFromParts).trim()
                  // Try to extract first label token from this row
                  const m = ln.match(labelToken)
                  if (currentEid && m && m[0] && !labelsByEndpointId.has(currentEid)) {
                    labelsByEndpointId.set(currentEid, m[0])
                  }
                } else if (currentEid && !labelsByEndpointId.get(currentEid)) {
                  // Continuation line (wrapped labels under the same endpoint)
                  const cont = ln.trim()
                  if (cont && !/^STATUS/i.test(cont) && !/^READY/i.test(cont)) {
                    const m2 = cont.match(labelToken)
                    if (m2 && m2[0]) labelsByEndpointId.set(currentEid, m2[0])
                  }
                }
              }
            }
          } catch {}

          const endpoints = (Array.isArray(epList) ? epList : []).map((ep) => {
            const endpointId = ep?.id ?? ep?.endpoint?.id ?? ep?.endpointID ?? ''
            const identity = ep?.security?.identity?.id ?? ep?.status?.identity?.id ?? ep?.identity?.id
            const podName = (() => {
              try {
                const ext = ep?.status?.['external-identifiers'] || ep?.status?.externalIdentifiers || {}
                return ext['pod-name'] || ext['k8s-pod-name'] || ext['pod'] || ''
              } catch {}
              return ''
            })()
            const ip = (() => {
              try {
                // Prefer status.networking.addressing[].ipv4 (as in endpoint list JSON)
                if (ep?.status?.networking?.addressing?.length) {
                  const addr = ep.status.networking.addressing[0]
                  return addr.ipv4 || addr.ipv6 || addr.ip || ''
                }
                if (ep?.networking?.addressing?.length) {
                  const addr = ep.networking.addressing[0]
                  return addr.ipv4 || addr.ipv6 || addr.ip || ''
                }
                if (ep?.status?.externalIdentifiers?.ip) return ep.status.externalIdentifiers.ip
              } catch {}
              return ''
            })()
            const labelsArr = (() => {
              try {
                if (ep?.status?.labels?.realized) return ep.status.labels.realized
                if (ep?.status?.labels?.security) return ep.status.labels.security
                if (ep?.labels?.security) return ep.labels.security
                if (Array.isArray(ep?.labels)) return ep.labels
              } catch {}
              return []
            })()
            const labelsFlat = (() => {
              const out = []
              const arr = Array.isArray(labelsArr) ? labelsArr : []
              for (const it of arr) {
                if (typeof it === 'string') { out.push(it); continue }
                if (it && typeof it === 'object') {
                  const src = it.source || it.Source || ''
                  const key = it.key || it.Key || ''
                  const val = it.value ?? it.Value
                  if (key) {
                    const prefix = src ? `${src}:` : ''
                    out.push(val === undefined || val === null || val === '' ? `${prefix}${key}` : `${prefix}${key}=${val}`)
                  }
                }
              }
              return out
            })()
            const labelsFromTable = labelsByEndpointId.get(String(endpointId).trim()) || simpleFirstLabel(String(endpointId).trim()) || ''
            return { endpointId, identity, podName, ip, labels: labelsFlat, labelsFromTable }
          }).filter((x) => x.endpointId)

          // 2) Extract policy names directly from endpoint JSON derived-from-rules
          const policyByEndpoint = new Map()
          const getDerivedPolicyNames = (epObj) => {
            const names = new Set()
            try {
              const l4 = epObj?.status?.policy?.realized?.l4 || {}
              for (const dir of ['egress', 'ingress']) {
                const arr = Array.isArray(l4[dir]) ? l4[dir] : []
                for (const rule of arr) {
                  const dfr = Array.isArray(rule?.['derived-from-rules']) ? rule['derived-from-rules'] : []
                  for (const labelSet of dfr) {
                    // labelSet is an array of strings like "k8s:io.cilium.k8s.policy.name=..."
                    for (const lbl of (Array.isArray(labelSet) ? labelSet : [])) {
                      const idx = typeof lbl === 'string' ? lbl.indexOf('k8s:io.cilium.k8s.policy.name=') : -1
                      if (idx >= 0) {
                        const val = lbl.slice('k8s:io.cilium.k8s.policy.name='.length)
                        if (val) names.add(val)
                      }
                    }
                  }
                }
              }
            } catch {}
            return Array.from(names).sort((a, b) => String(a).localeCompare(String(b)))
          }
          for (const epObj of (Array.isArray(epList) ? epList : [])) {
            const eid = epObj?.id ?? epObj?.endpoint?.id ?? epObj?.endpointID
            if (eid === undefined || eid === null) continue
            policyByEndpoint.set(String(eid), getDerivedPolicyNames(epObj))
          }

          // 3) Prepare rows using derived policies
          const pad = (s, n) => String(s).padEnd(n, ' ')
          const hdr = pad('POD_NAME', 60) + pad('ENDPOINT ID', 12) + pad('ENDPOINT IP', 18) + 'POLICY NAMES'
          const rows = [hdr]
          for (const ep of endpoints) {
            const policyNames = (policyByEndpoint.get(String(ep.endpointId)) || []).slice().sort((a, b) => String(a).localeCompare(String(b)))
            let podDisplay = ep.podName && ep.podName !== '/' ? ep.podName : ''
            if (!podDisplay) {
              const firstFromTable = String(ep.labelsFromTable || '').trim().split(/\s+/).filter(Boolean)[0] || ''
              if (firstFromTable) podDisplay = firstFromTable
            }
            if (!podDisplay) {
              const firstFromJson = Array.isArray(ep.labels) && ep.labels.length ? String(ep.labels[0]) : ''
              if (firstFromJson) podDisplay = firstFromJson
            }
            if (!podDisplay) podDisplay = '/'
            const ipDisplay = (ep.ip && String(ep.ip).trim()) ? ep.ip : (ciliumHostIP || '')
            const line = pad(String(podDisplay || ''), 60) + pad(String(ep.endpointId), 12) + pad(ipDisplay, 18) + policyNames.join(',')
            rows.push(line)
          }
          // Add blank line after each endpoint section for better readability
          const output = rows.join('\n') + '\n'
          results.push({ pod, ok: true, output })
        } catch (e) {
          results.push({ pod, ok: false, error: String(e.message || e) })
        }
      }
      return { pods, results }
    })
    res.json(out)
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) })
  }
})

app.get('/api/selectors', async (req, res) => {
  try {
    const out = await withTmpKubeconfig(req.sessionID, async (kcfg) => {
      const pods = await listCiliumPods(kcfg)
      if (!pods.length) return { pods: [], results: [], note: 'No cilium pods found in kube-system' }
      const results = []
      for (const pod of pods) {
        try {
          const { stdout } = await execCmd('kubectl', ['exec', '-n', 'kube-system', pod, '--', 'cilium', 'policy', 'selectors', '-v'], { KUBECONFIG: kcfg })
          results.push({ pod, ok: true, output: stdout })
        } catch (e) {
          results.push({ pod, ok: false, error: String(e.message || e) })
        }
      }
      return { pods, results }
    })
    res.json(out)
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) })
  }
})

function withTmpKubeconfig(sessionID, fn) {
  return new Promise((resolve, reject) => {
    let data = store.get(sessionID)
    // Auto-load default kubeconfig for this session if not yet set
    if ((!data || !data.kubeconfig) && GLOBAL_DEFAULT_KUBECONFIG && GLOBAL_DEFAULT_KUBECONFIG.trim()) {
      console.log(`[withTmpKubeconfig] Auto-loading default kubeconfig for session ${sessionID}`)
      data = { kubeconfig: GLOBAL_DEFAULT_KUBECONFIG }
      store.set(sessionID, data)
    }
    if (!data || !data.kubeconfig) {
      console.error(`[withTmpKubeconfig] No kubeconfig for session ${sessionID}, has default: ${!!GLOBAL_DEFAULT_KUBECONFIG}`)
      reject(new Error(`No kubeconfig available (session empty and default not found at ${DEFAULT_KUBECONFIG_PATH})`)); return
    }
    const tmpPath = path.join(os.tmpdir(), `kcfg-${sessionID}.yaml`)
    fs.writeFile(tmpPath, data.kubeconfig, { encoding: 'utf8' }, (err) => {
      if (err) { reject(err); return }
      fn(tmpPath).then((res) => {
        fs.unlink(tmpPath, () => resolve(res))
      }).catch((e) => {
        fs.unlink(tmpPath, () => reject(e))
      })
    })
  })
}

function execCmd(cmd, args, envExtra = {}) {
  return new Promise((resolve, reject) => {
    const options = { 
      env: { ...process.env, ...envExtra },
      timeout: 30000, // 30 second timeout
      maxBuffer: envExtra.maxBuffer || 1024 * 1024 // 1MB default, can be overridden
    }
    const child = execFile(cmd, args, options, (err, stdout, stderr) => {
      if (err) {
        // If there's output, it might be a successful command that exited with non-zero
        // (e.g., timeout command, or kubectl debug with timeout)
        if (stdout || stderr) {
          resolve({ stdout, stderr, exitCode: err.code })
        } else {
          const errMsg = stderr || stdout || err.message
          reject(new Error(errMsg))
        }
        return 
      }
      resolve({ stdout, stderr, exitCode: 0 })
    })
  })
}

async function listCiliumPods(kubeconfigPath) {
  // Try common selectors
  const selectors = [
    'k8s-app=cilium',
    'k8s-app=cilium-agent',
    'app.kubernetes.io/name=cilium',
  ]
  for (const sel of selectors) {
    try {
      const { stdout } = await execCmd('kubectl', ['get', 'pods', '-n', 'kube-system', '-l', sel, '-o', 'name'], { KUBECONFIG: kubeconfigPath })
      const pods = stdout.trim().split('\n').filter(Boolean).map((l) => l.replace('pod/', ''))
      if (pods.length) return pods
    } catch {}
  }
  return []
}

app.get('/api/endpoints', async (req, res) => {
  try {
    const out = await withTmpKubeconfig(req.sessionID, async (kcfg) => {
      const pods = await listCiliumPods(kcfg)
      if (!pods.length) return { pods: [], results: [], note: 'No cilium pods found in kube-system' }
      const results = []
      for (const pod of pods) {
        try {
          const { stdout } = await execCmd('kubectl', ['exec', '-n', 'kube-system', pod, '--', 'cilium', 'endpoint', 'list'], { KUBECONFIG: kcfg })
          results.push({ pod, ok: true, output: stdout })
        } catch (e) {
          results.push({ pod, ok: false, error: String(e.message || e) })
        }
      }
      return { pods, results }
    })
    res.json(out)
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) })
  }
})

app.get('/api/policies', async (req, res) => {
  try {
    const out = await withTmpKubeconfig(req.sessionID, async (kcfg) => {
      const pods = await listCiliumPods(kcfg)
      if (!pods.length) return { pods: [], results: [], note: 'No cilium pods found in kube-system' }
      const results = []
      for (const pod of pods) {
        try {
          const { stdout } = await execCmd('kubectl', ['exec', '-n', 'kube-system', pod, '--', 'cilium', 'bpf', 'policy', 'list'], { KUBECONFIG: kcfg })
          results.push({ pod, ok: true, output: stdout })
        } catch (e) {
          results.push({ pod, ok: false, error: String(e.message || e) })
        }
      }
      return { pods, results }
    })
    res.json(out)
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) })
  }
})

// Static client (vite dev serves separately; for production, build to dist and serve here)
app.use(express.static(path.join(__dirname, 'dist')))

const PORT = process.env.PORT || 12090
app.listen(PORT, () => console.log(`visual-inspector server listening on :${PORT}`))

// --- Policy Path helpers & endpoints ---
app.get('/api/ep-index', async (req, res) => {
  try {
    const out = await withTmpKubeconfig(req.sessionID, async (kcfg) => {
      const pods = await listCiliumPods(kcfg)
      const endpoints = []
      for (const pod of pods) {
        try {
          const { stdout } = await execCmd('kubectl', ['exec', '-n', 'kube-system', pod, '--', 'cilium', 'endpoint', 'list', '-o', 'json'], { KUBECONFIG: kcfg })
          let epList; try { epList = JSON.parse(stdout) } catch { epList = [] }
          for (const ep of (Array.isArray(epList) ? epList : [])) {
            const id = ep?.id ?? ep?.endpoint?.id ?? ep?.endpointID
            if (id === undefined || id === null) continue
            let podName = ''
            try {
              const ext = ep?.status?.['external-identifiers'] || ep?.status?.externalIdentifiers || {}
              podName = ext['pod-name'] || ext['k8s-pod-name'] || ext['pod'] || ''
            } catch {}
            endpoints.push({ pod, id: String(id), podName })
          }
        } catch {}
      }
      // Sort by podName then id
      endpoints.sort((a, b) => (a.podName || '').localeCompare(b.podName || '') || String(a.id).localeCompare(String(b.id)))
      return { endpoints }
    })
    res.json(out)
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) })
  }
})

app.get('/api/policy-path', async (req, res) => {
  try {
    const src = String(req.query.src || '').trim()
    const dst = String(req.query.dst || '').trim()
    if (!src || !dst) { res.status(400).json({ error: 'Missing src or dst query param' }); return }
    const out = await withTmpKubeconfig(req.sessionID, async (kcfg) => {
      const pods = await listCiliumPods(kcfg)
      const results = []
      // Summaries from `cilium bpf policy get <endpoint>`
      let srcGetHeader = ''
      let srcGetEgress = ''
      let dstGetHeader = ''
      let dstGetIngress = ''
      const buildSummaries = (text, dirWanted, reservedMap, oppositeIdentity, oppositeEndpointLabels) => {
        const lines = String(text || '').split('\n')
        const headerLine = lines.find(l => /\bPOLICY\b\s+\bDIRECTION\b/i.test(l)) || ''
        const pad = (s, w) => String(s).padEnd(w, ' ')
        let header = ''
        if (headerLine) {
          const hp = headerLine.trim().split(/\s+/)
          if (hp.length >= 11) {
            header = pad(hp[0], 10) + pad(hp[1], 12) + pad(hp[2], 20) + pad(hp[4], 14) + pad(hp[9], 10) + hp[10]
          }
        }
        const rows = []
        // Extract display name once from opposite endpoint labels
        let oppositeDisplayName = null
        if (oppositeIdentity && oppositeEndpointLabels && Array.isArray(oppositeEndpointLabels)) {
          const podLabel = oppositeEndpointLabels.find(l => /^k8s:io\.kubernetes\.pod\.namespace=/i.test(String(l)))
          const classLabel = oppositeEndpointLabels.find(l => /^k8s:class=/i.test(String(l)))
          if (podLabel && classLabel) {
            const ns = String(podLabel).replace(/^k8s:io\.kubernetes\.pod\.namespace=/i, '')
            const cls = String(classLabel).replace(/^k8s:class=/i, '')
            oppositeDisplayName = `${ns}/${cls}`
          } else {
            // Try alternative label patterns
            const nsLabel = oppositeEndpointLabels.find(l => /^k8s:io\.kubernetes\.pod\.namespace=/i.test(String(l)) || /^k8s:namespace=/i.test(String(l)))
            const appLabel = oppositeEndpointLabels.find(l => /^k8s:app=/i.test(String(l)))
            if (nsLabel && appLabel) {
              const ns = String(nsLabel).replace(/^k8s:(io\.kubernetes\.pod\.)?namespace=/i, '')
              const app = String(appLabel).replace(/^k8s:app=/i, '')
              oppositeDisplayName = `${ns}/${app}`
            } else {
              // Fallback: use identity number if we can't extract namespace/class
              oppositeDisplayName = `identity-${oppositeIdentity}`
            }
          }
        }
        // First pass: collect all k8s: lines to find the one with most traffic
        let bestK8sLine = null
        let maxTraffic = -1
        for (const ln of lines) {
          if (!ln || !/\b(Ingress|Egress)\b/.test(ln)) continue
          const parts = ln.trim().split(/\s+/)
          if (parts.length >= 8) {
            // Check direction from parts[1] (DIRECTION column), not from the full line
            const direction = parts[1] || ''
            if (!new RegExp(`^${dirWanted}$`, 'i').test(direction)) continue
            const labelTok = parts[2] || ''
            if (!(/^reserved:/i.test(labelTok)) && /\bk8s:/i.test(ln)) {
              const bytes = Number(parts[6]) || 0
              const packets = Number(parts[7]) || 0
              const traffic = bytes + packets
              if (traffic > maxTraffic) {
                maxTraffic = traffic
                bestK8sLine = { parts, ln }
              }
            }
          }
        }
        // Second pass: build rows
        for (const ln of lines) {
          if (!ln || !/\b(Ingress|Egress)\b/.test(ln)) continue
          const parts = ln.trim().split(/\s+/)
          if (parts.length >= 8) {
            // Check direction from parts[1] (DIRECTION column), not from the full line
            const direction = parts[1] || ''
            if (!new RegExp(`^${dirWanted}$`, 'i').test(direction)) continue
            const labelTok = parts[2] || ''
            // Include reserved labels
            if (/^reserved:/i.test(labelTok)) {
              const labelName = labelTok.replace(/^reserved:/i, '')
              let identityNum = '?'
              for (const [id, name] of reservedMap.entries()) {
                if (String(name).toLowerCase() === labelName.toLowerCase()) {
                  identityNum = String(id)
                  break
                }
              }
              const labelDisplay = `${labelName}(${identityNum})`
              const row = pad(parts[0], 10) + pad(parts[1], 12) + pad(labelDisplay, 20) + pad(parts[3], 14) + pad(parts[6], 10) + parts[7]
              rows.push(row)
            }
          }
        }
        // Add the opposite endpoint row if we found one with traffic
        if (bestK8sLine && oppositeDisplayName) {
          const parts = bestK8sLine.parts
          const row = pad(parts[0], 10) + pad(parts[1], 12) + pad(oppositeDisplayName, 20) + pad(parts[3], 14) + pad(parts[6], 10) + parts[7]
          rows.push(row)
        }
        return { header, body: rows.join('\n') }
      }
      // Build reserved identity ID -> name (e.g., 2 -> world) from the first cilium pod
      const reservedMap = new Map()
      try {
        const idPod = pods[0]
        if (idPod) {
          const { stdout: idJson } = await execCmd('kubectl', ['exec', '-n', 'kube-system', idPod, '--', 'cilium', 'identity', 'list', '-o', 'json'], { KUBECONFIG: kcfg })
          let ids; try { ids = JSON.parse(idJson) } catch { ids = [] }
          for (const it of (Array.isArray(ids) ? ids : [])) {
            const id = it?.id ?? it?.ID ?? it?.Id
            const labels = Array.isArray(it?.labels) ? it.labels : (Array.isArray(it?.Labels) ? it.Labels : [])
            if (id === undefined || id === null) continue
            let name = ''
            for (const lbl of labels) {
              const s = String(lbl || '')
              if (s.startsWith('reserved:')) { name = s.slice('reserved:'.length); break }
            }
            if (name) reservedMap.set(String(id), name)
          }
        }
      } catch {}

      // Build a GLOBAL endpointID -> identity map across all cilium pods
      const epIdToIdentityGlobal = new Map()
      // Also capture src/dst workload pod names, policies, and which cilium pod hosts them
      let srcHostCiliumPod = ''
      let dstHostCiliumPod = ''
      let srcWorkloadPod = ''
      let dstWorkloadPod = ''
      let srcWorkloadNs = ''
      let dstWorkloadNs = ''
      let srcPolicies = []
      let dstPolicies = []
      let srcIPv4 = ''
      let dstIPv4 = ''
      let srcLabels = []
      let dstLabels = []
      const extractDerivedPolicyNames = (epObj) => {
        const names = new Set()
        try {
          const l4 = epObj?.status?.policy?.realized?.l4 || {}
          for (const dir of ['egress', '_ingress', 'ingress']) {
            const arr = Array.isArray(l4[dir]) ? l4[dir] : []
            for (const rule of arr) {
              const dfr = Array.isArray(rule?.['derived-from-rules']) ? rule['derived-from-rules'] : []
              for (const labelSet of dfr) {
                for (const lbl of (Array.isArray(labelSet) ? labelSet : [])) {
                  const idx = typeof lbl === 'string' ? lbl.indexOf('k8s:io.cilium.k8s.policy.name=') : -1
                  if (idx >= 0) {
                    const val = lbl.slice('k8s:io.cilium.k8s.policy.name='.length)
                    if (val) names.add(val)
                  }
                }
              }
            }
          }
        } catch {}
        return Array.from(names).sort((a, b) => String(a).localeCompare(String(b)))
      }
      for (const pod of pods) {
        try {
          const { stdout: epListJson } = await execCmd('kubectl', ['exec', '-n', 'kube-system', pod, '--', 'cilium', 'endpoint', 'list', '-o', 'json'], { KUBECONFIG: kcfg })
          let epList; try { epList = JSON.parse(epListJson) } catch { epList = [] }
          for (const ep of (Array.isArray(epList) ? epList : [])) {
            const eid = ep?.id ?? ep?.endpoint?.id ?? ep?.endpointID
            const ident = ep?.security?.identity?.id ?? ep?.status?.identity?.id ?? ep?.identity?.id
            if (eid !== undefined && eid !== null && ident !== undefined && ident !== null) {
              epIdToIdentityGlobal.set(String(eid), Number(ident))
            }
            if (String(eid) === String(src)) {
              srcHostCiliumPod = pod
              try {
                const ext = ep?.status?.['external-identifiers'] || ep?.status?.externalIdentifiers || {}
                srcWorkloadPod = ext['pod-name'] || ext['k8s-pod-name'] || ext['pod'] || ''
                srcWorkloadNs = ext['k8s-namespace'] || ext['k8s_namespace'] || ext['namespace'] || ext['pod-namespace'] || ext['k8s-pod-namespace'] || srcWorkloadNs
              } catch {}
              if (!srcWorkloadNs) {
                try {
                  const labels = ep?.status?.labels?.security || ep?.labels?.security || ep?.labels || []
                  const arrL = Array.isArray(labels) ? labels : []
                  for (const l of arrL) {
                    const s = String(l || '')
                    const p1 = 'k8s:io.kubernetes.pod.namespace='
                    const p2 = 'k8s:namespace='
                    if (s.startsWith(p1)) { srcWorkloadNs = s.slice(p1.length); break }
                    if (s.startsWith(p2)) { srcWorkloadNs = s.slice(p2.length); break }
                  }
                } catch {}
              }
              srcPolicies = extractDerivedPolicyNames(ep)
              try {
                const labelsArr = ep?.status?.labels?.security || ep?.labels?.security || ep?.labels || []
                srcLabels = []
                for (const it of (Array.isArray(labelsArr) ? labelsArr : [])) {
                  if (typeof it === 'string') { srcLabels.push(it); continue }
                  if (it && typeof it === 'object') {
                    const src = it.source || it.Source || ''
                    const key = it.key || it.Key || ''
                    const val = it.value ?? it.Value
                    if (key) {
                      const prefix = src ? `${src}:` : ''
                      srcLabels.push(val === undefined || val === null || val === '' ? `${prefix}${key}` : `${prefix}${key}=${val}`)
                    }
                  }
                }
              } catch {}
              try {
                if (ep?.status?.networking?.addressing?.length) {
                  const addr = ep.status.networking.addressing[0]
                  srcIPv4 = addr.ipv4 || ''
                } else if (ep?.networking?.addressing?.length) {
                  const addr = ep.networking.addressing[0]
                  srcIPv4 = addr.ipv4 || ''
                }
              } catch {}
            }
            if (String(eid) === String(dst)) {
              dstHostCiliumPod = pod
              try {
                const ext = ep?.status?.['external-identifiers'] || ep?.status?.externalIdentifiers || {}
                dstWorkloadPod = ext['pod-name'] || ext['k8s-pod-name'] || ext['pod'] || ''
                dstWorkloadNs = ext['k8s-namespace'] || ext['k8s_namespace'] || ext['namespace'] || ext['pod-namespace'] || ext['k8s-pod-namespace'] || dstWorkloadNs
              } catch {}
              if (!dstWorkloadNs) {
                try {
                  const labels = ep?.status?.labels?.security || ep?.labels?.security || ep?.labels || []
                  const arrL = Array.isArray(labels) ? labels : []
                  for (const l of arrL) {
                    const s = String(l || '')
                    const p1 = 'k8s:io.kubernetes.pod.namespace='
                    const p2 = 'k8s:namespace='
                    if (s.startsWith(p1)) { dstWorkloadNs = s.slice(p1.length); break }
                    if (s.startsWith(p2)) { dstWorkloadNs = s.slice(p2.length); break }
                  }
                } catch {}
              }
              dstPolicies = extractDerivedPolicyNames(ep)
              try {
                const labelsArr = ep?.status?.labels?.security || ep?.labels?.security || ep?.labels || []
                dstLabels = []
                for (const it of (Array.isArray(labelsArr) ? labelsArr : [])) {
                  if (typeof it === 'string') { dstLabels.push(it); continue }
                  if (it && typeof it === 'object') {
                    const src = it.source || it.Source || ''
                    const key = it.key || it.Key || ''
                    const val = it.value ?? it.Value
                    if (key) {
                      const prefix = src ? `${src}:` : ''
                      dstLabels.push(val === undefined || val === null || val === '' ? `${prefix}${key}` : `${prefix}${key}=${val}`)
                    }
                  }
                }
              } catch {}
              try {
                if (ep?.status?.networking?.addressing?.length) {
                  const addr = ep.status.networking.addressing[0]
                  dstIPv4 = addr.ipv4 || ''
                } else if (ep?.networking?.addressing?.length) {
                  const addr = ep.networking.addressing[0]
                  dstIPv4 = addr.ipv4 || ''
                }
              } catch {}
            }
          }
        } catch {}
      }
      const srcIdentityGlobal = epIdToIdentityGlobal.get(String(src))
      const dstIdentityGlobal = epIdToIdentityGlobal.get(String(dst))

      for (const pod of pods) {
        try {
          // Use global identities for filtering
          const srcIdentity = srcIdentityGlobal
          const dstIdentity = dstIdentityGlobal

          const { stdout } = await execCmd('kubectl', ['exec', '-n', 'kube-system', pod, '--', 'cilium', 'bpf', 'policy', 'list', '-o', 'json'], { KUBECONFIG: kcfg })
          let items; try { items = JSON.parse(stdout) } catch { items = [] }
          const egressSrc = []
          const ingressDst = []
          const ntohs = (n) => {
            const v = Number(n) >>> 0
            return ((v & 0xff) << 8) | ((v >>> 8) & 0xff)
          }
          const protoName = (n) => ({ 6: 'TCP', 17: 'UDP', 132: 'SCTP' }[Number(n)] || String(Number(n) || 0))
          for (const it of (Array.isArray(items) ? items : [])) {
            const eid = String(it?.EndpointID || '')
            const content = Array.isArray(it?.Content) ? it.Content : []
            for (const entry of content) {
              const dir = Number(entry?.Key?.TrafficDirection)
              const ident = Number(entry?.Key?.Identity)
              const nexthdr = Number(
                entry?.Key?.Nexthdr ?? entry?.Key?.NextHeader ?? entry?.Key?.Proto ?? 0
              )
              const dportRaw = Number(
                entry?.Key?.DestPortNetwork ?? entry?.Key?.DestPort ?? entry?.Key?.Dport ?? 0
              )
              const dport = dportRaw ? ntohs(dportRaw) : 0
              const flags = Number(entry?.Flags)
              // TrafficDirection: 1 egress, 0 ingress
              if (eid === src && dir === 1) {
                // Keep opposite endpoint identity and reserved identities (<=256)
                if ((dstIdentity !== undefined && ident === Number(dstIdentity)) || ident <= 256) {
                  egressSrc.push({ identity: ident, proto: protoName(nexthdr), dport, flags })
                }
              } else if (eid === dst && dir === 0) {
                // Keep opposite endpoint identity and reserved identities (<=256)
                if ((srcIdentity !== undefined && ident === Number(srcIdentity)) || ident <= 256) {
                  ingressDst.push({ identity: ident, proto: protoName(nexthdr), dport, flags })
                }
              }
            }
          }
          // If identity has any ALLOW entries, mark its wildcard (*,*) entry as ALLOW for readability
          const markWildcardAllows = (arr) => {
            const allowed = new Set(arr.filter(x => (Number(x.flags) & 0x80) !== 0).map(x => String(x.identity)))
            for (const x of arr) {
              const isWildcardPort = !x.dport || Number(x.dport) === 0
              const isWildcardProto = x.proto === '0' || x.proto === 0 || x.proto === '*'
              if (isWildcardPort && isWildcardProto && allowed.has(String(x.identity)) && (Number(x.flags) & 0x80) === 0) {
                x.flags = 0x80
              }
            }
          }
          markWildcardAllows(egressSrc)
          markWildcardAllows(ingressDst)
          const markZeroIfAnyAllowed = (arr) => {
            const anyAllowed = arr.some(x => (Number(x.flags) & 0x80) !== 0)
            if (!anyAllowed) return
            for (const x of arr) {
              if (Number(x.identity) === 0) x.flags = (Number(x.flags) | 0x80)
            }
          }
          markZeroIfAnyAllowed(egressSrc)
          markZeroIfAnyAllowed(ingressDst)

          // Override allow/deny using human-readable `cilium bpf policy get <eid>` output
          const reservedNameToId = (() => {
            const m = new Map()
            for (const [id, name] of reservedMap.entries()) m.set(String(name), Number(id))
            // Common well-known defaults if not present
            if (!m.has('unknown')) m.set('unknown', 0)
            if (!m.has('host')) m.set('host', 1)
            if (!m.has('world')) m.set('world', 2)
            if (!m.has('cluster')) m.set('cluster', 3)
            if (!m.has('health')) m.set('health', 4)
            return m
          })()
          const parseGetAllowSets = (text) => {
            const allow = { ingress: new Set(), egress: new Set() }
            try {
              const lines = String(text || '').split('\n')
              for (const ln of lines) {
                const m = ln.match(/^\s*(Allow|Deny)\s+(Ingress|Egress)\s+(.*)$/)
                if (!m) continue
                const verb = m[1]
                const dir = m[2].toLowerCase()
                const labelsStr = m[3] || ''
                if (verb !== 'Allow') continue
                const toks = labelsStr.split(/\s+/).filter(Boolean)
                for (const t of toks) {
                  const rm = t.match(/^reserved:([A-Za-z0-9_.-]+)/)
                  if (rm) {
                    const id = reservedNameToId.get(rm[1])
                    if (id) allow[dir].add(Number(id))
                  }
                }
              }
            } catch {}
            return allow
          }
          try {
            if (src) {
              const hostPod = srcHostCiliumPod || pod
              const { stdout: gOut } = await execCmd('kubectl', ['exec', '-n', 'kube-system', hostPod, '--', 'cilium', 'bpf', 'policy', 'get', String(src)], { KUBECONFIG: kcfg })
              const allow = parseGetAllowSets(gOut)
              if (allow.egress.size) {
                for (const x of egressSrc) { if (allow.egress.has(Number(x.identity))) x.flags = (Number(x.flags) | 0x80) }
              }
              // Fallback: if any Egress Allow line exists at all, force identity 0 wildcard to ALLOW
              if (/^\s*Allow\s+Egress\b/m.test(String(gOut || ''))) {
                let hasZero = false
                for (const x of egressSrc) { if (Number(x.identity) === 0) { x.flags = (Number(x.flags) | 0x80); hasZero = true } }
                if (!hasZero) egressSrc.unshift({ identity: 0, proto: '*', dport: 0, flags: 0x80 })
              }
              // For Egress from source, pass destination identity and labels
              const sum = buildSummaries(gOut, 'Egress', reservedMap, dstIdentity, dstLabels)
              // Don't add synthetic numeric identity rows - only show reserved labels
              srcGetHeader = sum.header
              srcGetEgress = sum.body
            }
          } catch {}
          try {
            if (dst) {
              const hostPod = dstHostCiliumPod || pod
              const { stdout: gOut } = await execCmd('kubectl', ['exec', '-n', 'kube-system', hostPod, '--', 'cilium', 'bpf', 'policy', 'get', String(dst)], { KUBECONFIG: kcfg })
              const allow = parseGetAllowSets(gOut)
              if (allow.ingress.size) {
                // Mark matching identities ALLOW
                for (const x of ingressDst) { if (allow.ingress.has(Number(x.identity))) x.flags = (Number(x.flags) | 0x80) }
                // Ensure identity 0 wildcard exists and is ALLOW
                let hasZero = false
                for (const x of ingressDst) { if (Number(x.identity) === 0) { x.flags = (Number(x.flags) | 0x80); hasZero = true } }
                if (!hasZero) ingressDst.unshift({ identity: 0, proto: '*', dport: 0, flags: 0x80 })
              }
              // Fallback: if any Ingress Allow line exists at all, force identity 0 wildcard to ALLOW
              if (/^\s*Allow\s+Ingress\b/m.test(String(gOut || ''))) {
                let hasZero = false
                for (const x of ingressDst) { if (Number(x.identity) === 0) { x.flags = (Number(x.flags) | 0x80); hasZero = true } }
                if (!hasZero) ingressDst.unshift({ identity: 0, proto: '*', dport: 0, flags: 0x80 })
              }
              // For Ingress to destination, pass source identity and labels
              const sum = buildSummaries(gOut, 'Ingress', reservedMap, srcIdentity, srcLabels)
              // Don't add synthetic numeric identity rows - only show reserved labels
              dstGetHeader = sum.header
              dstGetIngress = sum.body
            }
          } catch {}

          const pad = (s, n) => String(s).padEnd(n, ' ')
          const flagsToText = (f) => {
            const v = Number(f) >>> 0
            const tags = []
            if (v & 0x80) tags.push('ALLOW')
            if (v & 0x40) tags.push('AUDIT')
            return tags.length ? tags.join('|') : 'DENY'
          }
          const fmtRow = (r) => {
            const proto = (r.proto === '0' || r.proto === 0) ? '*' : r.proto
            const port = Number(r.dport) || 0
            const protoStr = (proto === '*' ? 'ANY' : String(proto))
            const portStr = port === 0 ? 'ANY' : String(port)
            const actionTxt = flagsToText(r.flags)
            const idStr = (() => {
              const name = reservedMap.get(String(r.identity))
              if (name) return `reserved:${name}(${r.identity})`
              if (Number(r.identity) === 0) return 'reserved:unknown(0)'
              return String(r.identity)
            })()
            return [idStr, protoStr, portStr, actionTxt].join('\t\t')
          }
          const hdr = ['IDENTITY', 'PROTO', 'DPORT', 'ACTION'].join('\t\t')
          const srcRows = [hdr, ...egressSrc.map(fmtRow)].join('\n')
          const dstRows = [hdr, ...ingressDst.map(fmtRow)].join('\n')
          // Fallback: if identity not resolved from maps, get it directly from the correct hosting cilium pod
          try {
            if (!srcIdentity) {
              const hostPod = srcHostCiliumPod || pod
              const { stdout: sOut } = await execCmd('kubectl', ['exec', '-n', 'kube-system', hostPod, '--', 'cilium', 'endpoint', 'get', String(src), '-o', 'json'], { KUBECONFIG: kcfg })
              const sObj = JSON.parse(sOut)
              srcIdentity = Number(sObj?.status?.identity?.id ?? sObj?.identity?.id) || srcIdentity
            }
          } catch {}
          try {
            if (!dstIdentity) {
              const hostPod = dstHostCiliumPod || pod
              const { stdout: dOut } = await execCmd('kubectl', ['exec', '-n', 'kube-system', hostPod, '--', 'cilium', 'endpoint', 'get', String(dst), '-o', 'json'], { KUBECONFIG: kcfg })
              const dObj = JSON.parse(dOut)
              dstIdentity = Number(dObj?.status?.identity?.id ?? dObj?.identity?.id) || dstIdentity
            }
          } catch {}
          results.push({ pod, ok: true, source: src, dest: dst, srcIdentity, dstIdentity, egressFromSource: srcRows, ingressToDest: dstRows })
        } catch (e) {
          results.push({ pod, ok: false, error: String(e.message || e) })
        }
      }
      const pathSummary = `${srcHostCiliumPod || '(unknown-node)'}/${srcWorkloadPod || '(unknown-pod)'} [`+
        `${(srcPolicies && srcPolicies.length ? srcPolicies.join(',') : '-')}] -> `+
        `${dstHostCiliumPod || '(unknown-node)'}/${dstWorkloadPod || '(unknown-pod)'} [`+
        `${(dstPolicies && dstPolicies.length ? dstPolicies.join(',') : '-')}]`
      const path = {
        src: {
          node: srcHostCiliumPod || '',
          pod: srcWorkloadPod || '',
          ns: srcWorkloadNs || '',
          policies: Array.isArray(srcPolicies) ? srcPolicies : []
        },
        dst: {
          node: dstHostCiliumPod || '',
          pod: dstWorkloadPod || '',
          ns: dstWorkloadNs || '',
          policies: Array.isArray(dstPolicies) ? dstPolicies : []
        }
      }
      return { pods: [srcHostCiliumPod, dstHostCiliumPod].filter(Boolean), src, dst, pathSummary, path, srcIPv4, dstIPv4, results, srcGetHeader, srcGetEgress, dstGetHeader, dstGetIngress }
    })
    res.json(out)
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) })
  }
})

// Track active tcpdump processes
const activeTcpdumps = new Map()

// Run a tcpdump in an ephemeral debug container attached to a pod
app.post('/api/tcpdump', async (req, res) => {
  try {
    const { ns, pod, durationSeconds, captureId } = req.body || {}
    if (!ns || !pod) { res.status(400).json({ error: 'Missing ns or pod' }); return }
    const capId = captureId || `${ns}-${pod}-${Date.now()}`
    
    const out = await withTmpKubeconfig(req.sessionID, async (kcfg) => {
      // sanitize inputs: keep only bare names
      const rawPod = String(pod)
      const rawNs = String(ns)
      const safePod = rawPod.replace(/^pod\//, '').split('/').pop()
      const safeNs = rawNs.replace(/^namespace\//, '').split('/').pop()
      const dur = Number(durationSeconds) || 60
      // Use timeout as a safety limit, but allow early termination via SIGTERM
      // BusyBox timeout syntax: timeout [-s SIG] SECS PROG ARGS
      // -i any: capture on all interfaces
      // -nn: don't resolve hostnames or port names
      // -v: verbose output
      // -tttt: human-readable timestamps with date
      // -l: line-buffered output (flush after each line)
      // 'ip or arp': capture IPv4 and ARP packets
      const shellCmd = `timeout -s TERM ${dur} tcpdump -i any -nn -v -tttt -l 'ip or arp'`
      const tryRun = async (profile, image) => {
        return new Promise((resolve, reject) => {
          const args = ['--kubeconfig', kcfg, 'debug', '-n', safeNs, `pod/${safePod}`, `--profile=${profile}`, `--image=${image}`, '--attach', '--', 'sh', '-c', shellCmd]
          const child = execFile('kubectl', args, { 
            env: { ...process.env, KUBECONFIG: kcfg },
            maxBuffer: 10 * 1024 * 1024 // 10MB buffer for large captures
          }, (err, stdout, stderr) => {
            // Cleanup from active map
            activeTcpdumps.delete(capId)
            // tcpdump exits with code 124 when killed by timeout, or 0/1 normally
            // We treat any exit as success if we got output
            if (stdout || stderr) {
              resolve({ stdout, stderr, args: ['kubectl', ...args] })
            } else if (err) {
              reject(new Error(stderr || err.message))
            } else {
              resolve({ stdout, stderr, args: ['kubectl', ...args] })
            }
          })
          // Store the child process so we can kill it on demand
          activeTcpdumps.set(capId, child)
          // If client disconnects, kill the kubectl process (which will kill tcpdump)
          req.on('close', () => {
            if (!child.killed) {
              child.kill('SIGTERM')
              activeTcpdumps.delete(capId)
            }
          })
        })
      }
      try {
        // First, try with elevated netadmin profile and netshoot image
        const { stdout, stderr, args } = await tryRun('netadmin', 'nicolaka/netshoot:latest')
        return { ok: true, stdout, stderr, args, captureId: capId }
      } catch (e1) {
        try {
          // Fallback to general profile with dedicated tcpdump image
          const { stdout, stderr, args } = await tryRun('general', 'corfr/tcpdump:latest')
          return { ok: true, stdout, stderr, args, captureId: capId }
        } catch (e2) {
          return { ok: false, error: `netadmin failed: ${String(e1.message || e1)}; general failed: ${String(e2.message || e2)}` }
        }
      }
    })
    res.json(out)
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) })
  }
})

// Stop a running tcpdump capture
app.post('/api/tcpdump/stop', async (req, res) => {
  try {
    const { captureId } = req.body || {}
    if (!captureId) { res.status(400).json({ error: 'Missing captureId' }); return }
    const child = activeTcpdumps.get(captureId)
    if (child && !child.killed) {
      child.kill('SIGTERM')
      activeTcpdumps.delete(captureId)
      res.json({ ok: true, message: 'Capture stopped' })
    } else {
      res.json({ ok: false, message: 'Capture not found or already stopped' })
    }
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) })
  }
})
