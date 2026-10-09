import { useId, useState, type FormEvent } from 'react'
import { Activity, AlertTriangle, ArrowUpRight, Check, ChevronDown, FileImage, FileText, Globe2, LoaderCircle, Shield, ShieldAlert, ShieldCheck, Upload, X } from 'lucide-react'
import { BlurFade } from '@/components/ui/blur-fade'
import { Button } from '@/components/ui/button'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import './result-metrics.css'

type Mode = 'url' | 'email' | 'media'
type ResultData = { [key: string]: unknown }
type DataRecord = { [key: string]: unknown }
type AssessmentWarning = { code?: string; message?: string }
type MissingSignal = string | { signal_id?: string; code?: string; name?: string; state?: string; source?: string }
type RiskAssessment = { verdict?: string; risk_score?: number | null; severity?: string; confidence?: number | null; confidence_kind?: string; confidence_calibrated?: boolean; evidence_coverage?: number; analysis_completeness?: number; ml_probability?: number | null; top_signals?: Array<{ signal_id?: string; label?: string; description?: string; contribution?: number }>; warnings?: AssessmentWarning[]; missing_signals?: MissingSignal[]; status?: string }

function humanize(value: string) {
  return value.replace(/[._-]+/g, ' ').trim().replace(/\b\w/g, character => character.toUpperCase())
}

function formatMissingSignal(value: MissingSignal) {
  if (typeof value === 'string') return humanize(value)
  const label = value.signal_id ?? value.code ?? value.name ?? 'Unspecified check'
  return `${humanize(label)}${value.state ? ` (${humanize(value.state).toLowerCase()})` : ''}`
}

function normalizeWarnings(value: unknown): AssessmentWarning[] {
  if (!Array.isArray(value)) return []
  const warnings: AssessmentWarning[] = []
  for (const item of value) {
    if (typeof item === 'string') { warnings.push({ message: item }); continue }
    if (item && typeof item === 'object') {
      const warning = item as AssessmentWarning
      warnings.push({ code: typeof warning.code === 'string' ? warning.code : undefined,
        message: typeof warning.message === 'string' ? warning.message : undefined })
    }
  }
  return warnings
}

function displayMetric(value: number | null | undefined, suffix: string) {
  return typeof value === 'number' && Number.isFinite(value) ? `${Math.round(value)}${suffix}` : 'Unavailable'
}

function record(value: unknown): DataRecord {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as DataRecord : {}
}

function diagnosticValue(value: unknown, yes: string, no: string) {
  if (value === true || value === 1) return yes
  if (value === false || value === 0) return no
  return 'Unknown'
}

function diagnosticNumber(value: unknown, suffix = '') {
  return typeof value === 'number' && Number.isFinite(value) ? `${value.toLocaleString(undefined, { maximumFractionDigits: 3 })}${suffix}` : 'Unknown'
}

function websiteEvidence(data: ResultData) {
  const web = record(data.web_intelligence)
  const features = record(web.html_features)
  const fetch = record(web.fetch_summary)
  const brand = record(data.brand_intelligence)
  const crawl = record(brand.crawl)
  const pages = Array.isArray(crawl.pages) ? crawl.pages.map(record) : []
  const childPages = pages.filter(page => page.reused_root !== true && page.status === 'ANALYZED')
  const indicators = Array.isArray(web.indicators) ? web.indicators.map(record) : []
  const redirects = Array.isArray(record(web.behavior_intelligence).chain)
    ? (record(web.behavior_intelligence).chain as unknown[]).map(record) : []
  const rows: Array<[string, string]> = []
  if (typeof web.status === 'string') rows.push(['Page inspection', web.status === 'ANALYZED' ? 'Static page content inspected' : `Could not inspect page (${humanize(web.status)})`])
  if (typeof fetch.status_code === 'number') rows.push(['HTTP response', `${fetch.status_code}${typeof fetch.content_type === 'string' ? ` · ${fetch.content_type.split(';')[0]}` : ''}`])
  if (typeof fetch.redirect_count === 'number') rows.push(['Redirects', `${fetch.redirect_count} followed${redirects.length ? `; ${redirects.map(item => String(item.status_code ?? 'redirect')).join(', ')}` : ''}`])
  for (const [key, label] of [['password_input_count', 'Password fields'], ['form_count', 'Forms'], ['external_form_count', 'Forms posting to another site'], ['external_iframe_count', 'External frames'], ['script_count', 'Scripts']] as const) {
    if (typeof features[key] === 'number') rows.push([label, diagnosticNumber(features[key])])
  }
  if (typeof features.link_count === 'number') rows.push(['Page links found', diagnosticNumber(features.link_count)])
  if (indicators.length) rows.push(['Page warnings', indicators.slice(0, 4).map(item => String(item.reason ?? humanize(String(item.code ?? 'Signal')))).join(' ')])
  if (typeof crawl.status === 'string') {
    rows.push(['Same-site page crawl', crawl.status === 'ANALYZED' ? 'Completed' : crawl.status === 'PARTIAL' ? 'Partial' : humanize(crawl.status)])
    rows.push(['Pages inspected', `${pages.filter(page => page.status === 'ANALYZED').length} of ${pages.length} visited or attempted`])
    if (childPages.length) {
      const childPasswords = childPages.filter(page => Number(page.password_input_count) > 0).length
      const mentionedBrands = [...new Set(childPages.flatMap(page => Array.isArray(page.brand_claims) ? page.brand_claims.map(claim => String(record(claim).brand_id ?? '')) : []).filter(Boolean))]
      rows.push(['Additional page findings', `${childPasswords} page(s) had password fields · ${mentionedBrands.length} registered brand name(s) mentioned in page text`])
    }
    if (typeof crawl.robots_status === 'string') rows.push(['robots.txt', ({ AVAILABLE: 'Rules found and followed', NOT_PRESENT: 'Not found; crawl continued', UNAVAILABLE: 'Could not verify rules; child crawl stopped', NOT_REQUESTED: 'No child pages selected' } as Record<string, string>)[crawl.robots_status] ?? humanize(crawl.robots_status)])
    if (typeof crawl.stop_reason === 'string' && crawl.stop_reason) rows.push(['Crawl stopped', humanize(crawl.stop_reason)])
    if (typeof crawl.request_count === 'number' && typeof crawl.response_bytes === 'number') {
      const limits = record(crawl.limits)
      rows.push(['Crawl budget used', `${crawl.request_count} of ${diagnosticNumber(limits.max_requests)} requests · ${(crawl.response_bytes / 1024).toFixed(0)} of ${(Number(limits.max_total_bytes ?? 0) / 1024).toFixed(0)} KB · ${diagnosticNumber(crawl.elapsed_ms)} ms`])
      rows.push(['Crawl scope', `Same hostname · up to ${diagnosticNumber(limits.max_pages)} pages · depth ${diagnosticNumber(limits.max_depth)}`])
    }
  }
  return rows
}

function diagnosticRows(data: ResultData, assessment: RiskAssessment) {
  const domain = record(data.domain_intelligence)
  const registration = record(domain.registration)
  const tls = record(domain.tls)
  const domainFeatures = record(domain.domain_features)
  const advanced = record(data.advanced_analysis)
  const features = record(advanced.features)
  const reputation = record(domain.reputation)
  const registrationStatus = String(registration.status ?? '').toUpperCase()
  const tlsStatus = String(tls.status ?? '').toUpperCase()
  const blacklist = domainFeatures.is_blacklisted ?? reputation.is_blacklisted
  const blacklistStatus = String(reputation.status ?? reputation.reputation_status ?? '').toUpperCase()
  const blacklistText = blacklist === 1 || blacklist === true ? 'Match observed' : blacklist === 0 || blacklist === false
    ? (blacklistStatus && !['AVAILABLE', 'ANALYZED', 'SUCCESS', 'CLEAN'].includes(blacklistStatus) ? 'No match; provider unconfirmed' : 'No match observed')
    : 'Unknown'
  const model = record(data.ml_result)
  const modelAvailable = model.status === 'OK' && model.model_validated === true && ['sigmoid', 'isotonic'].includes(String(model.calibration_method))
  const probability = model.probability
  const modelScore = modelAvailable && typeof probability === 'number'
    ? `${(probability * 100).toFixed(1)}% phishing estimate`
    : 'Unavailable — not calibrated'
  const age = registrationStatus === 'AVAILABLE' ? registration.domain_age_days : null
  const ageText = typeof age === 'number' && Number.isFinite(age)
    ? `${diagnosticNumber(age, ' days')} (${diagnosticNumber(registration.domain_age_years ?? age / 365.2425, ' years')})`
    : registrationStatus === 'AVAILABLE' ? 'Lookup completed; creation date not disclosed' : 'WHOIS/RDAP lookup unavailable'
  return [
    ['Analyzed target', String(data.analysis_target ?? data.url ?? 'Unknown')],
    ['ML phishing estimate', modelScore],
    ['Observed risk score', diagnosticNumber(assessment.risk_score, ' / 100')],
    ['Registered domain', String(record(domain.domain_components).registrable_domain ?? record(domain.domain_components).normalized_registrable_domain ?? 'Unknown')],
    ['Domain age (WHOIS/RDAP)', ageText],
    ['Domain created', registration.creation_date ? new Date(String(registration.creation_date)).toLocaleDateString() : 'Not disclosed'],
    ['Registrar', typeof registration.registrar === 'string' ? (/^\d+$/.test(registration.registrar) ? `Registrar ID ${registration.registrar}` : registration.registrar) : 'Not disclosed'],
    ['SSL certificate', tlsStatus === 'VALID' || tls.certificate_valid === true ? 'Valid' : tlsStatus === 'INVALID' || tls.certificate_valid === false ? 'Invalid' : 'Unknown'],
    ['Blacklist', blacklistText],
    ['Suspicious token count', diagnosticNumber(features.suspicious_keyword_count)],
    ['IP address in host', diagnosticValue(features.has_ip, 'Yes', 'No')],
    ['HTTPS usage', diagnosticValue(features.is_https, 'Yes', 'No')],
    ['URL entropy', diagnosticNumber(features.url_entropy)],
  ] as const
}

function simpleVerdict(verdict: string) {
  return ({ LEGITIMATE: 'Likely safe', LOW_RISK: 'Likely safe', LIKELY_SAFE: 'Likely safe', UNKNOWN: 'Needs review', SUSPICIOUS: 'Avoid for now', PHISHING: 'Unsafe — likely phishing', MALICIOUS: 'Unsafe — threat signs found' } as Record<string, string>)[verdict] ?? 'Needs review'
}

function isModelProbabilityAvailable(data: ResultData | null) {
  const model = record(data?.ml_result)
  return model.status === 'OK' && model.model_validated === true && ['sigmoid', 'isotonic'].includes(String(model.calibration_method)) && typeof model.probability === 'number' && Number.isFinite(model.probability)
}

function emailRows(result: ResultData) {
  const email = record(result.email_analysis ?? result)
  const message = record(email.message)
  const header = record(message.headers)
  const auth = record(email.authentication)
  const body = record(email.body_analysis)
  const features = record(body.features)
  const fromDomain = String(header.from_domain ?? 'Unknown')
  const attachments = Array.isArray(email.attachments) ? email.attachments.map(record) : []
  const urls = Array.isArray(email.urls) ? email.urls.map(record) : []
  const urlInventory = Array.isArray(email.url_inventory) ? email.url_inventory.map(record) : []
  const uncheckedLinks = urlInventory.filter(item => item.status !== 'ANALYZED').length
  const risk = record(email.risk)
  const alignment = record(header.relationships)
  return [
    ['Claimed sender domain', fromDomain],
    ['Reply-to relationship', String(alignment['reply-to'] ?? 'Unknown').replaceAll('_', ' ').toLowerCase()],
    ['Email authentication', `SPF ${String(record(auth.spf).result ?? 'Unavailable').toLowerCase()}, DKIM ${String(record(auth.dkim).result ?? 'Unavailable').toLowerCase()}, DMARC ${String(record(auth.dmarc).result ?? 'Unavailable').toLowerCase()}`],
    ['Language cues found', Object.entries(features).filter(([, value]) => value === true).map(([name]) => humanize(name)).join(', ') || 'None observed'],
    ['Links found', `${urlInventory.length || urls.length} · ${urls.length} analyzed`],
    ['Attachments found', `${attachments.length}`],
    ...attachments.slice(0, 8).map((item, index) => [`Attachment ${index + 1}`, `${String(item.filename ?? 'Unnamed file')} · ${String(item.magic ?? item.mime ?? 'type unknown')} · ${Array.isArray(item.indicators) && item.indicators.length ? item.indicators.map(String).join(', ').replaceAll('_', ' ').toLowerCase() : 'no listed file warning'}`] as const),
    ...urls.slice(0, 8).map((item, index) => {
      const scan = record(item.analysis)
      const verdict = String(record(scan.assessment).verdict ?? 'UNKNOWN').toUpperCase()
      const advice = ['PHISHING', 'MALICIOUS'].includes(verdict) ? 'Avoid — threat indicators found'
        : verdict === 'SUSPICIOUS' ? 'Avoid for now — suspicious signs found'
        : ['LEGITIMATE', 'LOW_RISK'].includes(verdict) ? 'No strong warning found — still verify the sender'
        : 'Not verified — do not click until you confirm it'
      return [`Link ${index + 1}`, `${String(scan.analysis_target ?? item.url ?? item.display ?? 'Destination details unavailable')} · ${advice}`] as const
    }),
    ...urlInventory.filter(item => item.status !== 'ANALYZED').slice(0, 8).map((item, index) => [
      `Unchecked link ${index + 1}`,
      `${String(item.url ?? 'Destination withheld')} · ${item.status === 'BLOCKED' ? 'blocked before contact' : 'not fully scanned; do not click until verified'}`,
    ] as const),
    ...(uncheckedLinks > 0 ? [['Links not fully checked', `${uncheckedLinks} · use caution and verify these manually`] as const] : []),
    ['Recommended next step', ['PHISHING', 'MALICIOUS', 'SUSPICIOUS'].includes(String(risk.verdict ?? '').toUpperCase())
      ? 'Do not click or forward as a normal message. Report it with your mail app’s phishing/report option.'
      : 'Sender authentication is not verified from an uploaded message. Confirm with the sender using a known contact method before acting.'],
    ['Authentication limitation', 'Uploaded email headers can be forged; SPF checks need trusted delivery data.'],
  ] as const
}

function mediaRows(result: ResultData) {
  const metadata = record(result.metadata)
  const quality = record(result.quality)
  const ocr = record(result.ocr)
  const qr = record(result.qr)
  const synthid = record(result.synthid)
  const investigation = record(result.investigation)
  const checks = record(investigation.checks)
  const c2paCheck = record(checks.c2pa)
  const aiCheck = record(checks.ai_image_detector)
  const manipulationCheck = record(checks.manipulation_forensics)
  const visualCheck = record(checks.reverse_image_search)
  const safetyCheck = record(checks.content_safety)
  const c2paClaims = Array.isArray(c2paCheck.claims) ? c2paCheck.claims.map(record) : []
  const generatedClaims = c2paClaims.filter(claim => /trainedalgorithmicmedia|compositewithtrainedalgorithmicmedia/i.test(String(claim.digital_source_type ?? '')))
  const declaredTools = [...new Set(c2paClaims.map(claim => String(claim.software_agent ?? '')).filter(Boolean))]
  const originSummary = generatedClaims.length
    ? c2paCheck.trusted === true
      ? `A trusted signed credential declares AI-generated content${declaredTools.length ? ` · tool: ${declaredTools.join(', ')}` : ''}. This is provenance evidence, not proof of the depicted scene.`
      : `A credential declares AI-generated content${declaredTools.length ? ` · declared tool: ${declaredTools.join(', ')}` : ''}, but its signer is not trusted here. Treat the source as unverified.`
    : declaredTools.length
      ? `Credential lists ${declaredTools.join(', ')}; it does not state that the image was AI-generated.`
      : 'Unknown — no trusted generator information was found. SecureSight has no validated general-purpose AI-image detector.'
  const items = Array.isArray(qr.items) ? qr.items.map(record) : []
  const links = Array.isArray(result.linked_analysis) ? result.linked_analysis.map(record) : []
  const extractedText = String(ocr.text ?? '').trim()
  return [
    ['Image type', String(record(result.artifact).mime ?? metadata.mime ?? 'Unknown')],
    ['Image dimensions', typeof metadata.width === 'number' && typeof metadata.height === 'number' ? `${metadata.width} × ${metadata.height} pixels` : 'Unknown'],
    ['Image quality', String(quality.status ?? 'Unknown').replaceAll('_', ' ').toLowerCase()],
    ['Text found in image', extractedText ? extractedText.slice(0, 300) : String(ocr.status ?? 'No readable text found').replaceAll('_', ' ').toLowerCase()],
    ['QR codes found', `${items.length}`],
    ...items.slice(0, 5).map((item, index) => [`QR destination ${index + 1}`, String(item.display ?? 'Text payload redacted')] as const),
    ['Content Credentials (C2PA)', c2paCheck.status === 'detected' ? 'Valid provenance record found' : c2paCheck.status === 'not_detected' ? 'No supported credential found' : c2paCheck.status === 'inconclusive' ? 'Credential found; validation needs review' : c2paCheck.status === 'failed' ? 'Validation failed' : 'Validation unavailable'],
    ...(c2paClaims.length ? [['Declared content history', c2paClaims.slice(0, 4).map(claim => String(claim.action ?? 'Action') + (claim.digital_source_type ? ` · ${String(claim.digital_source_type).split('/').pop()}` : '')).join('; ')] as const] : []),
    ['Image origin / generator', originSummary],
    ['AI training data', 'Not disclosed by image pixels, a watermark or the available credentials. SecureSight cannot identify which dataset trained a generator.'],
    ['Photo metadata', metadata.exif_present === true ? 'EXIF data present (does not prove who made the image)' : metadata.exif_present === false ? 'No EXIF data found' : 'Unknown'],
    ['SynthID watermark', String(synthid.status ?? 'NOT_CHECKED').toUpperCase() === 'NOT_CHECKED'
      ? 'Not checked by SecureSight. Use the official Google detector below.'
      : String(synthid.status).replaceAll('_', ' ').toLowerCase()],
    ['AI-origin check', aiCheck.status === 'not_available' ? 'Not available — no validated AI-image model is configured' : humanize(String(aiCheck.status ?? 'not checked'))],
    ['Editing clues', manipulationCheck.status === 'partial' ? 'Measured file clues only; no manipulation verdict' : humanize(String(manipulationCheck.status ?? 'not checked'))],
    ['Public visual matches', visualCheck.status === 'not_available' ? 'Unavailable — no approved search provider; image not sent' : humanize(String(visualCheck.status ?? 'not checked'))],
    ['Content-safety check', safetyCheck.status === 'not_available' ? 'Unavailable — no content-safety model is configured' : humanize(String(safetyCheck.status ?? 'not checked'))],
    ['What to do', 'Check the image with SynthID for a supported watermark and confirm its source. No watermark or clean metadata alone proves an image is authentic.'],
    ['Links analyzed', `${links.length} of ${Number(record(result.correlations).url_candidates ?? 0)} found`],
  ] as const
}

const modes: { id: Mode; label: string; icon: typeof Globe2; helper: string }[] = [
  { id: 'url', label: 'Website', icon: Globe2, helper: 'Check a link and its available destination evidence.' },
  { id: 'email', label: 'Email', icon: FileText, helper: 'Inspect an .eml message, or extract links and text from a PDF, DOCX or XML email export.' },
  { id: 'media', label: 'Image', icon: FileImage, helper: 'Investigate image provenance, watermark and available editing clues.' },
]

function getAssessment(data: ResultData): RiskAssessment {
  const value = (data.assessment ?? data.risk ?? (data.media as ResultData | undefined)?.assessment ?? data) as RiskAssessment
  return value && typeof value === 'object' ? value : {}
}

function mediaOrigin(result: ResultData) {
  const checks = record(record(result.investigation).checks)
  const c2pa = record(checks.c2pa)
  const synthid = record(result.synthid)
  const claims = Array.isArray(c2pa.claims) ? c2pa.claims.map(record) : []
  const generated = claims.filter(claim => /trainedalgorithmicmedia|compositewithtrainedalgorithmicmedia/i.test(String(claim.digital_source_type ?? '')))
  const capture = claims.some(claim => /digitalcapture|positivefilm|negativefilm/i.test(String(claim.digital_source_type ?? '')))
  const tools = [...new Set(claims.map(claim => String(claim.software_agent ?? '')).filter(Boolean))]
  const watermark = String(synthid.status ?? '').toUpperCase()

  if (watermark === 'DETECTED' || watermark === 'LIKELY') return {
    title: watermark === 'DETECTED' ? 'AI watermark detected' : 'AI watermark likely present', state: 'detected',
    description: 'A supported AI watermark was reported. This identifies watermark evidence, not the image’s training data or whether the depicted event is true.',
  }
  if (generated.length && c2pa.trusted === true) return {
    title: 'AI-generated credential found', state: 'detected',
    description: `A trusted signed credential declares AI-generated content${tools.length ? ` · tool listed: ${tools.join(', ')}` : ''}. The credential does not establish which training data was used or prove the depicted scene is true.`,
  }
  if (generated.length) return {
    title: 'AI-generation claim · unverified', state: 'unverified',
    description: `The image contains a credential claiming AI-generated content${tools.length ? ` · tool listed: ${tools.join(', ')}` : ''}, but its signer is not trusted here. Treat the origin as unverified.`,
  }
  if (capture && c2pa.trusted === true) return {
    title: 'Camera-capture credential found', state: 'detected',
    description: 'A trusted signed credential declares camera capture. This is provenance evidence; it cannot prove the scene is genuine or unedited in every respect.',
  }
  if (watermark === 'INCONCLUSIVE' || watermark === 'ERROR') return {
    title: 'Origin unclear', state: 'unknown',
    description: 'The watermark check did not reach a clear result, and SecureSight has no validated general AI-image detector. The image may be AI-generated or camera-made.',
  }
  return {
    title: 'Origin unclear', state: 'unknown',
    description: 'No trusted origin credential or supported watermark result was found. SecureSight has no validated general AI-image detector, so this image could be AI-generated or camera-made.',
  }
}

function mediaMetricRows(result: ResultData, origin: ReturnType<typeof mediaOrigin>) {
  const investigation = record(result.investigation)
  const checks = record(investigation.checks)
  const coverage = record(investigation.coverage)
  const c2pa = record(checks.c2pa)
  const detector = record(checks.ai_image_detector)
  const synthid = record(result.synthid)
  const completion = Array.isArray(coverage.completed) ? coverage.completed.length : 0
  const requested = Array.isArray(coverage.requested) ? coverage.requested.length : 0
  const partial = Array.isArray(coverage.partial) ? coverage.partial.length : 0
  const unavailable = Array.isArray(coverage.unavailable) ? coverage.unavailable.length : 0
  const credentialStatus = c2pa.status === 'detected' ? 'Trusted credential'
    : c2pa.status === 'inconclusive' ? 'Unverified credential'
      : c2pa.status === 'not_detected' ? 'Not found'
        : c2pa.status === 'failed' ? 'Validation failed' : 'Unavailable'
  const detectorStatus = detector.status === 'not_available' ? 'Not configured'
    : detector.status ? humanize(String(detector.status)) : 'Not checked'
  const watermarkStatus = String(synthid.status ?? 'NOT_CHECKED').toUpperCase() === 'NOT_CHECKED'
    ? 'Not checked here' : humanize(String(synthid.status))
  return [
    ['Image origin', origin.title, origin.state === 'unknown' ? 'No verified source evidence' : origin.state === 'unverified' ? 'Claim needs verification' : 'Supported evidence found'],
    ['Content credentials', credentialStatus, c2pa.status === 'inconclusive' ? 'Signer is not trusted' : 'C2PA provenance'],
    ['AI detector', detectorStatus, 'No generic image classifier is configured'],
    ['AI watermark', watermarkStatus, 'SynthID must be checked separately'],
    ['Evidence checks', requested ? `${completion} of ${requested} complete` : 'Status unavailable', `${partial} partial · ${unavailable} unavailable`],
  ] as const
}

function csrfToken() { return document.querySelector<HTMLMetaElement>('meta[name="csrf-token"]')?.content ?? '' }
function headers(extra: HeadersInit = {}) { const csrf = csrfToken(); return { ...(csrf ? { 'X-CSRF-Token': csrf } : {}), ...extra } }
async function decode(response: Response): Promise<ResultData> {
  const data = await response.json().catch(() => ({})) as ResultData
  if (!response.ok) {
    const error = (data.error as { message?: string; code?: string } | undefined)
    throw new Error(error?.message || error?.code || `Request failed (${response.status})`)
  }
  return data
}

async function analyzeEmail(file: File) {
  const form = new FormData(); form.append('file', file)
  const start = await decode(await fetch('/api/v1/email/analyze', { method: 'POST', headers: headers(), body: form }))
  const id = String(start.job_id ?? ''), token = String(start.token ?? '')
  if (!id || !token) throw new Error('The email analysis job could not be started.')
  for (let attempt = 0; attempt < 100; attempt += 1) {
    await new Promise(resolve => window.setTimeout(resolve, 1000))
    const job = await decode(await fetch(`/api/v1/email/jobs/${encodeURIComponent(id)}`, { headers: { Authorization: `Bearer ${token}` }, cache: 'no-store' }))
    if (job.state === 'FAILED' || job.state === 'EXPIRED') throw new Error('Email analysis did not complete. Please try again.')
    if (job.result && typeof job.result === 'object') return job.result as ResultData
  }
  throw new Error('Email analysis is taking longer than expected. Please retry.')
}

function VerdictIcon({ verdict }: { verdict: string }) {
  if (verdict === 'PHISHING' || verdict === 'MALICIOUS') return <ShieldAlert aria-hidden="true" />
  if (verdict === 'SUSPICIOUS') return <AlertTriangle aria-hidden="true" />
  if (verdict === 'LEGITIMATE' || verdict === 'LOW_RISK') return <ShieldCheck aria-hidden="true" />
  return <Shield aria-hidden="true" />
}

function App() {
  const [mode, setMode] = useState<Mode>('url')
  const [url, setUrl] = useState('')
  const [email, setEmail] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [result, setResult] = useState<ResultData | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [dragging, setDragging] = useState(false)
  const inputId = useId()
  const current = modes.find(item => item.id === mode)!
  const assessment = result ? getAssessment(result) : null
  const warnings = normalizeWarnings(assessment?.warnings ?? result?.errors)
  const coverageWarnings = warnings.filter(warning => /^(URL|DNS|TLS|REGISTRATION|REPUTATION|HTML|CONTENT|ML|BRAND|HISTORICAL|CRAWL|REDIRECT)_(UNAVAILABLE|PARTIAL|TIMEOUT|ERROR)$/.test(warning.code ?? ''))
  const resultWarnings = warnings.filter(warning => !coverageWarnings.includes(warning))
  const unavailableSignals = (assessment?.missing_signals ?? []).map(formatMissingSignal).filter((value, index, values) => values.indexOf(value) === index)
  const verdict = String(assessment?.verdict ?? (result?.verdict as string | undefined) ?? 'UNKNOWN').toUpperCase()
  const flagged = ['PHISHING', 'MALICIOUS', 'SUSPICIOUS'].includes(verdict)
  const model = record(result?.ml_result)
  const stages = record(record(assessment).audit).stages
  const essentialChecksAvailable = ['AVAILABLE', 'NOT_APPLICABLE'].includes(String(record(stages).url)) &&
    ['AVAILABLE', 'NOT_APPLICABLE'].includes(String(record(stages).dns)) &&
    ['AVAILABLE', 'NOT_APPLICABLE'].includes(String(record(stages).html)) &&
    ['AVAILABLE', 'NOT_APPLICABLE'].includes(String(record(stages).tls))
  const likelySafe = verdict === 'UNKNOWN' && essentialChecksAvailable && isModelProbabilityAvailable(result) &&
    typeof model.probability === 'number' && model.probability <= 0.15 &&
    typeof assessment?.risk_score === 'number' && assessment.risk_score <= 15 &&
    !(assessment?.top_signals ?? []).some(signal => (signal.contribution ?? 0) >= 10)
  const reassuring = ['LEGITIMATE', 'LOW_RISK'].includes(verdict) || likelySafe
  const partial = String(result?.analysis_status ?? assessment?.status ?? '').toUpperCase() === 'PARTIAL'
  const kind = String(result?.type ?? mode).toLowerCase()
  const diagnostics = result && assessment && kind === 'url' ? diagnosticRows(result, assessment) : []
  const websiteRows = result && kind === 'url' ? websiteEvidence(result) : []
  const humanRows = result ? kind === 'email' ? emailRows(result) : kind === 'media' ? mediaRows(result) : [] : []
  const imageOrigin = result && kind === 'media' ? mediaOrigin(result) : null
  const shownVerdict = likelySafe ? 'LIKELY_SAFE' : verdict

  function reset(next: Mode) { setMode(next); setFile(null); setResult(null); setError('') }
  function acceptFile(candidate?: File) {
    if (!candidate) return
    if (mode === 'email' && !/\.(eml|pdf|docx|xml)$/i.test(candidate.name)) { setError('Choose an .eml, .pdf, .docx or .xml email file.'); return }
    if (mode === 'media' && !candidate.type.startsWith('image/')) { setError('Choose a PNG, JPEG or WebP image.'); return }
    if (candidate.size > (mode === 'media' ? 5 : 2) * 1024 * 1024) { setError(mode === 'media' ? 'Image must be 5 MB or smaller.' : 'Email must be 2 MB or smaller.'); return }
    setFile(candidate); setError(''); setResult(null)
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError(''); setResult(null)
    if (mode === 'url' && !url.trim()) { setError('Enter a website address to scan.'); return }
    if (mode === 'email' && !file && !email.trim()) { setError('Choose an email file or paste an email message.'); return }
    if (mode === 'media' && !file) { setError('Choose an image to scan.'); return }
    setBusy(true)
    try {
      let data: ResultData
      if (mode === 'url') data = await decode(await fetch('/api/v1/scan', { method: 'POST', headers: headers({ 'Content-Type': 'application/json' }), body: JSON.stringify({ url: url.trim() }) }))
      else if (mode === 'email') {
        if (!file && new Blob([email]).size > 2 * 1024 * 1024) throw new Error('Email must be 2 MB or smaller.')
        const message = file ?? new File([email], 'pasted-message.eml', { type: 'message/rfc822' })
        data = await analyzeEmail(message)
      } else {
        const form = new FormData(); form.append('file', file!)
        data = await decode(await fetch('/api/v1/media/analyze', { method: 'POST', headers: headers(), body: form }))
      }
      setResult(data)
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'The scan could not be completed.') }
    finally { setBusy(false) }
  }

  return <div className="app-shell">
    <header className="topbar">
      <a className="brand" href="/" aria-label="SecureSight home"><span className="brand-mark"><Shield size={18} strokeWidth={2.2} /></span><span>SecureSight</span></a>
      <nav aria-label="Main navigation"><a href="/guides/url-analysis">Guides</a><a href="/privacy">Privacy</a></nav>
    </header>
    <main>
      <BlurFade delay={0.05} inView>
        <section className="intro" aria-labelledby="page-title">
          <div className="eyebrow"><span className="live-dot" /> PRIVATE THREAT ANALYSIS</div>
          <h1 id="page-title">Check before<br className="mobile-break" /> you trust.</h1>
          <p>Review a link, email or image for threat indicators. Results show available evidence and where analysis is incomplete.</p>
        </section>
      </BlurFade>

      <section className="workspace" aria-label="Threat scanner">
        <div className="tabs" role="tablist" aria-label="Choose what to scan">
          {modes.map(item => <button key={item.id} type="button" role="tab" aria-selected={mode === item.id} className={`tab ${mode === item.id ? 'selected' : ''}`} onClick={() => reset(item.id)}><item.icon size={17} strokeWidth={1.8} />{item.label}</button>)}
        </div>
        <form className="scan-form" onSubmit={submit}>
          <p className="form-helper">{current.helper}</p>
          {mode === 'url' && <label className="field-label" htmlFor={inputId}>Website address</label>}
          {mode === 'url' && <div className="url-input-wrap"><Globe2 size={18} aria-hidden="true" /><input id={inputId} type="url" inputMode="url" autoComplete="url" placeholder="https://example.com" value={url} onChange={event => setUrl(event.target.value)} /></div>}
          {mode === 'email' && <>
            <label className="field-label" htmlFor={inputId}>Paste the original message</label>
            <textarea id={inputId} className="email-input" value={email} onChange={event => { setEmail(event.target.value); setFile(null); setResult(null) }} placeholder={'From: name@example.com\nSubject: Please review…'} maxLength={2 * 1024 * 1024} disabled={Boolean(file)} />
            <div className="or-divider"><span>or upload an email file</span></div>
            <FilePicker mode={mode} file={file} inputId={`${inputId}-file`} acceptFile={acceptFile} onClear={() => setFile(null)} dragging={dragging} setDragging={setDragging} />
            {file && !file.name.toLowerCase().endsWith('.eml') && <p className="diagnostic-note">We’ll scan extracted text and links. Document exports do not contain trusted delivery headers, so SPF, DKIM and DMARC cannot be checked.</p>}
          </>}
          {mode === 'media' && <>
            <FilePicker mode={mode} file={file} inputId={`${inputId}-file`} acceptFile={acceptFile} onClear={() => setFile(null)} dragging={dragging} setDragging={setDragging} />
            <aside className="synthid-handoff" aria-label="Optional SynthID watermark check">
              <div><strong>Optional: check for a SynthID watermark</strong><p>SynthID looks for a watermark used by Google AI and participating partners. It is not a universal deepfake detector.</p></div>
              <a href="https://synthid.com/" target="_blank" rel="noopener noreferrer">Open Google’s SynthID Detector <ArrowUpRight size={15} /></a>
              <small>SecureSight will not send your image to Google. The portal asks you to upload it yourself and shows its terms and privacy notice before checking.</small>
            </aside>
          </>}
          {error && <p className="error-message" role="alert"><AlertTriangle size={16} />{error}</p>}
          <div className="form-footer"><span className="privacy-note"><ShieldCheck size={15} /> Submitted content is processed for this scan.</span><Button type="submit" className="scan-button" disabled={busy}>{busy ? <><LoaderCircle className="spin" size={17} />Checking…</> : <>Analyze <ArrowUpRight size={16} /></>}</Button></div>
        </form>
        {busy && <div className="progress-note" role="status"><Activity size={16} className="pulse" /> Checking available evidence. This may take a few seconds.</div>}
      </section>

      {result && assessment && <section className={`result-card ${flagged ? 'result-risk' : reassuring ? 'result-clear' : ''}`} aria-live="polite" aria-labelledby="result-title">
        {imageOrigin ? <div className="result-main"><div className={`verdict-icon media-origin-icon ${imageOrigin.state}`}><FileImage aria-hidden="true" /></div><div className="result-copy"><span className="result-label">IMAGE ORIGIN · {imageOrigin.state === 'unknown' ? 'NOT DETERMINED' : imageOrigin.state === 'unverified' ? 'UNVERIFIED EVIDENCE' : 'EVIDENCE FOUND'}</span><h2 id="result-title">{imageOrigin.title}</h2><p>{imageOrigin.description}</p><p className="media-threat-status"><strong>Separate threat review:</strong> {simpleVerdict(verdict)}{partial ? ' · some checks unavailable' : ''}</p></div></div> : <div className="result-main"><div className="verdict-icon"><VerdictIcon verdict={likelySafe ? 'LOW_RISK' : verdict} /></div><div className="result-copy"><span className="result-label">{likelySafe ? 'LIKELY SAFE · SOME CHECKS MISSING' : partial ? 'CHECKS INCOMPLETE' : `RESULT · ${humanize(assessment.severity ?? 'UNKNOWN')}`}</span><h2 id="result-title">{simpleVerdict(shownVerdict)}</h2><p>{likelySafe ? 'The URL model and available checks found a low phishing signal. Reputation or other checks were incomplete, so use care with passwords and payments.' : verdict === 'UNKNOWN' || partial ? 'We could not verify every important check. Review the details before opening or trusting it.' : flagged ? 'Avoid opening it or sharing passwords and codes. Verify through the organization’s official website or phone number.' : 'Available checks found no strong threat signs. This is a screening result, not a guarantee.'}</p></div></div>}
        {humanRows.length > 0 && <section className="plain-summary" aria-label={`${humanize(kind)} scan summary`}><h3>What we checked</h3><dl>{humanRows.map(([label, value]) => <div className="plain-row" key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl></section>}
        {kind === 'media' && imageOrigin ? <div className="result-metrics media-result-metrics" aria-label="Image origin checks">
          {mediaMetricRows(result, imageOrigin).map(([label, value, note]) => <div className="result-metric" key={label}><span className="metric-label">{label}</span><strong className="metric-value">{value}</strong><span className="metric-note">{note}</span></div>)}
        </div> : <div className="result-metrics" aria-label="Scan metrics">
          <div className="result-metric"><span className="metric-label">Observed risk</span><strong className="metric-value">{displayMetric(assessment.risk_score, ' / 100')}</strong><span className="metric-note">Heuristic score</span></div>
          <div className="result-metric"><span className="metric-label">ML phishing estimate</span><strong className="metric-value">{isModelProbabilityAvailable(result) ? `${(Number(model.probability) * 100).toFixed(1)}%` : 'Unavailable'}</strong><span className="metric-note">Calibrated URL model</span></div>
          <div className="result-metric"><span className="metric-label">Evidence coverage</span><strong className="metric-value">{displayMetric(assessment.evidence_coverage, '%')}</strong><span className="metric-note">Scorable signals present</span></div>
          <div className="result-metric"><span className="metric-label">Analysis complete</span><strong className="metric-value">{displayMetric(assessment.analysis_completeness, '%')}</strong><span className="metric-note">Applicable checks available</span></div>
          <div className="result-metric"><span className="metric-label">Evidence quality</span><strong className="metric-value">{displayMetric(assessment.confidence, ' / 100')}</strong><span className="metric-note">Provisional, uncalibrated</span></div>
        </div>}
        {kind === 'url' && <Collapsible className="diagnostic-disclosure">
          <CollapsibleTrigger className="disclosure-trigger">Technical details <ChevronDown size={16} /></CollapsibleTrigger>
          <CollapsibleContent className="diagnostic-body">
            <dl className="diagnostic-grid">{diagnostics.map(([label, value]) => <div className="diagnostic-item" key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
    {!assessment.confidence_calibrated && <p className="diagnostic-note">The overall evidence-quality index is not a correctness probability. A model estimate, when shown, is limited to URL patterns and its historical validation data.</p>}
            {partial && <p className="diagnostic-note">This scan is incomplete. Missing intelligence prevents a clean verdict even when no strong threat signal was observed.</p>}
          </CollapsibleContent>
        </Collapsible>}
        <Collapsible className="evidence-disclosure">
          <CollapsibleTrigger className="disclosure-trigger">Evidence and limits <ChevronDown size={16} /></CollapsibleTrigger>
          <CollapsibleContent className="evidence-body">
            {kind === 'media' && <section className="evidence-inspection" aria-label="SynthID detector information"><h3>Google SynthID watermark check</h3><p>SynthID searches for a specific AI watermark. A positive result is evidence of that watermark; no result does not prove that the image is human-made. SecureSight has not submitted this file to Google.</p><a href="https://synthid.com/" target="_blank" rel="noopener noreferrer">Open the official detector <ArrowUpRight size={14} /></a></section>}
            {websiteRows.length > 0 && <section className="evidence-inspection" aria-label="Website inspection evidence"><h3>What the website scan observed</h3><dl>{websiteRows.map(([label, value]) => <div className="plain-row" key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl><p className="diagnostic-note">Pages are fetched as static HTML on the same hostname. Links with query strings, forms, scripts, and external resources are not executed or submitted.</p></section>}
            {(assessment.top_signals?.length ?? 0) > 0 ? <ul className="signal-list">{assessment.top_signals!.slice(0, 5).map((signal, index) => <li key={`${signal.signal_id ?? signal.label}-${index}`}><span><Check size={14} />{signal.label ?? signal.signal_id ?? 'Observed signal'}</span>{signal.contribution != null && <small>{Math.round(signal.contribution)} pts</small>}</li>)}</ul> : <p>{kind === 'media' ? 'Threat review is separate from image origin. No image-safety verdict was established by the available checks.' : verdict === 'UNKNOWN' ? 'No risk verdict could be established from the available checks.' : 'No high-confidence signals were available for this result.'}</p>}
            {coverageWarnings.length > 0 && <p className="result-warning"><AlertTriangle size={14} />Coverage is limited: {coverageWarnings.map(warning => {
              const match = (warning.code ?? '').match(/^(.*)_(UNAVAILABLE|PARTIAL|TIMEOUT|ERROR)$/)
              return match ? `${humanize(match[1].toLowerCase())} ${match[2].toLowerCase()}` : 'some checks incomplete'
            }).filter((value, index, values) => values.indexOf(value) === index).join('; ')}.</p>}
            {resultWarnings.map((warning, index) => <p className="result-warning" key={`${warning.code ?? warning.message ?? 'warning'}-${index}`}><AlertTriangle size={14} />{warning.message ?? humanize(warning.code ?? 'Some checks were unavailable')}</p>)}
            {unavailableSignals.length > 0 && <p><strong>Unavailable evidence:</strong> {unavailableSignals.slice(0, 5).join(', ')}{unavailableSignals.length > 5 ? `, and ${unavailableSignals.length - 5} more` : ''}.</p>}
            <p className="limit-note">{kind === 'media' ? 'Unknown origin does not mean camera-made. A generated image is not automatically unsafe; review the source and context.' : 'A low score does not guarantee safety. Verify sensitive requests through a trusted source.'}</p>
          </CollapsibleContent>
        </Collapsible>
      </section>}
      <p className="disclaimer">{kind === 'media' ? 'Image origin is reported only when supported evidence is available. Unknown means the origin could not be determined.' : 'For research and decision support. No automated scan can guarantee a file, message or website is safe.'}</p>
    </main>
    <footer className="site-footer"><span>© 2026 SecureSight</span><span>Evidence first. Uncertainty visible.</span><a href="/security">Security and responsible use</a></footer>
  </div>
}

function FilePicker({ mode, file, inputId, acceptFile, onClear, dragging, setDragging }: { mode: Mode; file: File | null; inputId: string; acceptFile: (file?: File) => void; onClear: () => void; dragging: boolean; setDragging: (value: boolean) => void }) {
  const image = mode === 'media'
  return <div className={`file-picker ${dragging ? 'dragging' : ''} ${file ? 'has-file' : ''}`} onDragOver={event => { event.preventDefault(); setDragging(true) }} onDragLeave={() => setDragging(false)} onDrop={event => { event.preventDefault(); setDragging(false); acceptFile(event.dataTransfer.files[0]) }}>
    {file ? <><span className="file-icon">{image ? <FileImage size={20} /> : <FileText size={20} />}</span><span className="file-name"><strong>{file.name}</strong><small>{(file.size / 1024 / 1024).toFixed(2)} MB</small></span><button type="button" className="clear-file" onClick={onClear} aria-label="Remove selected file"><X size={16} /></button></> : <><span className="upload-icon"><Upload size={19} /></span><span className="upload-copy"><strong>{image ? 'Drop an image here or browse' : 'Choose an email file'}</strong><small>{image ? 'PNG, JPEG or WebP · up to 5 MB' : 'EML, PDF, DOCX or XML · up to 2 MB'}</small></span><label className="browse-button" htmlFor={inputId}>Browse</label><input id={inputId} type="file" accept={image ? 'image/png,image/jpeg,image/webp' : '.eml,.pdf,.docx,.xml,message/rfc822,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/xml,text/xml'} onChange={event => acceptFile(event.target.files?.[0])} /></>}
  </div>
}

export default App
