/* Phase 12 API presentation. All untrusted strings use textContent; no verdict logic. */

'use strict';

(() => {

  /** @typedef {{investigation_id:string,entity_type:string,summary:Object,evidence:Array,panels:Object,graph:Object,timeline:Array}} Investigation */

  const $ = id => document.getElementById(id);

  const csrf = document.querySelector('meta[name="csrf-token"]').content;

  const canWrite = ['ADMIN', 'ANALYST', 'API_CLIENT'].includes(document.body.dataset.role);

  let offset = 0, total = 0, selected = new Set(), current = null, evidenceOffset = 0, graphOffset = 0, caseOffset = 0;

  const node = (tag, text, cls) => { const e = document.createElement(tag); if (text !== undefined) e.textContent = String(text); if (cls) e.className = cls; return e; };

  const show = value => value === null || value === undefined ? 'Unavailable' : typeof value === 'object' ? JSON.stringify(value) : String(value);

  const badge = value => { const e = node('span', show(value), 'badge'); e.dataset.value = value; return e; };

  const status = (message, error = false) => { $('status').textContent = message; $('status').className = error ? 'error' : 'muted'; };

  async function api(path, options = {}) {

    const r = await fetch(path, {credentials: 'same-origin', ...options, headers: {'X-CSRF-Token': csrf, ...(options.body ? {'Content-Type': 'application/json'} : {}), ...options.headers}});

    if (r.status === 401) { location.assign('/dashboard/login'); throw new Error('Session expired.'); }

    if (!r.ok) throw new Error(`Request failed (${r.status}). ${r.status === 409 ? 'Case changed; refresh before editing.' : 'Access or input may be restricted.'}`);

    return r.json();

  }

  const safely = fn => async event => { if (event) event.preventDefault(); try { await fn(event); } catch (e) { status(e.message, true); } };

  function metric(parent, label, value) { const d = node('div', undefined, 'metric'); d.append(node('span', label), node('strong', show(value))); parent.append(d); }

  function readable(value, parent, level = 0) {

    if (value === null || typeof value !== 'object' || level > 5) { parent.append(node('pre', typeof value === 'object' ? JSON.stringify(value, null, 2) : show(value))); return; }

    if (Array.isArray(value)) { if (value.length > 50) { parent.append(node('p', `Showing first 50 of ${value.length} observations; export contains the stored bounded record.`, 'muted')); } if (!value.length) parent.append(node('p', 'No observations available.', 'muted')); for (const [i, item] of value.slice(0,50).entries()) { const d = node('details'); d.append(node('summary', `${i + 1} · ${show(item?.event || item?.type || item?.name || item?.id || 'Observation')}`)); readable(item, d, level + 1); parent.append(d); } return; }

    const table = node('table'); const body = node('tbody');

    for (const [key, val] of Object.entries(value)) { const row = node('tr'); row.append(node('th', key.replaceAll('_', ' '))); const cell = node('td'); if (val !== null && typeof val === 'object') { const d = node('details'); d.append(node('summary', Array.isArray(val) ? `${val.length} entries` : 'Inspect details')); readable(val, d, level + 1); cell.append(d); } else cell.textContent = show(val); row.append(cell); body.append(row); }

    table.append(body); const wrap = node('div', undefined, 'table-wrap'); wrap.append(table); parent.append(wrap);

  }

  function chart(parent, title, data) { const c = node('div'); c.append(node('h3', title)); const maximum = Math.max(1, ...Object.values(data)); if (!Object.keys(data).length) c.append(node('p', 'No stored observations.', 'muted')); for (const [label, value] of Object.entries(data)) { const row = node('div', undefined, 'bar-row'); row.append(node('span', label)); const track = node('div', undefined, 'bar-track'); track.setAttribute('aria-hidden', 'true'); const bar = node('div', undefined, 'bar'); bar.style.width = `${100 * value / maximum}%`; track.append(bar); row.append(track, node('span', value)); c.append(row); } parent.append(c); }

  async function overview() {

    const d = await api('/api/v1/dashboard/summary'); $('metrics').replaceChildren();

    for (const [label, key] of [['Stored scans','total_scans'],['Scans today','scans_today'],['Phishing','phishing_detections'],['Suspicious','suspicious_detections'],['Legitimate candidates','legitimate_candidates'],['Unknown / partial','unknown_or_partial'],['Analysis failures','analysis_failures'],['Active local jobs','active_processing_jobs'],['High-risk domains','high_risk_domains'],['High-risk emails','high_risk_email_investigations'],['Media investigations','media_investigations'],['Deepfake detections','deepfake_detections']]) metric($('metrics'), label, d[key]);

    $('charts').replaceChildren(); chart($('charts'), 'Verdict distribution', d.verdict_distribution); chart($('charts'), 'Backend severity', d.severity_distribution); chart($('charts'), 'Observed risk index', d.risk_distribution); chart($('charts'), 'Confidence index', d.confidence_distribution);

    const volume = Object.fromEntries(d.daily_volume.slice(-30).map(x => [x.date, x.scans])); chart($('charts'), 'Investigation volume (UTC)', volume); chart($('charts'), 'Observed brands', d.top_observed_brands); chart($('charts'), 'Observed TLDs · descriptive only', d.top_observed_tlds); chart($('charts'), 'BEC context observations', d.bec_patterns); chart($('charts'), 'Authentication errors by method', d.authentication_failure_trends); chart($('charts'), 'Redirect observations', d.redirect_patterns);

    $('analytics-limits').replaceChildren(); readable({phishing_rate: d.phishing_rate, suspicious_rate: d.suspicious_rate, telemetry_coverage_records: d.telemetry_coverage_records, telemetry_missing_records: d.telemetry_missing_records, model_unavailable_investigations: d.model_unavailable_investigations, limited_history_investigations: d.limited_history_investigations, missing_evidence_observations: d.missing_evidence_observations, model_versions: d.model_versions, feature_versions: d.feature_versions, unavailable: d.unavailable, alerts: d.alerts, limitations: d.limitations}, $('analytics-limits'));

  }

  function listQuery() { const p = new URLSearchParams({limit: 25, offset}); for (const [id, key] of [['query','q'],['verdict','verdict'],['entity','entity_type'],['severity','severity'],['analysis-status','status'],['confidence-filter','confidence_min'],['brand-filter','brand'],['domain-filter','domain'],['source-filter','source'],['type-filter','evidence_type']]) if ($(id).value) p.set(key, $(id).value); if ($('since').value) p.set('since', `${$('since').value}T00:00:00Z`); if ($('until').value) p.set('until', `${$('until').value}T23:59:59Z`); return p; }

  async function list() {

    const d = await api('/api/v1/investigations?' + listQuery()); total = d.total; $('investigation-list').replaceChildren();

    for (const r of d.items) { const tr = node('tr'); const checkCell = node('td'); const check = node('input'); check.type = 'checkbox'; check.checked = selected.has(r.id); check.setAttribute('aria-label', 'Select investigation ' + r.id); check.addEventListener('change', () => { if (check.checked) selected.add(r.id); else selected.delete(r.id); }); checkCell.append(check); tr.append(checkCell);

      const subjectCell = node('td'); const link = node('a', r.subject); link.href = '/dashboard/investigations/' + encodeURIComponent(r.id); link.addEventListener('click', safely(async () => { await open(r.id); history.pushState({}, '', link.href); })); subjectCell.append(link, node('small', r.id)); tr.append(subjectCell, node('td', r.entity_type)); const verdictCell = node('td'); verdictCell.append(badge(r.verdict)); tr.append(verdictCell, node('td', show(r.risk)), node('td', show(r.confidence)), node('td', r.status), node('td', r.created_at.replace('T',' ').slice(0,19) + ' UTC')); $('investigation-list').append(tr);

    }

    if (!d.items.length) { const tr = node('tr'); const td = node('td', 'No matching investigations. Sign in and run a scan to record real results.'); td.colSpan = 8; tr.append(td); $('investigation-list').append(tr); }

    $('page-count').textContent = `${Math.min(offset + 1, total)}–${Math.min(offset + 25, total)} of ${total}`; $('previous').disabled = offset === 0; $('next').disabled = offset + 25 >= total;

  }

  async function open(id) {

    status('Loading investigation…'); current = await api('/api/v1/investigations/' + encodeURIComponent(id)); evidenceOffset = graphOffset = 0;

    $('workspace').hidden = false; $('workspace-type').textContent = current.entity_type + ' / ' + current.investigation_id; $('workspace-subject').textContent = current.subject;

    $('risk-summary').replaceChildren(); for (const [label, key] of [['Verdict','verdict'],['Risk score','risk_score'],['Severity','severity'],['Confidence index','confidence'],['Completeness','analysis_completeness'],['Evidence coverage','evidence_coverage'],['ML probability','ml_probability'],['Analysis status','status']]) metric($('risk-summary'), label, current.summary[key]);

    $('confidence-kind').textContent = `${show(current.summary.assessment_scope)} · ${current.summary.confidence_kind} · calibrated: ${current.summary.confidence_calibrated}. Indexes and model probabilities are separate; none guarantees safety.`;

    $('export-actions').hidden = !canWrite; $('export-json').href = `/api/v1/investigations/${id}/export`; $('export-html').href = `/api/v1/investigations/${id}/export?format=html`;

    const content = $('workspace-content'); content.replaceChildren();

    const reasons = node('details'); reasons.open = true; reasons.append(node('summary', 'Why SecureSight reached this assessment · Phase 7'));

    if (!current.explanations.length) reasons.append(node('p', 'Backend explanation unavailable.', 'muted'));

    for (const reason of current.explanations) { const block = node('div', undefined, 'note'); block.append(node('strong', reason.title || reason.category || 'Backend reason'), node('p', reason.description || 'Description unavailable.')); for (const ref of reason.evidence_references) { const a = node('a', 'Evidence ' + ref); a.href = '#evidence-' + encodeURIComponent(ref); a.addEventListener('click', safely(async () => { await evidenceReference(ref); })); block.append(a, node('span', ' ')); } block.append(node('small', `${reason.source || 'Backend'} · ${reason.evidence_type || 'Unspecified type'} · confidence ${show(reason.confidence)} · ${reason.reference_status}`)); reasons.append(block); } content.append(reasons);

    for (const [label, value] of [['Missing intelligence & warnings', {coverage: current.coverage, warnings: current.warnings, limitations: current.limitations}],['Contradictory evidence', current.contradictions]]) { const d = node('details'); d.append(node('summary', label)); readable(value, d); content.append(d); }

    const timeline = node('details'); timeline.append(node('summary', 'Cross-modal timeline')); const events = node('ol', undefined, 'timeline'); for (const event of current.timeline) { const li = node('li'); li.append(node('strong', event.timestamp), node('p', event.event), node('small', `${show(event.source)} · confidence ${show(event.confidence)} · ${event.provenance}${event.claimed ? ' · UNTRUSTED HEADER CLAIM' : ''}`)); events.append(li); } timeline.append(events); content.append(timeline);

    for (const [label, values] of Object.entries(current.panels)) { const d = node('details'); d.append(node('summary', label)); if (label === 'C2PA') d.append(node('p', 'C2PA absence does not prove fabrication. Presence does not prove truthfulness.', 'muted')); if (label === 'Media models') d.append(node('p', 'Synthetic probability is model-derived evidence, not proof of maliciousness.', 'muted')); readable(values, d); content.append(d); }

    $('feedback-form').hidden = !canWrite; $('feedback-current').replaceChildren(); readable(current.analyst_assessment, $('feedback-current')); $('feedback-label').value = current.analyst_assessment.feedback; $('feedback-status').value = current.analyst_assessment.status;

    $('graph-type').replaceChildren(node('option', 'All entity types')); $('graph-type').firstChild.value = ''; for (const type of new Set(current.graph.nodes.map(n => n.type || 'UNKNOWN'))) { const o = node('option', type); o.value = type; $('graph-type').append(o); }

    await Promise.all([evidence(), graph()]); status('Investigation loaded. Missing information remains unavailable.'); $('workspace').scrollIntoView({block: 'start'});

  }

  async function evidenceReference(ref) { const row = current.evidence.findIndex(e => e.evidence_id === ref); if (row < 0) return; for (const id of ['evidence-category','evidence-source','evidence-phase','evidence-severity','evidence-confidence','evidence-since']) $(id).value = ''; $('evidence-type').value = ''; evidenceOffset = Math.floor(row / 50) * 50; await evidence(); document.getElementById('evidence-' + encodeURIComponent(ref))?.scrollIntoView({block:'center'}); }

  async function evidence() {

    if (!current) return; const p = new URLSearchParams({limit: 50, offset: evidenceOffset}); for (const [id,key] of [['evidence-category','category'],['evidence-type','evidence_type'],['evidence-source','source'],['evidence-phase','phase'],['evidence-severity','severity'],['evidence-confidence','confidence_min']]) if ($(id).value) p.set(key,$(id).value); if ($('evidence-since').value) p.set('since',new Date($('evidence-since').value).toISOString());

    const d = await api(`/api/v1/investigations/${current.investigation_id}/evidence?${p}`); $('evidence-list').replaceChildren();

    for (const e of d.items) { const row = node('tr'); row.id = 'evidence-' + encodeURIComponent(e.evidence_id); const id = node('td', e.indicator); id.append(node('small',e.evidence_id),node('small',e.category)); row.append(id); const type = node('td'); type.append(badge(e.evidence_type)); row.append(type,node('td',show(e.value)),node('td',`${show(e.severity)} / ${show(e.confidence)}`),node('td',`${e.source} / ${show(e.source_version)} / ${show(e.phase)}`),node('td',`${show(e.timestamp)} / ${show(e.artifact_hash)}`)); $('evidence-list').append(row); }

    if (!d.items.length) { const row = node('tr'); const td = node('td','No evidence matches the current filter.'); td.colSpan = 6; row.append(td); $('evidence-list').append(row); } $('evidence-more').disabled = evidenceOffset + 50 >= d.total; $('evidence-previous').disabled = evidenceOffset === 0;

  }

  async function graph() {

    if (!current) return; const p = new URLSearchParams({limit: 50, offset: graphOffset}); if ($('graph-type').value) p.set('type',$('graph-type').value);

    const d = await api(`/api/v1/investigations/${current.investigation_id}/graph?${p}`); const host = $('graph-view'); host.replaceChildren();

    if (!d.nodes.length) { host.append(node('p','No backend graph nodes available.')); $('graph-more').disabled = true; return; }

    const ns = 'http://www.w3.org/2000/svg'; const svg = document.createElementNS(ns,'svg'); const height = Math.ceil(d.nodes.length / 4) * 110 + 30; svg.setAttribute('viewBox',`0 0 1000 ${height}`); svg.setAttribute('role','group'); svg.setAttribute('aria-label','Interactive evidence graph');

    const positions = new Map(d.nodes.map((n,i) => [n.id,{x:25 + i % 4 * 245,y:20 + Math.floor(i / 4) * 110}]));

    for (const e of d.edges) { const a=positions.get(e.source),b=positions.get(e.target); const line=document.createElementNS(ns,'line'); for (const [key,val] of Object.entries({x1:a.x+100,y1:a.y+30,x2:b.x+100,y2:b.y+30})) line.setAttribute(key,val); svg.append(line); }

    for (const n of d.nodes) { const pos=positions.get(n.id); const group=document.createElementNS(ns,'g'); group.setAttribute('tabindex','0'); group.setAttribute('role','button'); group.setAttribute('aria-label',`${n.type}: ${n.id}`); const rect=document.createElementNS(ns,'rect'); for (const [k,v] of Object.entries({x:pos.x,y:pos.y,width:210,height:64,rx:8})) rect.setAttribute(k,v); group.append(rect);

      for (const [i,label] of [n.type || 'UNKNOWN',String(n.value || n.hostname || n.id).slice(0,27)].entries()) { const t=document.createElementNS(ns,'text'); t.setAttribute('x',pos.x+10); t.setAttribute('y',pos.y+23+i*21); t.textContent=label; group.append(t); }

      const inspect=() => { $('graph-selection').replaceChildren(); readable({node:n,relationships:current.graph.edges.filter(e => e.source===n.id || e.target===n.id)},$('graph-selection')); }; group.addEventListener('click',inspect); group.addEventListener('keydown',e => { if (e.key==='Enter' || e.key===' ') {e.preventDefault();inspect();} }); svg.append(group);

    } host.append(svg,node('p',`${d.total_nodes} matching nodes · ${d.omitted_edges} edges outside this page.`,'muted')); $('graph-more').disabled = graphOffset+50>=d.total_nodes; $('graph-previous').disabled = graphOffset === 0;

  }

  async function cases() {

    const d=await api(`/api/v1/cases?limit=10&offset=${caseOffset}`); $('case-list').replaceChildren(); $('case-form').hidden=!canWrite;

    for (const c of d.items) { const card=node('article',undefined,'case-card'); card.append(node('h3',c.title),badge(c.status),node('p',`Case ${c.id} · revision ${c.revision} · reviewed ${c.reviewed} · tags ${c.tags.join(', ')}`)); for (const id of c.investigation_ids) { const a=node('a','Investigation '+id); a.href='/dashboard/investigations/'+id; a.addEventListener('click',safely(() => open(id))); card.append(a,node('br')); } readable({evidence_references:c.evidence_references},card);

      for (const note of c.notes) { const n=node('div',undefined,'note'); n.append(node('strong',`ANALYST NOTE · ${note.author} · ${note.timestamp}`),node('p',note.text)); card.append(n); }

      if (canWrite) { const form=node('form',undefined,'filters'); const label=node('label','Case status'); const state=node('select'); for (const s of ['NEW','IN_REVIEW','ESCALATED','CONFIRMED','CLOSED','FALSE_POSITIVE']) { const o=node('option',s); o.value=s; state.append(o); } state.value=c.status; label.append(state); const noteLabel=node('label','Add analyst note'); const input=node('textarea'); input.maxLength=4000; input.setAttribute('aria-label','Analyst note for '+c.title); noteLabel.append(input); const submit=node('button','Save case'); submit.type='submit'; form.append(label,noteLabel,submit); form.addEventListener('submit',safely(async () => { let revision=c.revision; if (state.value!==c.status) { const updated=await api(`/api/v1/cases/${c.id}`,{method:'POST',body:JSON.stringify({status:state.value,revision})}); revision=updated.revision; } if (input.value.trim()) await api(`/api/v1/cases/${c.id}/notes`,{method:'POST',body:JSON.stringify({text:input.value,revision})}); await cases(); status('Case saved. Analyst notes do not change system evidence.'); })); card.append(form);

        const refLabel=node('label','Optional evidence ID from the current investigation'); const refInput=node('input'); refInput.maxLength=256; refLabel.append(refInput); card.append(refLabel); const attach=node('button','Add current investigation and evidence reference', 'secondary'); attach.addEventListener('click',safely(async () => {if (!current) throw new Error('Open an investigation first.'); const ids=[...new Set([...c.investigation_ids,current.investigation_id])]; const refs=[...c.evidence_references]; if (refInput.value.trim()) refs.push({investigation_id:current.investigation_id,evidence_id:refInput.value.trim()}); await api(`/api/v1/cases/${c.id}`,{method:'POST',body:JSON.stringify({revision:c.revision,investigation_ids:ids,evidence_references:refs})}); await cases();})); card.append(attach);

        const review=node('button',c.reviewed ? 'Mark unreviewed' : 'Mark reviewed','secondary'); review.addEventListener('click',safely(async()=>{await api(`/api/v1/cases/${c.id}`,{method:'POST',body:JSON.stringify({revision:c.revision,reviewed:!c.reviewed})}); await cases();}));card.append(review);

      } $('case-list').append(card);

    } if (!d.items.length) $('case-list').append(node('p','No cases on this page.')); $('cases-more').disabled=d.items.length<10; $('cases-previous').disabled=caseOffset===0;

  }

  $('refresh').addEventListener('click',safely(async()=>{await Promise.all([overview(),list(),cases()]); status('Workspace refreshed.');}));

  $('search-form').addEventListener('submit',safely(async()=>{offset=0;await list();status('Search complete. Matching uses normalized exact entities.');}));

  $('previous').addEventListener('click',safely(async()=>{offset=Math.max(0,offset-25);await list();})); $('next').addEventListener('click',safely(async()=>{offset+=25;await list();}));

  $('evidence-previous').addEventListener('click',safely(async()=>{evidenceOffset=Math.max(0,evidenceOffset-50);await evidence();}));
  $('graph-previous').addEventListener('click',safely(async()=>{graphOffset=Math.max(0,graphOffset-50);await graph();}));
  $('cases-previous').addEventListener('click',safely(async()=>{caseOffset=Math.max(0,caseOffset-10);await cases();}));
  $('evidence-form').addEventListener('submit',safely(async()=>{evidenceOffset=0;await evidence();})); $('evidence-more').addEventListener('click',safely(async()=>{evidenceOffset+=50;await evidence();}));

  $('graph-type').addEventListener('change',safely(async()=>{graphOffset=0;await graph();})); $('graph-more').addEventListener('click',safely(async()=>{graphOffset+=50;await graph();}));

  $('case-form').addEventListener('submit',safely(async()=>{await api('/api/v1/cases',{method:'POST',body:JSON.stringify({title:$('case-title').value,investigation_ids:$('case-include').checked&&current?[current.investigation_id]:[]})});$('case-title').value='';caseOffset=0;await cases();status('Case created.');}));

  $('cases-more').addEventListener('click',safely(async()=>{caseOffset+=10;await cases();}));

  $('feedback-form').addEventListener('submit',safely(async()=>{if (!current) return;await api(`/api/v1/investigations/${current.investigation_id}/feedback`,{method:'POST',body:JSON.stringify({feedback:$('feedback-label').value,status:$('feedback-status').value,tags:$('feedback-tags').value.split(',').map(t=>t.trim()).filter(Boolean)})});await open(current.investigation_id);status('Unvalidated analyst feedback saved. Technical verdict unchanged.');}));

  $('compare').addEventListener('click',safely(async()=>{if (selected.size!==2) throw new Error('Select exactly two investigations to compare.'); const ids=[...selected];const d=await api(`/api/v1/investigations/compare?a=${ids[0]}&b=${ids[1]}`);const host=$('comparison');host.replaceChildren(node('h2','Investigation comparison'));host.hidden=false;if(d.warning)host.append(node('p',d.warning,'muted'));for(const inv of d.investigations){const detail=node('details');detail.open=true;detail.append(node('summary',`${inv.entity_type} · ${inv.subject}`));readable({summary:inv.summary,panels:inv.panels,timeline:inv.timeline,evidence_count:inv.evidence.length},detail);host.append(detail);}host.scrollIntoView();}));

  safely(async()=>{const session=await api('/api/v1/dashboard/session');for(const s of session.policy.severity){const o=node('option',s.name);o.value=s.name;$('severity').append(o);}await Promise.all([overview(),list(),cases()]);status('Authorized workspace loaded.');if(document.body.dataset.investigation)await open(document.body.dataset.investigation);})();

})();

