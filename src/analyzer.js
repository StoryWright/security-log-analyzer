import { isIP } from 'node:net';

export function canonicalIP(value) {
  if (typeof value !== 'string' || !isIP(value)) throw new Error('Invalid source IP');
  if (isIP(value) === 6) return new URL(`http://[${value}]/`).hostname.slice(1, -1);
  return value;
}

export function timestamp(value) {
  if (typeof value !== 'string') throw new Error('Timestamp must be a string');
  const m = value.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,3})?(Z|[+-]\d{2}:\d{2})$/);
  if (!m) throw new Error('Use an ISO timestamp with a timezone');
  const [yr, mo, day, hr, min, sec] = m.slice(1, 7).map(Number);
  const leap = yr % 4 === 0 && (yr % 100 !== 0 || yr % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (yr < 1 || mo < 1 || mo > 12 || day < 1 || day > days[mo - 1] || hr > 23 || min > 59 || sec > 59)
    throw new Error('Invalid calendar timestamp');
  if (m[7] !== 'Z' && (Number(m[7].slice(1, 3)) > 23 || Number(m[7].slice(4)) > 59))
    throw new Error('Invalid timezone offset');
  const result = Date.parse(value);
  if (!Number.isFinite(result)) throw new Error('Invalid timestamp');
  return result;
}

function normalize(obj, line) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new Error('Expected an event object');
  const types = { LOGIN_FAILED: 'failure', LOGIN_SUCCESS: 'success', failure: 'failure', success: 'success' };
  const type = Object.hasOwn(types, obj.event) ? types[obj.event] : null;
  if (!type) throw new Error('Unsupported authentication event');
  if (obj.user !== undefined && (typeof obj.user !== 'string' || obj.user.length > 256)) throw new Error('Invalid username');
  return {
    id: `line-${line}`, line, time: timestamp(obj.timestamp), type,
    ip: canonicalIP(obj.src_ip ?? obj.ip), user: obj.user ?? null,
    host: typeof obj.host === 'string' ? obj.host.slice(0, 256) : null
  };
}

export function parseLine(raw, line = 1, { format = 'auto', year } = {}) {
  const value = raw.trim();
  if (!value || value.startsWith('#')) return null;
  if (value.length > 65536) throw new Error('Line exceeds 64 KiB limit');
  if (!['auto', 'jsonl', 'legacy', 'ssh'].includes(format)) throw new Error('Unsupported input format');
  if (format === 'jsonl' || (format === 'auto' && value.startsWith('{'))) return normalize(JSON.parse(value), line);
  const legacy = value.match(/^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(LOGIN_FAILED|LOGIN_SUCCESS)\s+(\S+)(?:\s+(\S+))?$/);
  if (legacy && ['auto', 'legacy'].includes(format))
    return normalize({ timestamp: `${legacy[1]}T${legacy[2]}Z`, event: legacy[3], ip: legacy[4], user: legacy[5] }, line);
  if (format === 'legacy') throw new Error('Invalid legacy log line');
  let time, message;
  const iso = value.match(/^(\S+)\s+(\S+)\s+sshd(?:\[\d+\])?:\s+(.+)$/);
  if (iso && /^\d{4}-/.test(iso[1])) { time = iso[1]; message = iso[3]; }
  else {
    const classic = value.match(/^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+\S+\s+sshd(?:\[\d+\])?:\s+(.+)$/);
    if (!classic) throw new Error('Unrecognized log format');
    if (!Number.isInteger(year) || year < 1970 || year > 9999) throw new Error('Yearless syslog requires --year');
    const month = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'].indexOf(classic[1]) + 1;
    if (!month) throw new Error('Invalid month');
    time = `${year}-${String(month).padStart(2,'0')}-${classic[2].padStart(2,'0')}T${classic[3]}Z`;
    message = classic[4];
  }
  const auth = message.match(/^(Failed password|Accepted password|Accepted publickey) for (?:invalid user )?(\S+) from (\S+) port \d+(?:\s|$)/);
  if (!auth) throw new Error('Unsupported SSH event');
  return normalize({ timestamp: time, event: auth[1].startsWith('Failed') ? 'failure' : 'success', user: auth[2], ip: auth[3] }, line);
}

export function parseText(text, options = {}) {
  if (!['auto','jsonl','legacy','ssh'].includes(options.format ?? 'auto')) throw new Error('Unsupported input format');
  const events = [], errors = [];
  let errorCount = 0, ignoredLines = 0;
  const maxEvents = options.maxEvents ?? 100000;
  if (!Number.isInteger(maxEvents) || maxEvents < 1) throw new Error('maxEvents must be a positive integer');
  for (const [i, raw] of text.split(/\r?\n/).entries()) {
    let event;
    try { event = parseLine(raw, i + 1, options); }
    catch (error) { errorCount++; if (errors.length < 20) errors.push({ line: i + 1, reason: error instanceof SyntaxError ? 'Invalid JSON syntax' : error.message }); continue; }
    if (event) {
      if (events.length >= maxEvents) throw new Error(`Input exceeds ${maxEvents} valid events`);
      events.push(event);
    } else ignoredLines++;
  }
  return { events, errors, errorCount, ignoredLines };
}

export function analyze(events, { threshold = 5, windowSeconds = 300, successWindowSeconds = 600, allowlist = [] } = {}) {
  if (!Number.isInteger(threshold) || threshold < 2) throw new Error('threshold must be an integer >= 2');
  if (!Number.isInteger(windowSeconds) || windowSeconds < 1) throw new Error('windowSeconds must be positive');
  if (!Number.isInteger(successWindowSeconds) || successWindowSeconds < 1) throw new Error('successWindowSeconds must be positive');
  const allowed = new Set(allowlist.map(canonicalIP));
  const sorted = [...events].sort((a,b) => a.time - b.time || a.line - b.line);
  const states = new Map(), alerts = [];
  let failures = 0, successes = 0;
  for (const event of sorted) {
    let state = states.get(event.ip);
    if (!state) { state = { ip: event.ip, failures: 0, successes: 0, queue: [], head: 0, active: false, lastBurst: null, successReported: false }; states.set(event.ip, state); }
    while (state.head < state.queue.length && state.queue[state.head].time < event.time - windowSeconds * 1000) state.head++;
    if (state.queue.length - state.head < threshold) state.active = false;
    if (event.type === 'failure') {
      failures++; state.failures++; state.queue.push(event);
      const count = state.queue.length - state.head;
      if (count >= threshold && !state.active && !allowed.has(event.ip)) {
        const evidence = state.queue.slice(state.head);
        const alert = {
          id: `AUTH-${alerts.length + 1}`, rule: 'failure_burst', severity: 'medium', ip: event.ip,
          timestamp: new Date(event.time).toISOString(), windowStart: new Date(evidence[0].time).toISOString(),
          attempts: count, users: [...new Set(evidence.map(e => e.user).filter(Boolean))],
          evidenceLines: evidence.map(e => e.line),
          explanation: `${count} failed authentications within ${windowSeconds} seconds; investigate before treating as malicious.`
        };
        alerts.push(alert); state.lastBurst = alert; state.successReported = false; state.active = true;
      }
    } else {
      successes++; state.successes++;
      if (state.lastBurst && !state.successReported && !allowed.has(event.ip) && event.time - Date.parse(state.lastBurst.timestamp) <= successWindowSeconds * 1000) {
        alerts.push({ id: `AUTH-${alerts.length + 1}`, rule: 'success_after_burst', severity: 'high', ip: event.ip,
          timestamp: new Date(event.time).toISOString(), user: event.user, relatedAlert: state.lastBurst.id,
          evidenceLines: [event.line], explanation: 'Successful authentication from the same source IP after a failure burst. This does not prove account compromise; shared IPs and legitimate retries are possible.' });
        state.successReported = true;
      }
    }
    // Keep the active window rather than retaining every historical failure per IP.
    if (state.head > 1024 && state.head * 2 > state.queue.length) { state.queue = state.queue.slice(state.head); state.head = 0; }
  }
  return {
    schemaVersion: 1, settings: { threshold, windowSeconds, successWindowSeconds, allowlist: [...allowed] },
    summary: { totalEvents: events.length, failures, successes, sourceIPs: states.size, alerts: alerts.length },
    sources: [...states.values()].map(s => ({ ip: s.ip, failures: s.failures, successes: s.successes, allowlisted: allowed.has(s.ip) })), alerts
  };
}

export const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const csvCell = value => {
  let s = String(value ?? '');
  if (/^[=+@\-\t\r]/.test(s)) s = "'" + s;
  return '"' + s.replaceAll('"','""') + '"';
};
export function toCSV(report) {
  const keys = ['id','rule','severity','ip','timestamp','attempts','explanation'];
  return [keys.join(','), ...report.alerts.map(a => keys.map(k => csvCell(a[k])).join(','))].join('\n') + '\n';
}
export function toHTML(report, label = 'Authentication analysis report') {
  const h = escapeHTML;
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${h(label)}</title><style>body{font:16px/1.6 system-ui;max-width:1000px;margin:40px auto;padding:0 24px;color:#18232f}h1{line-height:1.2}table{border-collapse:collapse;width:100%}td,th{padding:10px;text-align:left;border-bottom:1px solid #ddd}code{background:#eee}article{padding:18px 0;border-bottom:1px solid #ddd}.note{color:#52616d}</style><h1>${h(label)}</h1><p class="note">${h(report.provenance ?? 'Input provenance has not been independently established.')}</p><p>${report.summary.totalEvents} events / ${report.summary.failures} failures / ${report.summary.successes} successes / ${report.alerts.length} alerts</p><p>Rule: ${report.settings.threshold} failures in ${report.settings.windowSeconds} seconds. Source-IP correlation identifies review candidates, not confirmed attackers.</p>${report.alerts.map(a=>`<article><h2>${h(a.id)} · ${h(a.rule)}</h2><p><strong>${h(a.severity)}</strong> | ${h(a.ip)} | ${h(a.timestamp)}</p><p>${h(a.explanation)}</p><p>Evidence lines: ${h(a.evidenceLines.join(', '))}</p></article>`).join('') || '<p>No configured rule matched. This is not a guarantee that the input is safe.</p>'}<h2>Source totals</h2><table><tr><th>IP</th><th>Failures</th><th>Successes</th></tr>${report.sources.map(s=>`<tr><td>${h(s.ip)}</td><td>${s.failures}</td><td>${s.successes}</td></tr>`).join('')}</table><p>Invalid lines: ${report.parseErrors?.errorCount ?? 0}. Analyze only logs you are authorized to access; redact private identifiers before publishing reports.</p></html>`;
}
