#!/usr/bin/env node
/**
 * Minimal Collector/API bridge for QoSD telemetry.
 *
 * Receives Fluent Bit HTTP output, stores recent events in-memory,
 * maintains persona statistics, and exposes policy endpoints that
 * edge nodes (qosd) can poll for persona-specific actions.
 */

const http = require('http');
const url = require('url');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { spawn } = require('child_process');

const PORT = parseInt(process.env.PORT || '4000', 10);
const MAX_RECENT_EVENTS = parseInt(process.env.MAX_EVENTS || '200', 10);

let policies = {};
let personaStats = {};
let recentEvents = [];
let hostSnapshot = {};
const APP_PROTO_PERSONA = {
  netflix: 'streaming',
  youtube: 'streaming',
  'youtube-video': 'streaming',
  'amazon-video': 'streaming',
  disney_plus: 'streaming',
  hulu: 'streaming',
  quic: 'streaming',
  zoom: 'voip',
  webex: 'voip',
  teams: 'voip',
  skype: 'voip',
  discord: 'voip',
  slack: 'work',
  office365: 'work',
  ms_office365: 'work',
  vpn: 'work',
  steam: 'gaming',
  'blizzard-battle.net': 'gaming',
  riot: 'gaming',
  psn: 'gaming',
  xboxlive: 'gaming'
};

function isPrivateIP(ip) {
  if (!ip)
    return false;
  if (ip.indexOf(':') !== -1) {
    return ip.toLowerCase().startsWith('fc') ||
      ip.toLowerCase().startsWith('fd') ||
      ip.toLowerCase().startsWith('fe80');
  }
  return ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip) ||
    ip.startsWith('169.254.');
}

function loadPolicies() {
  const policyPath = path.join(__dirname, 'policies.json');
  try {
    const raw = fs.readFileSync(policyPath, 'utf-8');
    const data = JSON.parse(raw);
    if (data && typeof data === 'object')
      policies = data;
  } catch (err) {
    policies = {
      streaming: { policy_action: 'boost', priority: 'medium', dscp: 'AF41' },
      gaming: { policy_action: 'boost', priority: 'high', dscp: 'CS6' },
      voip: { policy_action: 'boost', priority: 'high', dscp: 'EF' },
      work: { policy_action: 'boost', priority: 'medium', dscp: 'AF21' },
      bulk: { policy_action: 'throttle', priority: 'low', dscp: 'CS1' },
      iot: { policy_action: 'observe', priority: 'low', dscp: 'CS2' },
      latency: { policy_action: 'boost', priority: 'medium', dscp: 'CS5' },
      other: { policy_action: 'observe', priority: 'normal', dscp: 'CS0' }
    };
  }
}

function jsonResponse(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
}

function textResponse(res, status, text) {
  res.writeHead(status, { 'Content-Type': 'text/plain' });
  res.end(text);
}

function updateStats(event) {
  if (!event || typeof event !== 'object')
    return;

  const persona = (event.persona || event.category || 'other').toLowerCase();
  const latency = Number(event.latency_ms || 0);

  if (!personaStats[persona]) {
    personaStats[persona] = {
      persona,
      count: 0,
      avgLatency: 0,
      lastSeen: null
    };
  }

  const stat = personaStats[persona];
  stat.count += 1;
  if (latency > 0) {
    stat.avgLatency = stat.avgLatency === 0
      ? latency
      : ((stat.avgLatency * (stat.count - 1)) + latency) / stat.count;
  }
  stat.lastSeen = new Date().toISOString();
}

function ensureHost(ip, mac) {
  if (!ip || !isPrivateIP(ip))
    return null;
  const key = ip;
  if (!hostSnapshot[key]) {
    hostSnapshot[key] = {
      ip,
      mac: mac || '',
      persona: 'unknown',
      priority: 'normal',
      policy_action: 'observe',
      dscp: 'CS0',
      confidence: 0,
      hostname: '',
      router: '',
      rx_bps: 0,
      tx_bps: 0,
      sni: '',
      alpn: '',
      ja3: '',
      last_seen: null,
      source: 'heuristic',
      last_pushed_persona: '',
      last_pushed_confidence: 0,
      last_push_at: 0
    };
  }
  const host = hostSnapshot[key];
  if (mac && !host.mac)
    host.mac = mac;
  return host;
}

function updateHostSnapshot(event) {
  if (!event || typeof event !== 'object')
    return;

  if (event.event === 'qosd_live') {
    const host = ensureHost(event.ip, event.mac);
    if (!host)
      return;
    host.persona = event.persona || host.persona;
    host.priority = event.priority || host.priority;
    host.policy_action = event.policy_action || host.policy_action;
    host.dscp = event.dscp || host.dscp;
    host.confidence = event.confidence || host.confidence;
    host.hostname = event.hostname || host.hostname;
    host.router = event.router || host.router;
    host.rx_bps = Number(event.rx_bps || host.rx_bps);
    host.tx_bps = Number(event.tx_bps || host.tx_bps);
    host.sni = event.sni || host.sni;
    host.alpn = event.alpn || host.alpn;
    host.ja3 = event.ja3 || host.ja3;
    if (event.last_seen)
      host.last_seen = event.last_seen;
    else if (event.timestamp)
      host.last_seen = Math.floor(Date.parse(event.timestamp) / 1000) || host.last_seen;
    else
      host.last_seen = Math.floor(Date.now() / 1000);
    host.source = 'qosd_live';
    host.confidence = Number(event.confidence || host.confidence || 0);
    maybePushOverride(host);
  } else if (event.event === 'qosd_policy_trace') {
    const host = ensureHost(event.src, null) || ensureHost(event.dst, null);
    if (!host)
      return;
    if (event.persona)
      host.persona = event.persona;
    if (event.priority)
      host.priority = event.priority;
    if (event.policy_action)
      host.policy_action = event.policy_action;
    if (event.dscp)
      host.dscp = event.dscp;
    host.confidence = Math.max(host.confidence, Number(event.observed_confidence || 0));
    if (event.timestamp)
      host.last_seen = Math.floor(Date.parse(event.timestamp) / 1000) || host.last_seen;
    else
      host.last_seen = Math.floor(Date.now() / 1000);
    host.source = event.source || 'heuristic';
    if (event.sni)
      host.sni = event.sni;
    if (event.alpn)
      host.alpn = event.alpn;
    if (event.ja3)
      host.ja3 = event.ja3;
    maybePushOverride(host);
  }
}

function snapshotToArray() {
  return Object.values(hostSnapshot).sort((a, b) => {
    return (b.rx_bps + b.tx_bps) - (a.rx_bps + a.tx_bps);
  });
}

function maybePushOverride(host) {
  if (!PUSH_OVERRIDES || !host)
    return;

  if (!host.ip || !host.persona)
    return;

  const now = Date.now();
  const personaChanged = host.persona !== host.last_pushed_persona;
  const confidenceChanged = Math.abs((host.confidence || 0) - (host.last_pushed_confidence || 0)) >= 5;
  const cooldownExpired = (now - (host.last_push_at || 0)) > 10000;

  if (!personaChanged && !confidenceChanged && !cooldownExpired)
    return;

  const payload = {
    ip: host.ip,
    persona: host.persona,
    confidence: Math.round(host.confidence || 0)
  };
  if (host.priority)
    payload.priority = host.priority;
  if (host.policy_action)
    payload.policy_action = host.policy_action;
  if (host.dscp)
    payload.dscp = host.dscp;

  const child = spawn(UBUS_BIN, ['call', 'qosd', 'apply', JSON.stringify(payload)], { stdio: 'ignore' });
  child.on('error', err => {
    console.error('[collector] ubus apply error:', err.message);
  });
  child.on('close', code => {
    if (code !== 0)
      console.error('[collector] ubus apply exited with code', code);
  });

  host.last_pushed_persona = host.persona;
  host.last_pushed_confidence = host.confidence || 0;
  host.last_push_at = now;
}

function ingestPayload(payload) {
  if (!payload)
    return;

  const items = Array.isArray(payload) ? payload : [payload];

  items.forEach(item => {
    updateStats(item);
    updateHostSnapshot(item);
    recentEvents.push(item);
  });

  if (recentEvents.length > MAX_RECENT_EVENTS) {
    recentEvents = recentEvents.slice(-MAX_RECENT_EVENTS);
  }
}

function parseRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      if (!chunks.length)
        return resolve(null);
      try {
        const body = Buffer.concat(chunks).toString('utf-8');
        if (!body)
          return resolve(null);
        resolve(JSON.parse(body));
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

async function handleRequest(req, res) {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname || '/';

  if (req.method === 'GET' && pathname === '/health') {
    return jsonResponse(res, 200, { status: 'ok', timestamp: new Date().toISOString() });
  }

  if (req.method === 'GET' && pathname === '/policies') {
    return jsonResponse(res, 200, policies);
  }

  if (req.method === 'GET' && pathname.startsWith('/policy/')) {
    const persona = pathname.split('/').pop();
    if (!persona)
      return jsonResponse(res, 400, { error: 'Persona required' });

    const policy = policies[persona] || policies.other || {};
    return jsonResponse(res, 200, { persona, policy });
  }

  if (req.method === 'POST' && pathname === '/policy') {
    try {
      const body = await parseRequestBody(req);
      if (!body || !body.persona)
        return jsonResponse(res, 400, { error: 'persona field is required' });

      const personaKey = body.persona.toLowerCase();
      policies[personaKey] = {
        policy_action: body.policy_action || 'observe',
        priority: body.priority || 'normal',
        dscp: body.dscp || 'CS0'
      };
      return jsonResponse(res, 200, { ok: true, persona: personaKey, policy: policies[personaKey] });
    } catch (err) {
      return jsonResponse(res, 400, { error: err.message });
    }
  }

  if (req.method === 'GET' && pathname === '/telemetry/recent') {
    return jsonResponse(res, 200, { events: recentEvents });
  }

  if (req.method === 'GET' && pathname === '/telemetry/persona') {
    return jsonResponse(res, 200, { personas: personaStats });
  }

  if (req.method === 'GET' && pathname === '/snapshot/lan') {
    return jsonResponse(res, 200, { hosts: snapshotToArray() });
  }

  if (req.method === 'POST' && pathname === '/ingest') {
    try {
      const payload = await parseRequestBody(req);
      ingestPayload(payload);
      return jsonResponse(res, 200, { ok: true });
    } catch (err) {
      return jsonResponse(res, 400, { error: err.message });
    }
  }

  textResponse(res, 404, 'Not Found');
}

loadPolicies();

http
  .createServer((req, res) => {
    handleRequest(req, res).catch(err => {
      jsonResponse(res, 500, { error: err.message });
    });
  })
  .listen(PORT, '0.0.0.0', () => {
    console.log(`[collector] listening on :${PORT}`);
  });
const PUSH_OVERRIDES = process.env.QOSD_PUSH_OVERRIDES === '1';
const UBUS_BIN = process.env.QOSD_UBUS_BIN || 'ubus';
const SURICATA_EVE_PATH = process.env.SURICATA_EVE_PATH || '';
const SURICATA_ENABLED = SURICATA_EVE_PATH.length > 0;

function processSuricataRecord(record) {
  if (!record || record.event_type !== 'app-layer')
    return;

  const proto = (record.app_proto || '').toLowerCase();
  if (!proto)
    return;

  const persona = APP_PROTO_PERSONA[proto];
  if (!persona)
    return;

  const ip = isPrivateIP(record.src_ip) ? record.src_ip :
    (isPrivateIP(record.dest_ip) ? record.dest_ip : null);
  if (!ip)
    return;

  const host = ensureHost(ip, null);
  if (!host)
    return;

  host.persona = persona;
  host.source = 'suricata';
  host.confidence = Math.max(host.confidence, 90);
  host.last_seen = Math.floor(Date.now() / 1000);
  maybePushOverride(host);
}

function startSuricataTail() {
  if (!SURICATA_ENABLED) {
    console.log('[collector] SURICATA_EVE_PATH not set, DPI integration disabled');
    return;
  }

  const args = ['-n0', '-F', SURICATA_EVE_PATH];
  const tail = spawn('tail', args);
  tail.on('error', err => {
    console.error('[collector] Failed to tail Suricata logs:', err.message);
  });
  tail.on('close', code => {
    console.warn(`[collector] Suricata tail exited with code ${code}, retrying in 5s`);
    setTimeout(startSuricataTail, 5000);
  });

  const rl = readline.createInterface({ input: tail.stdout });
  rl.on('line', line => {
    line = line.trim();
    if (!line)
      return;
    try {
      const record = JSON.parse(line);
      processSuricataRecord(record);
    } catch (err) {
      console.warn('[collector] Failed to parse Suricata EVE line:', err.message);
    }
  });
  rl.on('error', err => {
    console.error('[collector] Suricata readline error:', err.message);
  });
}

if (SURICATA_ENABLED)
  startSuricataTail();
