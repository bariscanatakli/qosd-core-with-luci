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

const PORT = parseInt(process.env.PORT || '4000', 10);
const MAX_RECENT_EVENTS = parseInt(process.env.MAX_EVENTS || '200', 10);

let policies = {};
let personaStats = {};
let recentEvents = [];

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

function ingestPayload(payload) {
  if (!payload)
    return;

  const items = Array.isArray(payload) ? payload : [payload];

  items.forEach(item => {
    updateStats(item);
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
