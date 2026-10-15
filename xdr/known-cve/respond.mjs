import { readFile, writeFile, appendFile } from 'node:fs/promises';
import { decide } from './decide.mjs';
const TTL_MS = 10 * 60 * 1000;
export async function respond(alerts, { now = Date.now(),
  rulesPath = new URL('../known-cve-deny-rules.json', import.meta.url),
  logPath = new URL('../alerts.log', import.meta.url) } = {}) {
  let saved = [];
  try { saved = JSON.parse(await readFile(rulesPath, 'utf8')); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const rules = Array.isArray(saved) ? saved.filter(rule => Date.parse(rule.expiresAt) > now) : [];
  const events = [];
  for (const alert of alerts) {
    const decision = decide(alert);
    if (decision.action === 'record') continue;
    const alertId = typeof alert?.id === 'string' ? alert.id : '';
    events.push({ alertId, action: decision.action, reason: decision.reason });
    const address = alert?.data?.srcip;
    if (decision.action === 'block' && decision.confidence >= 0.85
      && typeof address === 'string' && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(address)) {
      const existing = rules.find(rule => rule.sourceAddress === address);
      if (existing) {
        if (!existing.evidenceAlertIds.includes(alertId)) existing.evidenceAlertIds.push(alertId);
      } else {
        rules.push({ sourceAddress: address, expiresAt: new Date(now + TTL_MS).toISOString(),
          evidenceAlertIds: [alertId], reason: decision.reason });
      }
    }
  }
  await writeFile(rulesPath, JSON.stringify(rules, null, 2) + '\n');
  if (events.length) await appendFile(logPath, events.map(event => JSON.stringify(event)).join('\n') + '\n');
  return { rules, events };
}
