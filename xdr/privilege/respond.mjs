// Temporary account-session denial candidates, separate from existing ZTNA rules.
import { readFile, writeFile, appendFile } from 'node:fs/promises';
import { decide } from './decide.mjs';
export async function respond(alerts, { now = Date.now(),
  rulesPath = new URL('../privilege-deny-rules.json', import.meta.url),
  logPath = new URL('../alerts.log', import.meta.url) } = {}) {
  let previous = [];
  try { previous = JSON.parse(await readFile(rulesPath, 'utf8')); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const rules = Array.isArray(previous) ? previous.filter(rule => Date.parse(rule.expiresAt) > now) : [];
  const events = [];
  for (const alert of alerts) {
    const decision = decide(alert);
    if (decision.action === 'record') continue;
    const alertId = typeof alert?.id === 'string' ? alert.id : '';
    events.push({ alertId, action: decision.action, reason: decision.reason });
    const account = alert?.data?.srcuser;
    const sourceAddress = alert?.data?.srcip;
    if (decision.action === 'block' && decision.confidence >= 0.85
      && typeof account === 'string' && account.length > 0
      && typeof sourceAddress === 'string' && sourceAddress.length > 0) {
      const existing = rules.find(r => r.account === account && r.sourceAddress === sourceAddress);
      if (existing) {
        if (!existing.evidenceAlertIds.includes(alertId)) existing.evidenceAlertIds.push(alertId);
      } else {
        rules.push({ account, sourceAddress, expiresAt: new Date(now + 600000).toISOString(),
          evidenceAlertIds: [alertId], reason: decision.reason });
      }
    }
  }
  await writeFile(rulesPath, JSON.stringify(rules, null, 2) + '\n');
  if (events.length) await appendFile(logPath, events.map(e => JSON.stringify(e)).join('\n') + '\n');
  return { rules, events };
}
