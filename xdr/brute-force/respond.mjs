import { appendFile, readFile, writeFile } from 'node:fs/promises';
import { decide } from './decide.mjs';
const TTL_MS = 10 * 60 * 1000;
export async function respond(alerts, { now = Date.now(), rulesPath = new URL('../deny-rules.json', import.meta.url), logPath = new URL('../alerts.log', import.meta.url) } = {}) {
  let existing = [];
  try { existing = JSON.parse(await readFile(rulesPath, 'utf8')); } catch(error) { if(error.code !== 'ENOENT') throw error; }
  const rules = Array.isArray(existing) ? existing.filter(r => Date.parse(r.expiresAt) > now) : [];
  const events = [];
  for (const alert of alerts) {
    const result = decide(alert);
    const id = typeof alert?.id === 'string' ? alert.id : '';
    if (result.action === 'record') continue;
    events.push({ alertId:id, action:result.action, reason:result.reason });
    if(result.action === 'block' && result.confidence >= 0.85 && typeof alert?.data?.srcip === 'string'
      && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(alert.data.srcip)
      && !rules.some(r => r.sourceAddress === alert.data.srcip)) {
      rules.push({sourceAddress:alert.data.srcip,expiresAt:new Date(now+TTL_MS).toISOString(),evidenceAlertIds:[id],reason:result.reason});
    }
  }
  await writeFile(rulesPath,JSON.stringify(rules,null,2)+'\n');
  if(events.length) await appendFile(logPath,events.map(e=>JSON.stringify(e)).join('\n')+'\n');
  // This is a candidate rules file. Production ZTNA enforcement requires
  // explicit integration with the engine; never overwrite RULE_IDS.
  return { rules, events };
}
