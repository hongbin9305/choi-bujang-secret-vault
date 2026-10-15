// Operates only on the engine-provided synthetic event contract.
// Never inspect, store, or print credentials, note contents, or real identities.
export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const bySubject = new Map();
  for (const event of events) {
    if (event?.method !== 'GET') continue;
    const sub = event?.identity?.sub;
    const at = event?.at;
    if (typeof sub !== 'string' || !sub || typeof at !== 'string') continue;
    const time = Date.parse(at);
    if (!Number.isFinite(time)) continue;
    if (!bySubject.has(sub)) bySubject.set(sub, []);
    bySubject.get(sub).push(time);
  }

  for (const [sub, times] of bySubject) {
    if (times.length <= 120) continue;
    times.sort((a, b) => a - b);
    for (let right = 120; right < times.length; right++) {
      // Inclusive 10-minute window; 121 events are required.
      if (times[right] - times[right - 120] <= 600000) {
        return { action: 'propose_revocation', reasonCode: 'burst_read', subject: sub };
      }
    }
  }
  return { action: 'observe' };
}
