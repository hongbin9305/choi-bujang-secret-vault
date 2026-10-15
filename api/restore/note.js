import { readFileSync } from 'node:fs';
import { createLoginVerifier } from '../../src/verify-login.mjs';
const config = JSON.parse(readFileSync(new URL('../../aleph.config.json', import.meta.url), 'utf8'));
let verify;
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) return res.status(500).json({ error: 'Server configuration missing' });
  if (!req.headers.authorization) return res.status(401).json({ error: 'Authentication required' });
  try {
    verify ??= createLoginVerifier({ config, supabaseSecretKey: key });
    const identity = await verify(req.headers.authorization);
    if (!identity) return res.status(401).json({ error: 'Invalid authentication' });
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    const id = Number(body?.id);
    if (!Number.isSafeInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid note ID' });
    // Owner is derived exclusively from the verified login, not the request body.
    const headers = { apikey: key, Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' };
    const params = new URLSearchParams({ id: `eq.${id}`, owner_id: `eq.${identity.userId}`, select: 'id,owner_id,content_hash' });
    const snapshot = await fetch(`${url}/rest/v1/defense_note_backups?${params}`, { headers, cache: 'no-store' });
    if (!snapshot.ok) return res.status(503).json({ error: 'Backup unavailable' });
    const backups = await snapshot.json();
    if (backups.length !== 1) return res.status(404).json({ error: 'Verified backup not found' });
    const rpc = await fetch(`${url}/rest/v1/rpc/restore_defense_note`, {
      method: 'POST', headers, body: JSON.stringify({ p_id: id, p_owner: identity.userId })
    });
    if (!rpc.ok) return res.status(409).json({ error: 'Restore verification failed' });
    const result = await rpc.json();
    if (!result?.restored || result.id !== id || result.contentHash !== backups[0].content_hash)
      return res.status(409).json({ error: 'Restore integrity mismatch' });
    return res.status(200).json({ restored: true, id, contentHash: result.contentHash });
  } catch {
    return res.status(400).json({ error: 'Invalid restore request' });
  }
}
