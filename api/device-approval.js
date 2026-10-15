import { randomBytes, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createLoginVerifier } from '../src/verify-login.mjs';
const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
let verify;
const hash = token => createHash('sha256').update(token).digest('hex');
export default async function handler(req,res) {
  res.setHeader('Cache-Control','no-store');
  res.setHeader('X-Content-Type-Options','nosniff');
  if (!['GET','POST'].includes(req.method)) return res.status(405).json({error:'Method not allowed'});
  const url=process.env.SUPABASE_URL,key=process.env.SUPABASE_SECRET_KEY;
  if(!url||!key) return res.status(500).json({error:'Server configuration missing'});
  if(!req.headers.authorization) return res.status(401).json({error:'Authentication required'});
  try {
    verify ??= createLoginVerifier({config,supabaseSecretKey:key});
    const identity=await verify(req.headers.authorization);
    if(!identity) return res.status(401).json({error:'Invalid authentication'});
    const headers={apikey:key,Authorization:`Bearer ${key}`,'Content-Type':'application/json'};
    const cookie=(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith('bb_device='));
    const token=cookie?.slice('bb_device='.length);
    const valid=typeof token==='string' && /^[a-f0-9]{64}$/.test(token);
    if(req.method==='GET') {
      if(!valid) return res.status(200).json({status:'unregistered',approved:false});
      const params=new URLSearchParams({select:'status',owner_id:`eq.${identity.userId}`,device_hash:`eq.${hash(token)}`,limit:'1'});
      const response=await fetch(`${url}/rest/v1/defense_device_requests?${params}`,{headers,cache:'no-store'});
      if(!response.ok) return res.status(503).json({error:'Approval status unavailable'});
      const rows=await response.json();
      const status=rows[0]?.status||'unregistered';
      return res.status(200).json({status,approved:status==='approved'});
    }
    if(valid) {
      const params=new URLSearchParams({select:'status',owner_id:`eq.${identity.userId}`,device_hash:`eq.${hash(token)}`,limit:'1'});
      const previous=await fetch(`${url}/rest/v1/defense_device_requests?${params}`,{headers});
      if(!previous.ok) return res.status(503).json({error:'Approval status unavailable'});
      const rows=await previous.json();
      if(rows.length) return res.status(200).json({status:rows[0].status,approved:rows[0].status==='approved'});
    }
    const fresh=randomBytes(32).toString('hex');
    const response=await fetch(`${url}/rest/v1/defense_device_requests`,{
      method:'POST',headers:{...headers,Prefer:'return=minimal'},
      body:JSON.stringify({owner_id:identity.userId,device_hash:hash(fresh),status:'pending'})
    });
    if(!response.ok) return res.status(503).json({error:'Device request failed'});
    res.setHeader('Set-Cookie',`bb_device=${fresh}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=2592000`);
    return res.status(202).json({status:'pending',approved:false});
  } catch {return res.status(500).json({error:'Device approval unavailable'});}
}
