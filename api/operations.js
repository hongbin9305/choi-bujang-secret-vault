import { readFileSync } from 'node:fs';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { RULE_IDS } from '../src/decider.mjs';
const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
let verify;
export default async function handler(req,res) {
  res.setHeader('Cache-Control','no-store');
  res.setHeader('X-Content-Type-Options','nosniff');
  if(req.method!=='GET') return res.status(405).json({error:'Method not allowed'});
  const url=process.env.SUPABASE_URL,key=process.env.SUPABASE_SECRET_KEY,admin=process.env.ADMIN_USER_ID;
  if(!url||!key||!admin) return res.status(503).json({error:'Dashboard unavailable'});
  try {
    verify ??= createLoginVerifier({config,supabaseSecretKey:key});
    const identity=await verify(req.headers.authorization);
    if(!identity) return res.status(401).json({error:'Authentication required'});
    if(identity.kind!=='student'||identity.userId!==admin) return res.status(403).json({error:'Admin only'});
    const headers={apikey:key,Authorization:`Bearer ${key}`};
    const since=new Date(Date.now()-5*60000).toISOString();
    const q=new URLSearchParams({select:'id,event_type,created_at',created_at:`gte.${since}`,order:'created_at.desc',limit:'1000'});
    const response=await fetch(`${url}/rest/v1/security_events?${q}`,{headers,cache:'no-store'});
    if(!response.ok) return res.status(503).json({error:'Events unavailable'});
    const events=await response.json();
    const backup=await fetch(`${url}/rest/v1/defense_note_backups?select=id&limit=1`,{headers,cache:'no-store'});
    const devices=await fetch(`${url}/rest/v1/defense_device_requests?select=status&limit=1000`,{headers,cache:'no-store'});
    return res.status(200).json({
      checkedAt:new Date().toISOString(),
      policy:{source:'checked-in src/decider.mjs',ruleIds:RULE_IDS,liveEngine:'not_verified'},
      detection:{source:'security_events',windowMinutes:5,observedEvents:events.length,liveRevocation:'not_verified'},
      revocation:{status:'not_verified'},
      restore:{source:'defense_note_backups',snapshotAvailable:backup.ok,version:'current_snapshot_not_preincident',lastRestore:'not_verified'},
      deviceApproval:{source:'defense_device_requests',counts:devices.ok?(await devices.json()).reduce((a,x)=>(a[x.status]=(a[x.status]||0)+1,a),{}):null},
      testSuite:{total:41,executed:0,passed:0,status:'not_run'}
    });
  } catch {return res.status(503).json({error:'Dashboard unavailable'});}
}
