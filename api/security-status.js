
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  const adminUid = process.env.ADMIN_USER_ID;

  if (!url || !key || !adminUid) {
    return res.status(500).json({ error: 'Server configuration missing' });
  }

  const match = /^Bearer (.+)$/i.exec(req.headers.authorization || '');

  if (!match) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const authResponse = await fetch(`${url}/auth/v1/user`, {
      headers: {
        apikey: key,
        Authorization: `Bearer ${match[1]}`
      }
    });

    if (!authResponse.ok) {
      return res.status(401).json({ error: 'Invalid authentication' });
    }

    const user = await authResponse.json();

    if (!user.id || user.id !== adminUid) {
      return res.status(403).json({ error: 'Admin access required' });
    }

    // 관리자 인증이 끝난 후에만 보안 로그를 조회한다.
    const since = new Date(Date.now() - 5 * 60 * 1000).toISOString();

    const params = new URLSearchParams({
      select: 'id,event_type,path,reason,created_at',
      event_type: 'eq.unauthorized_access',
      created_at: `gte.${since}`,
      order: 'created_at.desc',
      limit: '1000'
    });

    const response = await fetch(
      `${url}/rest/v1/security_events?${params}`,
      {
        headers: {
          apikey: key,
          Authorization: `Bearer ${key}`
        }
      }
    );

    if (!response.ok) {
      console.error('Security status query failed:', response.status);
      return res.status(500).json({ error: 'Failed to load security status' });
    }

    const events = await response.json();
    const count = events.length;

    return res.status(200).json({
      attempt_count: count,
      threat_level: count >= 5 ? 'ALERT' : 'NORMAL',
      window_minutes: 5,
      events
    });

  } catch (error) {
    console.error('Security status error:', error.message);
    return res.status(500).json({ error: 'Failed to load security status' });
  }
}
