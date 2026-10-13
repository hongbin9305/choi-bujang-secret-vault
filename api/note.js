
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;

  if (!url || !key) {
    return res.status(500).json({ error: 'Server configuration missing' });
  }

  const authorization = req.headers.authorization || '';
  const match = /^Bearer (.+)$/i.exec(authorization);

  if (!match) {
  console.warn(JSON.stringify({
    event: 'unauthorized_access',
    path: '/api/note',
    reason: 'missing_authentication',
    status: 401,
    timestamp: new Date().toISOString()
  }));

  return res.status(401).json({
    error: 'Authentication required'
  });
}


  const token = match[1];

  try {
    // Supabase Auth에서 토큰을 검증한다.
    const authResponse = await fetch(`${url}/auth/v1/user`, {
      headers: {
        apikey: key,
        Authorization: `Bearer ${token}`
      }
    });

    if (!authResponse.ok) {
      return res.status(401).json({ error: 'Invalid authentication' });
    }

    const user = await authResponse.json();

    if (!user.id) {
      return res.status(401).json({ error: 'Invalid user' });
    }

    // 검증된 사용자 UID에 해당하는 자료만 조회한다.
    const params = new URLSearchParams({
      select: 'title,content',
      owner_id: `eq.${user.id}`,
      order: 'id.asc'
    });

    const response = await fetch(
      `${url}/rest/v1/defense_notes?${params}`,
      {
        headers: {
          apikey: key,
          Authorization: `Bearer ${token}`
        }
      }
    );

    if (!response.ok) {
      console.error('Database request failed:', response.status);
      return res.status(500).json({ error: 'Failed to load notes' });
    }

    const notes = await response.json();
    return res.status(200).json({ notes });

  } catch (error) {
    console.error('Notes API error:', error.message);
    return res.status(500).json({ error: 'Failed to load notes' });
  }
}
