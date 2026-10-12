
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (req.method !== 'GET') {
    return res.status(405).json({
      error: 'Method not allowed'
    });
  }

  // 1. 인증 토큰이 있는지 확인
  const authorization = req.headers.authorization;

  if (!authorization || !/^Bearer\s+\S+$/i.test(authorization)) {
    return res.status(401).json({
      error: 'Authentication required'
    });
  }

  // 2. 서버 설정 확인
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;

  if (!url || !key) {
    return res.status(500).json({
      error: 'Server configuration missing'
    });
  }

  // 3. 전달받은 토큰을 Supabase에서 검증
  const token = authorization.replace(/^Bearer\s+/i, '');

  try {
    const authResponse = await fetch(`${url}/auth/v1/user`, {
      headers: {
        apikey: key,
        Authorization: `Bearer ${token}`
      }
    });

    if (!authResponse.ok) {
      return res.status(401).json({
        error: 'Invalid or expired token'
      });
    }

    const user = await authResponse.json();

    if (!user.id) {
      return res.status(401).json({
        error: 'Invalid user'
      });
    }

    // 4. 사용자 본인의 자료만 조회
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
      throw new Error('Database request failed');
    }

    const notes = await response.json();

    return res.status(200).json({ notes });

  } catch (error) {
    console.error('Notes API error:', error.message);

    return res.status(500).json({
      error: 'Failed to load notes'
    });
  }
}
