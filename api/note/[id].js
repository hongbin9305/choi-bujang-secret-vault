
const ALLOWED_METHODS = ['GET', 'PUT', 'DELETE'];

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (!ALLOWED_METHODS.includes(req.method)) {
    return res.status(405).json({
      error: 'Method not allowed'
    });
  }

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;

  if (!url || !key) {
    return res.status(500).json({
      error: 'Server configuration missing'
    });
  }

  const match = /^Bearer (.+)$/i.exec(
    req.headers.authorization || ''
  );

  if (!match) {
    return res.status(401).json({
      error: 'Authentication required'
    });
  }

  const token = match[1];

  try {
    // Supabase 서버에서 실제 로그인 토큰 확인
    const authResponse = await fetch(
      `${url}/auth/v1/user`,
      {
        headers: {
          apikey: key,
          Authorization: `Bearer ${token}`
        }
      }
    );

    if (!authResponse.ok) {
      return res.status(401).json({
        error: 'Invalid authentication'
      });
    }

    const user = await authResponse.json();

    if (!user.id) {
      return res.status(401).json({
        error: 'Invalid user'
      });
    }

    // URL의 메모 번호 확인
    const rawId = req.query.id;

    const id = Number(rawId);

    if (
      !Number.isSafeInteger(id) ||
      id <= 0
    ) {
      return res.status(400).json({
        error: 'Invalid note ID'
      });
    }

    const headers = {
      apikey: key,
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    };

    const params = new URLSearchParams({
      id: `eq.${id}`,
      owner_id: `eq.${user.id}`,
      select: 'id,title,content'
    });

    const endpoint =
      `${url}/rest/v1/defense_notes?${params}`;

    // 개별 메모 조회
    if (req.method === 'GET') {
      const response = await fetch(endpoint, {
        headers
      });

      if (!response.ok) {
        return res.status(500).json({
          error: 'Failed to load note'
        });
      }

      const notes = await response.json();

      if (!notes.length) {
        return res.status(404).json({
          error: 'Note not found'
        });
      }

      return res.status(200).json({
        id: notes[0].id,
        title: notes[0].title,
        body: notes[0].content
      });
    }

    // 개별 메모 수정
    if (req.method === 'PUT') {
      const body = typeof req.body === 'string'
        ? JSON.parse(req.body)
        : req.body || {};

      const title = body.title;
      const content = body.body;

      if (
        typeof title !== 'string' ||
        typeof content !== 'string' ||
        !title.trim() ||
        title.length > 200 ||
        content.length > 10000
      ) {
        return res.status(400).json({
          error: 'Invalid note data'
        });
      }

      const response = await fetch(endpoint, {
        method: 'PATCH',
        headers: {
          ...headers,
          Prefer: 'return=representation'
        },
        body: JSON.stringify({
          title: title.trim(),
          content
        })
      });

      if (!response.ok) {
        return res.status(500).json({
          error: 'Failed to update note'
        });
      }

      const notes = await response.json();

      if (!notes.length) {
        return res.status(404).json({
          error: 'Note not found'
        });
      }

      return res.status(200).json({
        id: notes[0].id,
        title: notes[0].title,
        body: notes[0].content
      });
    }

    // 개별 메모 삭제
    const response = await fetch(endpoint, {
      method: 'DELETE',
      headers: {
        ...headers,
        Prefer: 'return=representation'
      }
    });

    if (!response.ok) {
      return res.status(500).json({
        error: 'Failed to delete note'
      });
    }

    const notes = await response.json();

    if (!notes.length) {
      return res.status(404).json({
        error: 'Note not found'
      });
    }

    return res.status(200).json({
      deleted: true,
      id
    });

  } catch (error) {
    console.error('Individual note API error:', error.message);

    return res.status(500).json({
      error: 'Request failed'
    });
  }
}
