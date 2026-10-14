import { readFileSync } from 'node:fs';
import { createLoginVerifier } from '../../src/verify-login.mjs';

const ALLOWED_METHODS = ['GET', 'PUT', 'DELETE'];

const config = JSON.parse(
  readFileSync(
    new URL('../../aleph.config.json', import.meta.url),
    'utf8'
  )
);

let verifier;

function getVerifier(secretKey) {
  if (!verifier) {
    verifier = createLoginVerifier({
      config,
      supabaseSecretKey: secretKey
    });
  }
  return verifier;
}

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

  if (!req.headers.authorization) {
    return res.status(401).json({
      error: 'Authentication required'
    });
  }

  try {
    // 서버에서 로그인 토큰 검증
    const identity = await getVerifier(key)(
      req.headers.authorization
    );

    if (!identity) {
      return res.status(401).json({
        error: 'Invalid authentication'
      });
    }

    // 요청자가 입력한 사용자 ID는 사용하지 않는다.
    const userId = identity.userId;

    const id = Number(req.query.id);

    if (
      !Number.isSafeInteger(id) ||
      id <= 0
    ) {
      return res.status(400).json({
        error: 'Invalid note ID'
      });
    }

    // 서버 전용 키 사용
    // 검증된 소유자의 메모만 접근 가능
    const headers = {
      apikey: key,
      Authorization: `Bearer ${key}`,
      'Content-Type': 'application/json'
    };

    const params = new URLSearchParams({
      id: `eq.${id}`,
      owner_id: `eq.${userId}`,
      select: 'id,title,content'
    });

    const endpoint =
      `${url}/rest/v1/defense_notes?${params}`;

    if (req.method === 'GET') {
      const response = await fetch(endpoint, {
        headers,
        cache: 'no-store'
      });

      if (!response.ok) {
        console.error('GET note failed:', response.status);
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

    if (req.method === 'PUT') {
      let body;

      try {
        body = typeof req.body === 'string'
          ? JSON.parse(req.body)
          : req.body || {};
      } catch {
        return res.status(400).json({
          error: 'Invalid JSON'
        });
      }

      const title = body.title;
      const content = body.body ?? body.content;

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
        console.error('PUT note failed:', response.status);
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

    const response = await fetch(endpoint, {
      method: 'DELETE',
      headers: {
        ...headers,
        Prefer: 'return=representation'
      }
    });

    if (!response.ok) {
      console.error('DELETE note failed:', response.status);
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
    console.error(
      'Individual note API error:',
      error.message
    );

    return res.status(500).json({
      error: 'Request failed'
    });
  }
}
