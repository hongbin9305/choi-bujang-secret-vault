import { readFileSync } from 'node:fs';
import { createLoginVerifier } from '../src/verify-login.mjs';

const METHODS = ['GET', 'POST', 'PUT', 'DELETE'];

const config = JSON.parse(
  readFileSync(
    new URL('../aleph.config.json', import.meta.url),
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

async function recordSecurityEvent(url, key, reason) {
  try {
    await fetch(`${url}/rest/v1/security_events`, {
      method: 'POST',
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal'
      },
      body: JSON.stringify({
        event_type: 'unauthorized_access',
        path: '/api/note',
        reason
      })
    });
  } catch (error) {
    console.error('Security event error:', error.message);
  }
}

function validNote(title, content) {
  return (
    typeof title === 'string' &&
    typeof content === 'string' &&
    title.trim().length > 0 &&
    title.length <= 200 &&
    content.length <= 10000
  );
}

function formatNote(note) {
  return {
    id: note.id,
    title: note.title,
    body: note.content
  };
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (!METHODS.includes(req.method)) {
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

  const authorization = req.headers.authorization;

  if (!authorization) {
    await recordSecurityEvent(
      url, key, 'missing_authentication'
    );

    return res.status(401).json({
      error: 'Authentication required'
    });
  }

  try {
    const identity = await getVerifier(key)(
      authorization
    );

    if (!identity) {
      await recordSecurityEvent(
        url, key, 'invalid_authentication'
      );

      return res.status(401).json({
        error: 'Invalid authentication'
      });
    }

    // 사용자 ID는 검증된 토큰에서만 가져온다.
    const userId = identity.userId;

    // 서버 전용 비밀 키로 DB에 접근하되
    // 모든 쿼리에 검증된 소유자 조건을 적용한다.
    const headers = {
      apikey: key,
      Authorization: `Bearer ${key}`,
      'Content-Type': 'application/json'
    };

    const base = `${url}/rest/v1/defense_notes`;

    if (req.method === 'GET') {
      const params = new URLSearchParams({
        select: 'id,title,content',
        owner_id: `eq.${userId}`,
        order: 'id.asc'
      });

      const response = await fetch(`${base}?${params}`, {
        headers,
        cache: 'no-store'
      });

      if (!response.ok) {
        console.error('GET failed:', response.status);
        return res.status(500).json({
          error: 'Failed to load notes'
        });
      }

      const notes = await response.json();

      if (identity.kind === 'judge') {
        return res.status(200).json(
          notes.map(formatNote)
        );
      }

      // 기존 웹사이트 응답 형식 유지
      return res.status(200).json({ notes });
    }

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

    if (
      !body ||
      typeof body !== 'object' ||
      Array.isArray(body)
    ) {
      return res.status(400).json({
        error: 'Invalid request body'
      });
    }

    if (req.method === 'POST') {
      const title = body.title;
      const content = body.body ?? body.content;

      if (!validNote(title, content)) {
        return res.status(400).json({
          error: 'Invalid note data'
        });
      }

      const response = await fetch(base, {
        method: 'POST',
        headers: {
          ...headers,
          Prefer: 'return=representation'
        },
        body: JSON.stringify({
          title: title.trim(),
          content,
          owner_id: userId
        })
      });

      if (!response.ok) {
        console.error('POST failed:', response.status);
        return res.status(500).json({
          error: 'Failed to create note'
        });
      }

      const notes = await response.json();
      const note = notes[0];

      if (!note) {
        return res.status(500).json({
          error: 'Created note not returned'
        });
      }

      if (identity.kind === 'judge') {
        return res.status(201).json(formatNote(note));
      }

      return res.status(201).json({ note });
    }

    // 기존 화면에서 사용하는 PUT / DELETE
    const id = Number(body.id);

    if (!Number.isSafeInteger(id) || id <= 0) {
      return res.status(400).json({
        error: 'Invalid note ID'
      });
    }

    const params = new URLSearchParams({
      id: `eq.${id}`,
      owner_id: `eq.${userId}`,
      select: 'id,title,content'
    });

    const endpoint = `${base}?${params}`;

    if (req.method === 'PUT') {
      const title = body.title;
      const content = body.body ?? body.content;

      if (!validNote(title, content)) {
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

      if (identity.kind === 'judge') {
        return res.status(200).json(
          formatNote(notes[0])
        );
      }

      return res.status(200).json({
        note: notes[0]
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
    console.error('Notes API error:', error.message);

    return res.status(500).json({
      error: 'Request failed'
    });
  }
}
