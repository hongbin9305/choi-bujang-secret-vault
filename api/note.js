
const METHODS = ['GET', 'POST', 'PUT', 'DELETE'];

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

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (!METHODS.includes(req.method)) {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;

  if (!url || !key) {
    return res.status(500).json({ error: 'Server configuration missing' });
  }

  const match = /^Bearer (.+)$/i.exec(
    req.headers.authorization || ''
  );

  if (!match) {
    await recordSecurityEvent(url, key, 'missing_authentication');
    return res.status(401).json({
      error: 'Authentication required'
    });
  }

  const token = match[1];

  try {
    const authResponse = await fetch(`${url}/auth/v1/user`, {
      headers: {
        apikey: key,
        Authorization: `Bearer ${token}`
      }
    });

    if (!authResponse.ok) {
      await recordSecurityEvent(url, key, 'invalid_authentication');
      return res.status(401).json({
        error: 'Invalid authentication'
      });
    }

    const user = await authResponse.json();

    if (!user.id) {
      return res.status(401).json({ error: 'Invalid user' });
    }

    const headers = {
      apikey: key,
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    };

    const base = `${url}/rest/v1/defense_notes`;

    if (req.method === 'GET') {
      const params = new URLSearchParams({
        select: 'id,title,content',
        owner_id: `eq.${user.id}`,
        order: 'id.asc'
      });

      const response = await fetch(`${base}?${params}`, {
        headers
      });

      if (!response.ok) {
        return res.status(500).json({ error: 'Failed to load notes' });
      }

      return res.status(200).json({
        notes: await response.json()
      });
    }

    const body = typeof req.body === 'string'
      ? JSON.parse(req.body)
      : req.body || {};

    if (req.method === 'POST') {
      const title = body.title;
      const content = body.content;

      if (
        typeof title !== 'string' ||
        typeof content !== 'string' ||
        !title.trim() ||
        title.length > 200 ||
        content.length > 10000
      ) {
        return res.status(400).json({ error: 'Invalid note data' });
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
          owner_id: user.id
        })
      });

      if (!response.ok) {
        console.error('Insert failed:', response.status);
        return res.status(500).json({ error: 'Failed to create note' });
      }

      return res.status(201).json({
        note: (await response.json())[0]
      });
    }

    const id = Number(body.id);

    if (!Number.isSafeInteger(id) || id <= 0) {
      return res.status(400).json({ error: 'Invalid note ID' });
    }

    const params = new URLSearchParams({
      id: `eq.${id}`,
      owner_id: `eq.${user.id}`,
      select: 'id,title,content'
    });

    if (req.method === 'PUT') {
      const title = body.title;
      const content = body.content;

      if (
        typeof title !== 'string' ||
        typeof content !== 'string' ||
        !title.trim() ||
        title.length > 200 ||
        content.length > 10000
      ) {
        return res.status(400).json({ error: 'Invalid note data' });
      }

      const response = await fetch(`${base}?${params}`, {
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
        return res.status(500).json({ error: 'Failed to update note' });
      }

      const notes = await response.json();

      if (!notes.length) {
        return res.status(404).json({ error: 'Note not found' });
      }

      return res.status(200).json({ note: notes[0] });
    }

    const response = await fetch(`${base}?${params}`, {
      method: 'DELETE',
      headers: {
        ...headers,
        Prefer: 'return=representation'
      }
    });

    if (!response.ok) {
      return res.status(500).json({ error: 'Failed to delete note' });
    }

    const notes = await response.json();

    if (!notes.length) {
      return res.status(404).json({ error: 'Note not found' });
    }

    return res.status(200).json({ deleted: true });

  } catch (error) {
    console.error('Notes API error:', error.message);
    return res.status(500).json({ error: 'Request failed' });
  }
}
