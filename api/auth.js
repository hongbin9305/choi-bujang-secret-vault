const url = process.env.SUPABASE_URL;
const key = process.env.SUPABASE_SECRET_KEY;

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  if (!url || !key) {
    return res.status(500).json({ error: 'Server configuration error' });
  }

  const { email, password } = req.body || {};

  if (
    typeof email !== 'string' ||
    typeof password !== 'string' ||
    email.length > 254 ||
    password.length > 1024
  ) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  try {
    const response = await fetch(`${url}/auth/v1/token?grant_type=password`, {
      method: 'POST',
      headers: {
        apikey: key,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ email, password })
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(401).json({ error: 'Login failed' });
    }

    return res.status(200).json({
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_in: data.expires_in,
      user: {
        id: data.user?.id,
        email: data.user?.email
      }
    });
  } catch {
    return res.status(502).json({ error: 'Authentication service unavailable' });
  }
}
