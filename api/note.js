
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

  try {
    const response = await fetch(
      `${url}/rest/v1/defense_notes?select=title,content&order=id.asc`,
      {
        headers: {
          apikey: key,
        }
      }
    );

    if (!response.ok) {
  const details = await response.text();
  console.error('Supabase error status:', response.status);
  console.error('Supabase error details:', details);
  throw new Error(`Database request failed: ${response.status}`);
}

    const notes = await response.json();
    return res.status(200).json({ notes });
  } catch (error) {
    console.error('Notes API error:', error.message);
    return res.status(500).json({ error: 'Failed to load notes' });
  }
}
