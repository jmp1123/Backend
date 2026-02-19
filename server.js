/**
 * Vestiary Backend — server.js
 * Proxies the Anthropic API so your key never touches the client.
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json({ limit: '20mb' }));

app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',
  methods: ['POST', 'GET'],
}));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests — please wait a moment and try again.' }
});
app.use('/api/', limiter);

app.use(function (req, res, next) {
  console.log('[' + new Date().toISOString() + ']', req.method, req.path);
  next();
});

// Health check
app.get('/health', function (req, res) {
  res.json({
    status: 'ok',
    version: '1.0.0',
    keyConfigured: !!process.env.ANTHROPIC_API_KEY
  });
});

// POST /api/identify — Image analysis
app.post('/api/identify', async function (req, res) {
  const { image, mimeType } = req.body;

  if (!image) {
    return res.status(400).json({ error: 'Missing image field.' });
  }
  if (!mimeType || !mimeType.startsWith('image/')) {
    return res.status(400).json({ error: 'Invalid or missing mimeType.' });
  }
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error('ANTHROPIC_API_KEY is not set in environment.');
    return res.status(500).json({ error: 'Server is not configured. Contact the app owner.' });
  }

  const prompt = [
    'You are a fashion identification assistant for a wardrobe app.',
    'Analyse this clothing item photo and return ONLY a JSON object — no markdown, no prose, no explanation.',
    'Required fields:',
    '  name   — short descriptive name, e.g. "White Oxford Shirt"',
    '  cat    — exactly one of: Tops | Bottoms | Outerwear | Footwear | Accessories | Suiting | Other',
    '  color  — primary color(s) in plain English',
    '  fabric — material if discernible e.g. "cotton", "wool", "leather", "denim"; else ""',
    '  fit    — fit style if applicable e.g. "slim", "relaxed", "oversized"; else ""',
    '  brand  — brand name if clearly visible in the photo; else ""',
    '  details — one natural sentence max 15 words describing the item',
    '',
    'Example output:',
    '{"name":"White Oxford Shirt","cat":"Tops","color":"White","fabric":"Cotton","fit":"Regular","brand":"","details":"Classic cotton button-down, versatile for smart-casual and formal occasions."}'
  ].join('\n');

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 300,
        messages: [{
          role: 'user',
          content: [
            {
              type: 'image',
              source: { type: 'base64', media_type: mimeType, data: image }
            },
            { type: 'text', text: prompt }
          ]
        }]
      })
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      const msg = (err.error && err.error.message) || ('Anthropic API error ' + response.status);
      console.error('Anthropic error:', response.status, msg);
      return res.status(502).json({ error: msg });
    }

    const data = await response.json();
    const raw = (data.content && data.content[0] && data.content[0].text) || '';

    const match = raw.match(/\{[\s\S]*\}/);
    if (!match) {
      console.error('Unexpected Claude response:', raw);
      return res.status(502).json({ error: 'Unexpected response from AI — try again.' });
    }

    const result = JSON.parse(match[0]);

    const out = {
      name: result.name || 'Clothing Item',
      cat: result.cat || 'Other',
      color: result.color || '',
      fabric: result.fabric || '',
      fit: result.fit || '',
      brand: result.brand || '',
      details: result.details || '',
    };

    return res.json(out);

  } catch (err) {
    console.error('Server error:', err);
    return res.status(500).json({ error: 'Internal server error. Please try again.' });
  }
});

// POST /api/coach — Style coach chat
app.post('/api/coach', async function (req, res) {
  const { messages, systemContext } = req.body;

  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: 'Missing messages array.' });
  }
  if (!process.env.ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'Server is not configured. Contact the app owner.' });
  }

  const systemPrompt = [
    'You are Alex, a certified personal stylist and style coach inside the Vestiary wardrobe app.',
    'You have access to the user\'s full wardrobe, measurements, and style profile.',
    'Be direct, specific, and helpful. Reference their actual items when relevant.',
    'Keep responses concise — 2-4 sentences unless a detailed breakdown is needed.',
    systemContext || ''
  ].filter(Boolean).join('\n');

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 400,
        system: systemPrompt,
        messages: messages.slice(-10)
      })
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      return res.status(502).json({ error: (err.error && err.error.message) || 'API error' });
    }

    const data = await response.json();
    const reply = (data.content && data.content[0] && data.content[0].text) || '';
    return res.json({ reply });

  } catch (err) {
    console.error('Coach error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// Start server
app.listen(PORT, function () {
  console.log('');
  console.log('  ✦ Vestiary Backend running');
  console.log('  → Port: ' + PORT);
  console.log('  → API key: ' + (process.env.ANTHROPIC_API_KEY ? '✓ configured' : '✗ MISSING'));
  console.log('');
});
