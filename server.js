/**
 * Vestiary Backend v2.0
 * - PostgreSQL database for user data
 * - User authentication (signup/login)
 * - Admin panel to view all users
 * - AI clothing identification
 * - Style coach chat
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'vestiary-secret-change-in-production';
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'admin123'; // Change this!

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Initialize database tables
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        name VARCHAR(255),
        city VARCHAR(255),
        measurements JSONB DEFAULT '{}',
        style_moods TEXT[] DEFAULT '{}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS closet_items (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        category VARCHAR(50),
        color VARCHAR(100),
        fabric VARCHAR(100),
        fit VARCHAR(50),
        brand VARCHAR(100),
        details TEXT,
        image_url TEXT,
        cost DECIMAL(10,2),
        wears INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS saved_outfits (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255),
        item_ids INTEGER[],
        occasion VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE INDEX IF NOT EXISTS idx_closet_user ON closet_items(user_id);
      CREATE INDEX IF NOT EXISTS idx_outfits_user ON saved_outfits(user_id);
    `);
    console.log('  → Database tables initialized');
  } catch (err) {
    console.error('Database init error:', err.message);
  }
}

// Middleware
app.use(express.json({ limit: '20mb' }));
app.use(cors({
  origin: '*',
  methods: ['POST', 'GET', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-key']
}));
app.options('*', cors());

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: { error: 'Too many requests — please wait.' }
});
app.use('/api/', limiter);

// Request logger
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// Auth middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Admin middleware
function authenticateAdmin(req, res, next) {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_SECRET) {
    return res.status(403).json({ error: 'Admin access denied' });
  }
  next();
}

// ============== HEALTH & ROOT ==============

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    version: '2.0.0',
    database: !!process.env.DATABASE_URL,
    apiKey: !!process.env.ANTHROPIC_API_KEY
  });
});

app.get('/', (req, res) => {
  res.json({
    name: 'Vestiary Backend',
    version: '2.0.0',
    endpoints: {
      auth: ['/api/auth/signup', '/api/auth/login'],
      user: ['/api/user/profile', '/api/user/closet', '/api/user/outfits'],
      ai: ['/api/identify', '/api/coach'],
      admin: ['/api/admin/users', '/api/admin/stats']
    }
  });
});

// ============== AUTH ENDPOINTS ==============

// Sign up
app.post('/api/auth/signup', async (req, res) => {
  const { email, password, name, city, measurements, moods } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  
  try {
    // Check if user exists
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);
    
    // Create user
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, name, city, measurements, style_moods) 
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING id, email, name, city, measurements, style_moods, created_at`,
      [email.toLowerCase(), passwordHash, name || '', city || '', measurements || {}, moods || []]
    );
    
    const user = result.rows[0];
    
    // Generate token
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    
    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        city: user.city,
        measurements: user.measurements,
        moods: user.style_moods
      }
    });
    
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Server error during signup' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  
  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email.toLowerCase()]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    // Update last login
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
    
    // Generate token
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    
    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        city: user.city,
        measurements: user.measurements,
        moods: user.style_moods
      }
    });
    
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// ============== USER ENDPOINTS ==============

// Get profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, name, city, measurements, style_moods, created_at FROM users WHERE id = $1',
      [req.user.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Update profile
app.put('/api/user/profile', authenticateToken, async (req, res) => {
  const { name, city, measurements, moods } = req.body;
  
  try {
    const result = await pool.query(
      `UPDATE users SET 
        name = COALESCE($1, name),
        city = COALESCE($2, city),
        measurements = COALESCE($3, measurements),
        style_moods = COALESCE($4, style_moods)
       WHERE id = $5
       RETURNING id, email, name, city, measurements, style_moods`,
      [name, city, measurements, moods, req.user.id]
    );
    
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get closet items
app.get('/api/user/closet', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM closet_items WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Add closet item
app.post('/api/user/closet', authenticateToken, async (req, res) => {
  const { name, category, color, fabric, fit, brand, details, image_url, cost } = req.body;
  
  if (!name) {
    return res.status(400).json({ error: 'Item name required' });
  }
  
  try {
    const result = await pool.query(
      `INSERT INTO closet_items (user_id, name, category, color, fabric, fit, brand, details, image_url, cost)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING *`,
      [req.user.id, name, category, color, fabric, fit, brand, details, image_url, cost]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Update closet item
app.put('/api/user/closet/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const updates = req.body;
  
  try {
    const fields = Object.keys(updates).filter(k => 
      ['name', 'category', 'color', 'fabric', 'fit', 'brand', 'details', 'cost', 'wears'].includes(k)
    );
    if (fields.length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }
    
    const setClause = fields.map((f, i) => `${f} = $${i + 1}`).join(', ');
    const values = fields.map(f => updates[f]);
    
    const result = await pool.query(
      `UPDATE closet_items SET ${setClause} WHERE id = $${fields.length + 1} AND user_id = $${fields.length + 2} RETURNING *`,
      [...values, id, req.user.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Item not found' });
    }
    
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete closet item
app.delete('/api/user/closet/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM closet_items WHERE id = $1 AND user_id = $2 RETURNING id',
      [req.params.id, req.user.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Item not found' });
    }
    
    res.json({ deleted: true, id: result.rows[0].id });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get saved outfits
app.get('/api/user/outfits', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM saved_outfits WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Save outfit
app.post('/api/user/outfits', authenticateToken, async (req, res) => {
  const { name, item_ids, occasion } = req.body;
  
  try {
    const result = await pool.query(
      `INSERT INTO saved_outfits (user_id, name, item_ids, occasion)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [req.user.id, name, item_ids, occasion]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============== ADMIN ENDPOINTS ==============

// Get all users (admin only)
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.email, u.name, u.city, u.created_at, u.last_login,
        COUNT(c.id) as closet_count
      FROM users u
      LEFT JOIN closet_items c ON u.id = c.user_id
      GROUP BY u.id
      ORDER BY u.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user details (admin only)
app.get('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
    const closet = await pool.query('SELECT * FROM closet_items WHERE user_id = $1', [req.params.id]);
    const outfits = await pool.query('SELECT * FROM saved_outfits WHERE user_id = $1', [req.params.id]);
    
    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({
      ...user.rows[0],
      closet: closet.rows,
      outfits: outfits.rows
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get stats (admin only)
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    const users = await pool.query('SELECT COUNT(*) FROM users');
    const items = await pool.query('SELECT COUNT(*) FROM closet_items');
    const outfits = await pool.query('SELECT COUNT(*) FROM saved_outfits');
    const recentUsers = await pool.query("SELECT COUNT(*) FROM users WHERE created_at > NOW() - INTERVAL '7 days'");
    
    res.json({
      totalUsers: parseInt(users.rows[0].count),
      totalItems: parseInt(items.rows[0].count),
      totalOutfits: parseInt(outfits.rows[0].count),
      newUsersThisWeek: parseInt(recentUsers.rows[0].count)
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============== AI ENDPOINTS ==============

app.post('/api/identify', async (req, res) => {
  const { image, mimeType } = req.body;

  if (!image) return res.status(400).json({ error: 'Missing image field.' });
  if (!mimeType || !mimeType.startsWith('image/')) {
    return res.status(400).json({ error: 'Invalid or missing mimeType.' });
  }
  if (!process.env.ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'Server is not configured.' });
  }

  const prompt = `You are an expert fashion analyst. Analyze this clothing item photo.

Return ONLY a valid JSON object (no markdown, no backticks):
{
  "name": "descriptive name like 'Navy Blue Crew Neck Sweater'",
  "cat": "one of: Tops | Bottoms | Outerwear | Footwear | Accessories | Suiting | Other",
  "color": "primary color(s)",
  "fabric": "material if visible, else empty string",
  "fit": "fit style if applicable, else empty string",
  "brand": "brand if visible, else empty string",
  "details": "one sentence, max 15 words",
  "confidence": "high, medium, or low"
}`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 300,
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'base64', media_type: mimeType, data: image } },
            { type: 'text', text: prompt }
          ]
        }]
      })
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      return res.status(502).json({ error: err.error?.message || 'AI error' });
    }

    const data = await response.json();
    const raw = data.content?.[0]?.text || '';
    const match = raw.match(/\{[\s\S]*\}/);
    
    if (!match) return res.status(502).json({ error: 'Unexpected AI response' });

    const result = JSON.parse(match[0]);
    res.json({
      name: result.name || 'Clothing Item',
      cat: result.cat || 'Other',
      color: result.color || '',
      fabric: result.fabric || '',
      fit: result.fit || '',
      brand: result.brand || '',
      details: result.details || '',
      confidence: result.confidence || 'medium'
    });

  } catch (err) {
    console.error('Identify error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============== OUTFIT VIBE ANALYSIS ==============
app.post('/api/analyze-vibe', async (req, res) => {
  const { image, mimeType } = req.body;

  if (!image) return res.status(400).json({ error: 'Missing image field.' });
  if (!mimeType || !mimeType.startsWith('image/')) {
    return res.status(400).json({ error: 'Invalid or missing mimeType.' });
  }
  if (!process.env.ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'Server is not configured.' });
  }

  const prompt = `Analyze this outfit or fashion photo. Identify the overall style vibe.

Return ONLY a valid JSON object (no markdown, no backticks):
{
  "vibe": "2-4 word style name like 'Casual Street', 'Business Sharp', 'Preppy Classic', 'Minimalist Modern'",
  "description": "One sentence describing the aesthetic and feel",
  "keywords": ["array", "of", "5-8", "style", "keywords", "for", "matching", "items"],
  "colors": ["main", "colors", "seen"],
  "formality": "one of: casual, smart-casual, business-casual, business",
  "pieces": ["types", "of", "clothing", "visible", "like", "blazer", "jeans", "sneakers"]
}`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 400,
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'base64', media_type: mimeType, data: image } },
            { type: 'text', text: prompt }
          ]
        }]
      })
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      return res.status(502).json({ error: err.error?.message || 'AI error' });
    }

    const data = await response.json();
    const raw = data.content?.[0]?.text || '';
    const match = raw.match(/\{[\s\S]*\}/);
    
    if (!match) return res.status(502).json({ error: 'Unexpected AI response' });

    const result = JSON.parse(match[0]);
    res.json({
      vibe: result.vibe || 'Stylish Look',
      description: result.description || 'A great outfit',
      keywords: result.keywords || [],
      colors: result.colors || [],
      formality: result.formality || 'smart-casual',
      pieces: result.pieces || []
    });

  } catch (err) {
    console.error('Vibe analysis error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============== BACKGROUND REMOVAL ==============
// Uses sharp for image processing - no external API needed!
app.post('/api/remove-bg', async (req, res) => {
  const { image, mimeType } = req.body;

  if (!image) return res.status(400).json({ error: 'Missing image field.' });

  try {
    const sharp = require('sharp');
    
    // Convert base64 to buffer
    const imageBuffer = Buffer.from(image, 'base64');
    
    // Get image metadata and pixels
    const img = sharp(imageBuffer);
    const metadata = await img.metadata();
    const { width, height } = metadata;
    
    // Resize if too large (for performance)
    const maxSize = 800;
    let processWidth = width;
    let processHeight = height;
    if (width > maxSize || height > maxSize) {
      if (width > height) {
        processWidth = maxSize;
        processHeight = Math.round(height * maxSize / width);
      } else {
        processHeight = maxSize;
        processWidth = Math.round(width * maxSize / height);
      }
    }
    
    // Get raw pixel data
    const { data, info } = await img
      .resize(processWidth, processHeight)
      .ensureAlpha()
      .raw()
      .toBuffer({ resolveWithObject: true });
    
    // Sample corners to find background color
    const getPixel = (x, y) => {
      const idx = (y * info.width + x) * 4;
      return { r: data[idx], g: data[idx+1], b: data[idx+2], a: data[idx+3] };
    };
    
    const corners = [
      getPixel(0, 0),
      getPixel(info.width - 1, 0),
      getPixel(0, info.height - 1),
      getPixel(info.width - 1, info.height - 1)
    ];
    
    // Average corner colors
    let bgR = 0, bgG = 0, bgB = 0;
    corners.forEach(c => { bgR += c.r; bgG += c.g; bgB += c.b; });
    bgR = Math.round(bgR / 4);
    bgG = Math.round(bgG / 4);
    bgB = Math.round(bgB / 4);
    
    const bgBrightness = (bgR + bgG + bgB) / 3;
    
    // Only process if background is light (white/gray)
    if (bgBrightness > 180) {
      const tolerance = 45;
      const newData = Buffer.from(data);
      
      for (let i = 0; i < newData.length; i += 4) {
        const r = newData[i];
        const g = newData[i + 1];
        const b = newData[i + 2];
        
        const diffR = Math.abs(r - bgR);
        const diffG = Math.abs(g - bgG);
        const diffB = Math.abs(b - bgB);
        
        // Check if pixel is similar to background
        if (diffR < tolerance && diffG < tolerance && diffB < tolerance) {
          // Make transparent
          newData[i + 3] = 0;
        }
      }
      
      // Convert back to PNG
      const resultBuffer = await sharp(newData, {
        raw: {
          width: info.width,
          height: info.height,
          channels: 4
        }
      })
      .png()
      .toBuffer();
      
      const resultBase64 = resultBuffer.toString('base64');
      
      return res.json({ 
        image: resultBase64, 
        mimeType: 'image/png',
        processed: true 
      });
    }
    
    // Background not light enough - return original
    res.json({ image: image, processed: false });

  } catch (err) {
    console.error('Remove-bg error:', err);
    // Return original image on error
    res.json({ image: image, processed: false, error: 'Processing failed' });
  }
});

app.post('/api/coach', async (req, res) => {
  const { messages, systemContext } = req.body;

  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: 'Missing messages array.' });
  }
  if (!process.env.ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'Server is not configured.' });
  }

  const systemPrompt = [
    'You are Alex, a personal stylist inside the Vestiary wardrobe app.',
    'Be direct, specific, and helpful. Keep responses concise.',
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
        model: 'claude-sonnet-4-20250514',
        max_tokens: 600,
        system: systemPrompt,
        messages: messages.slice(-10)
      })
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      return res.status(502).json({ error: err.error?.message || 'AI error' });
    }

    const data = await response.json();
    res.json({ reply: data.content?.[0]?.text || '' });

  } catch (err) {
    console.error('Coach error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============== START SERVER ==============

app.listen(PORT, async () => {
  console.log('');
  console.log('  ✦ Vestiary Backend v2.0');
  console.log('  → Port:', PORT);
  console.log('  → Database:', process.env.DATABASE_URL ? '✓ configured' : '✗ MISSING');
  console.log('  → API key:', process.env.ANTHROPIC_API_KEY ? '✓ configured' : '✗ MISSING');
  console.log('');
  
  if (process.env.DATABASE_URL) {
    await initDB();
  }
});
