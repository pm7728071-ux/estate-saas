/** estate-saas — multi-tenant property-management API (foundation slice).
 *  Auth: email + password (scrypt), opaque session tokens (stored hashed).
 *  Isolation: every query is filtered by the session's agencyId. Roles: owner > manager > agent.
 */
const express = require('express');
const crypto = require('crypto');
const { createRepo } = require('./db.js');

const SESSION_TTL_MS = 1000 * 60 * 60 * 12;
const WRITE_ROLES = ['owner', 'manager'];

const hashPassword = (pw) => {
  const salt = crypto.randomBytes(16).toString('hex');
  return 'scrypt:' + salt + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
};
const verifyPassword = (pw, stored) => {
  try {
    const [, salt, hash] = String(stored).split(':');
    const calc = crypto.scryptSync(pw, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(calc, 'hex'), Buffer.from(hash, 'hex'));
  } catch { return false; }
};
const hashToken = (t) => crypto.createHash('sha256').update(t).digest('hex');
const clean = (o, keys) => Object.fromEntries(keys.map((k) => [k, o[k]]));

function createApp(repo) {
  const app = express();
  app.use(express.json({ limit: '32kb' }));
  app.disable('x-powered-by');

  const audit = (agencyId, actorId, action, meta) =>
    repo.insert('audit', { agencyId, actorId, action, meta: meta || {}, at: new Date().toISOString() });

  // ---- auth middleware ----
  const requireAuth = async (req, res, next) => {
    try {
      const header = req.get('authorization') || '';
      const token = header.startsWith('Bearer ') ? header.slice(7) : '';
      if (!token) return res.status(401).json({ error: 'Authentication required' });
      const session = await repo.findOne('sessions', { tokenHash: hashToken(token) });
      if (!session) return res.status(401).json({ error: 'Invalid or expired session' });
      if (new Date(session.expiresAt).getTime() < Date.now()) return res.status(401).json({ error: 'Session expired' });
      const user = await repo.findOne('users', { _id: session.userId });
      if (!user) return res.status(401).json({ error: 'User no longer exists' });
      req.auth = { userId: user._id, agencyId: user.agencyId, role: user.role, email: user.email };
      next();
    } catch (e) { res.status(500).json({ error: 'Auth check failed' }); }
  };

  const requireWrite = (req, res, next) =>
    WRITE_ROLES.includes(req.auth.role) ? next() : res.status(403).json({ error: 'Insufficient role for this action' });

  // ---- health ----
  app.get('/api/health', (req, res) => res.json({ ok: true, service: 'estate-saas', storage: repo.mode(), time: new Date().toISOString() }));

  // ---- agency signup (creates the agency + its first owner) ----
  app.post('/api/agencies', async (req, res) => {
    try {
      const { agencyName, email, password, fullName } = req.body || {};
      if (!agencyName || !email || !password) return res.status(400).json({ error: 'agencyName, email and password are required' });
      if (String(password).length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
      const normalized = String(email).trim().toLowerCase();
      if (await repo.findOne('users', { email: normalized })) return res.status(409).json({ error: 'That email is already registered' });
      const agency = await repo.insert('agencies', { name: String(agencyName).slice(0, 120), createdAt: new Date().toISOString() });
      const user = await repo.insert('users', {
        agencyId: agency._id, email: normalized, fullName: String(fullName || '').slice(0, 120),
        role: 'owner', passHash: hashPassword(String(password)), createdAt: new Date().toISOString(),
      });
      await audit(agency._id, user._id, 'agency.created', { agencyName: agency.name });
      return res.status(201).json({ agency: { id: agency._id, name: agency.name }, user: clean(user, ['_id', 'email', 'role', 'fullName']) });
    } catch (e) { return res.status(500).json({ error: 'Could not create agency' }); }
  });

  // ---- login / logout ----
  app.post('/api/auth/login', async (req, res) => {
    try {
      const { email, password } = req.body || {};
      if (!email || !password) return res.status(400).json({ error: 'email and password are required' });
      const user = await repo.findOne('users', { email: String(email).trim().toLowerCase() });
      if (!user || !verifyPassword(String(password), user.passHash)) return res.status(401).json({ error: 'Invalid credentials' });
      const token = crypto.randomBytes(32).toString('hex');
      await repo.insert('sessions', {
        tokenHash: hashToken(token), userId: user._id, agencyId: user.agencyId,
        createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
      });
      await audit(user.agencyId, user._id, 'auth.login', {});
      return res.json({ token, user: { id: user._id, email: user.email, role: user.role, agencyId: user.agencyId } });
    } catch (e) { return res.status(500).json({ error: 'Login failed' }); }
  });

  app.post('/api/auth/logout', requireAuth, async (req, res) => {
    const header = req.get('authorization') || '';
    await repo.remove('sessions', { tokenHash: hashToken(header.slice(7)) });
    res.json({ ok: true });
  });

  app.get('/api/me', requireAuth, (req, res) => res.json(req.auth));

  // ---- properties (agency-scoped) ----
  app.get('/api/properties', requireAuth, async (req, res) => {
    const rows = await repo.find('properties', { agencyId: req.auth.agencyId });
    res.json(rows.map((r) => clean(r, ['_id', 'name', 'address', 'rentAmount', 'currency', 'createdAt'])));
  });

  app.post('/api/properties', requireAuth, requireWrite, async (req, res) => {
    try {
      const { name, address, rentAmount, currency } = req.body || {};
      if (!name) return res.status(400).json({ error: 'name is required' });
      const amount = Number(rentAmount);
      if (!Number.isFinite(amount) || amount < 0) return res.status(400).json({ error: 'rentAmount must be a non-negative number' });
      const property = await repo.insert('properties', {
        agencyId: req.auth.agencyId, name: String(name).slice(0, 120), address: String(address || '').slice(0, 200),
        rentAmount: amount, currency: String(currency || 'KES').toUpperCase(), createdAt: new Date().toISOString(),
      });
      await audit(req.auth.agencyId, req.auth.userId, 'property.created', { propertyId: property._id });
      res.status(201).json(clean(property, ['_id', 'name', 'address', 'rentAmount', 'currency', 'createdAt']));
    } catch (e) { res.status(500).json({ error: 'Could not create property' }); }
  });

  app.get('/api/properties/:id', requireAuth, async (req, res) => {
    const property = await repo.findOne('properties', { _id: req.params.id, agencyId: req.auth.agencyId });
    if (!property) return res.status(404).json({ error: 'Property not found' });
    res.json(clean(property, ['_id', 'name', 'address', 'rentAmount', 'currency', 'createdAt']));
  });

  // ---- tenants (agency-scoped, property must belong to same agency) ----
  app.get('/api/tenants', requireAuth, async (req, res) => {
    const rows = await repo.find('tenants', { agencyId: req.auth.agencyId });
    res.json(rows.map((r) => clean(r, ['_id', 'name', 'phone', 'propertyId', 'leaseStart', 'createdAt'])));
  });

  app.post('/api/tenants', requireAuth, requireWrite, async (req, res) => {
    try {
      const { name, phone, propertyId, leaseStart } = req.body || {};
      if (!name || !propertyId) return res.status(400).json({ error: 'name and propertyId are required' });
      const property = await repo.findOne('properties', { _id: propertyId, agencyId: req.auth.agencyId });
      if (!property) return res.status(404).json({ error: 'Property not found in your agency' });
      const tenant = await repo.insert('tenants', {
        agencyId: req.auth.agencyId, propertyId, name: String(name).slice(0, 120),
        phone: String(phone || '').slice(0, 40), leaseStart: String(leaseStart || '').slice(0, 40),
        createdAt: new Date().toISOString(),
      });
      await audit(req.auth.agencyId, req.auth.userId, 'tenant.created', { tenantId: tenant._id, propertyId });
      res.status(201).json(clean(tenant, ['_id', 'name', 'phone', 'propertyId', 'leaseStart', 'createdAt']));
    } catch (e) { res.status(500).json({ error: 'Could not create tenant' }); }
  });

  app.get('/api/tenants/:id', requireAuth, async (req, res) => {
    const tenant = await repo.findOne('tenants', { _id: req.params.id, agencyId: req.auth.agencyId });
    if (!tenant) return res.status(404).json({ error: 'Tenant not found' });
    res.json(clean(tenant, ['_id', 'name', 'phone', 'propertyId', 'leaseStart', 'createdAt']));
  });

  // ---- audit (agency-scoped, read-only) ----
  app.get('/api/audit', requireAuth, async (req, res) => {
    const rows = await repo.find('audit', { agencyId: req.auth.agencyId });
    res.json(rows.slice(-200).reverse());
  });

  app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
  return app;
}

module.exports = { createApp };

if (require.main === module) {
  (async () => {
    const repo = createRepo();
    await repo.init({});
    const app = createApp(repo);
    const port = process.env.PORT || 3100;
    app.listen(port, () => console.log('estate-saas listening on ' + port + ' (storage: ' + repo.mode() + ')'));
  })();
}
