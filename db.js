/** estate-saas — repository layer.
 *  Mongo in production (MONGODB_URI), in-memory for tests/dev.
 *  Deliberately narrow interface: every call is collection + equality filter.
 */
const COLLECTIONS = ['agencies', 'users', 'properties', 'tenants', 'payments', 'sessions', 'audit'];

function createRepo() {
  let mode = 'memory';
  let db = null;
  const mem = {};
  for (const c of COLLECTIONS) mem[c] = [];

  const matches = (doc, filter) =>
    Object.entries(filter || {}).every(([k, v]) => {
      if (v && typeof v === 'object' && Array.isArray(v.$in)) return v.$in.includes(doc[k]);
      return doc[k] === v;
    });

  async function init({ mongoUri, dbName } = {}) {
    const uri = mongoUri || process.env.MONGODB_URI;
    if (uri) {
      try {
        const { MongoClient } = require('mongodb');
        const client = new MongoClient(uri, { serverSelectionTimeoutMS: 4000 });
        await client.connect();
        db = client.db(dbName || process.env.MONGODB_DB || 'estate_saas');
        mode = 'mongo';
        await db.collection('users').createIndex({ email: 1 }, { unique: true });
        await db.collection('sessions').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
        await db.collection('payments').createIndex({ agencyId: 1, provider: 1, reference: 1 }, { unique: true, sparse: true });
        await db.collection('audit').createIndex({ agencyId: 1, at: -1 });
      } catch (e) {
        console.error('[db] Mongo unavailable, using memory store:', e.message);
        db = null; mode = 'memory';
      }
    }
    return mode;
  }

  async function insert(coll, doc) {
    const record = { ...doc };
    if (!record._id) record._id = require('crypto').randomBytes(12).toString('hex');
    if (mode === 'mongo') { await db.collection(coll).insertOne(record); return record; }
    mem[coll].push(record);
    return record;
  }

  async function find(coll, filter = {}) {
    if (mode === 'mongo') return db.collection(coll).find(filter).toArray();
    return mem[coll].filter((d) => matches(d, filter));
  }

  async function findOne(coll, filter = {}) {
    if (mode === 'mongo') return db.collection(coll).findOne(filter);
    return mem[coll].find((d) => matches(d, filter)) || null;
  }

  async function update(coll, filter, patch) {
    if (mode === 'mongo') {
      const r = await db.collection(coll).findOneAndUpdate(filter, { $set: patch }, { returnDocument: 'after' });
      return r && (r.value || r);
    }
    const doc = mem[coll].find((d) => matches(d, filter));
    if (!doc) return null;
    Object.assign(doc, patch);
    return doc;
  }

  async function remove(coll, filter) {
    if (mode === 'mongo') { await db.collection(coll).deleteMany(filter); return; }
    mem[coll] = mem[coll].filter((d) => !matches(d, filter));
  }

  async function close() {
    if (mode === 'mongo' && db) { try { await db.client.close(); } catch {} }
  }

  return { init, insert, find, findOne, update, remove, close, mode: () => mode, COLLECTIONS };
}

module.exports = { createRepo, COLLECTIONS };
