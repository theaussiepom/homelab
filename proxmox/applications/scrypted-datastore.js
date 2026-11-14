'use strict';
// Verify software decoder selection before the upstream server command starts.
// Inspect mode is restricted to a disposable copy. No plugin code is imported.
const fs = require('node:fs');
const crypto = require('node:crypto');

const allowed = new Set(['none', 'Default', 'Software', 'Hardware', 'vaapi', 'cuda',
  'vulkan', 'qsv', 'videotoolbox', 'CPU', 'GPU', 'AUTO', false, true, null]);
const fields = new Set(['hwaccel', 'hwscalar', 'openclMotion']);
function parse(value) {
  if (typeof value !== 'string') return value;
  try { return JSON.parse(value); } catch { return value; }
}
function collect(value, path, output, depth = 0) {
  if (depth > 12) throw new Error('nested_data_bound');
  const decoded = parse(value);
  if (!decoded || typeof decoded !== 'object') return;
  if (Array.isArray(decoded)) {
    if (decoded.length > 1000) throw new Error('array_bound');
    decoded.forEach((item, i) => collect(item, [...path, i], output, depth + 1));
    return;
  }
  for (const [key, item] of Object.entries(decoded)) {
    if (fields.has(key)) {
      if (output.length >= 10000) throw new Error('observation_bound');
      // StorageSettings preserves string enum values literally. JSON-decoding
      // "null" or a quoted enum here could admit a different effective value.
      const selected = key === 'openclMotion' ? parse(item) : item;
      output.push({ path: [...path, key], value: allowed.has(selected) ? selected : 'unrecognised' });
    } else collect(item, [...path, key], output, depth + 1);
  }
}
function verify(decoderDevices, observations) {
  const global = observations.filter(x => x.global_decoder);
  if (decoderDevices !== 1 || !global.some(x => x.field === 'hwaccel' && x.value === 'none')
      || !global.some(x => x.field === 'hwscalar' && x.value === 'Software')
      || observations.some(x => x.field === 'hwaccel' && !['none', 'Default', null].includes(x.value)
        || x.field === 'hwscalar' && !['Software', 'Default', null].includes(x.value)
        || x.field === 'openclMotion' && ![false, null].includes(x.value)))
    throw new Error('software_decoder_required');
}
async function main() {
  const mode = process.argv[2];
  if (!['verify', 'inspect'].includes(mode)) throw new Error('mode_required');
  if (mode === 'inspect' && process.env.SCRYPTED_LEVELDB_DISPOSABLE_COPY !== 'yes')
    throw new Error('disposable_copy_required');
  const directory = mode === 'verify' ? '/server/volume/scrypted.db' : '/leveldb-copy';
  if (!fs.lstatSync(directory).isDirectory() || !fs.existsSync(directory + '/CURRENT'))
    throw new Error('existing_copy_required');
  const { Level } = require('/server/node_modules/level');
  const db = new Level(directory, { createIfMissing: false,
    keyEncoding: 'buffer', valueEncoding: 'buffer' });
  let records = 0, bytes = 0, decoderDevices = 0;
  const observations = [], packages = [];
  try {
    await db.open();
    for await (const [key, raw] of db.iterator()) {
      if (++records > 100000 || key.length > 1048576 || raw.length > 67108864)
        throw new Error('record_bound');
      bytes += key.length + raw.length;
      if (bytes > 536870912) throw new Error('database_bound');
      let doc;
      try { doc = JSON.parse(raw.toString('utf8')); } catch { continue; }
      if (doc?._documentType === 'Plugin' &&
          /^@scrypted\/[a-z0-9-]+$/.test(doc.packageJson?.name) &&
          /^[0-9A-Za-z.+-]{1,80}$/.test(doc.packageJson?.version))
        packages.push({ name: doc.packageJson.name, version: doc.packageJson.version });
      if (doc?._documentType !== 'PluginDevice' || !doc.storage || typeof doc.storage !== 'object') continue;
      const globalDecoder = doc.pluginId === '@scrypted/nvr' && doc.nativeId === 'decoder';
      if (globalDecoder) decoderDevices++;
      const selected = [];
      collect(doc.storage, [], selected);
      for (const item of selected) {
        if (observations.length >= 10000) throw new Error('observation_bound');
        // Field locations and device identity are hashed; unknown field values
        // are never printed. Credentials and unrelated settings never escape.
        const location = crypto.createHash('sha256').update(key)
          .update(JSON.stringify(item.path)).digest('hex');
        observations.push({ location_sha256: location, global_decoder: globalDecoder,
          field: item.path[item.path.length - 1], value: item.value });
      }
    }
  } finally { await db.close(); }
  if (!records || observations.length > 10000) throw new Error('empty_or_unbounded_observations');
  if (mode === 'verify') {
    verify(decoderDevices, observations);
    console.log(JSON.stringify({status:'passed', software_decoder_verified:true, plugin_code_loaded:false}));
  } else {
    console.log(JSON.stringify({ status: 'passed', records, logical_bytes: bytes,
      global_decoder_devices: decoderDevices, packages, observations,
      source_opened: false, plugin_code_loaded: false, settings_changed: false }));
  }
}
module.exports = { collect, verify };
if (require.main === module) main().catch(() => {
  console.log(JSON.stringify({ status: 'blocked', reason: 'scrypted_datastore_check_failed' }));
  process.exitCode = 1;
});
