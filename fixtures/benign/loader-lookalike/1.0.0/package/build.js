// SYNTHETIC FIXTURE — benign build tool: compresses OUTPUT and runs a fixed system binary.
const fs = require('fs'), zlib = require('zlib'), cp = require('child_process');
const data = fs.readFileSync('src/index.js');
fs.writeFileSync('dist/index.js.gz', zlib.gzipSync(data));
cp.execFileSync('/usr/bin/tar', ['-czf', 'dist.tgz', 'dist']);
