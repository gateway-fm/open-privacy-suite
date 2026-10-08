const fs = require('node:fs');
const solc = require('solc');
if (!solc.version().startsWith('0.8.35+')) throw new Error('unexpected Solidity compiler version');
process.stdout.write(solc.compile(fs.readFileSync(0, 'utf8')));
