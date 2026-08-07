import { encryptPayload, decryptPayload, armorPayload, unarmorPayload } from './src/crypto-core.mjs';
import { readFile, writeFile } from 'node:fs/promises';

const PARAMS = { m: 8192, t: 2, p: 1 };   // ligero, para probar rápido
const [cmd, password, pepper, arg] = process.argv.slice(2);

if (cmd === 'encrypt') {
  const bytes = await encryptPayload(
    { type: 'text', data: arg },
    password, pepper, null, PARAMS,
  );
  await writeFile('message.ptx', armorPayload(bytes));
  console.log('Written to message.ptx');
}

if (cmd === 'decrypt') {
  const armored = await readFile('message.ptx', 'utf8');
  const bytes = unarmorPayload(armored);
  if (!bytes) throw new Error('No armor block found');
  const result = await decryptPayload(bytes, password, pepper, null);
  console.log(result.data);
}