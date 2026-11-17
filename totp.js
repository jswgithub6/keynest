#!/usr/bin/env node
/**
 * KeyNest TOTP — 无状态 TOTP 验证码生成器 (RFC 6238)
 *
 * 不保存任何数据:每次输入 setup key(或 otpauth:// 链接),输出当前验证码。
 * 零依赖,仅用 Node 内置 crypto。
 *
 * 用法:
 *   node totp.js              交互输入 key(输入不回显),输出验证码
 *   node totp.js -c           同上,并复制验证码到剪贴板
 *   node totp.js --selftest   用 RFC 6238 官方测试向量校验算法
 *   pbpaste | node totp.js    从管道读入 key
 *
 * 注意:不支持把 key 写在命令行参数里——那样会留在 shell 历史和进程列表中。
 */
'use strict';

const crypto = require('crypto');
const { execSync } = require('child_process');

// ---------- 核心算法 ----------

function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = input.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  if (!clean) throw new Error('key 为空');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) throw new Error(`key 含非法字符 "${ch}"(Base32 只允许 A-Z 和 2-7)`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function hotp(keyBuf, counter, digits = 6, algorithm = 'sha1') {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac(algorithm, keyBuf).update(msg).digest();
  const off = h[h.length - 1] & 0x0f;
  const bin = h.readUInt32BE(off) & 0x7fffffff;
  return String(bin % 10 ** digits).padStart(digits, '0');
}

function totp(keyBuf, { timeSec = Date.now() / 1000, period = 30, digits = 6, algorithm = 'sha1' } = {}) {
  return hotp(keyBuf, Math.floor(timeSec / period), digits, algorithm);
}

// ---------- 输入解析:裸 key 或 otpauth:// 链接 ----------

function parseInput(raw) {
  const s = raw.trim();
  if (s.toLowerCase().startsWith('otpauth://')) {
    const url = new URL(s);
    if (url.host.toLowerCase() !== 'totp') throw new Error('只支持 otpauth://totp/ 类型');
    const p = url.searchParams;
    const secret = p.get('secret');
    if (!secret) throw new Error('otpauth 链接里没有 secret 参数');
    return {
      key: base32Decode(secret),
      label: decodeURIComponent(url.pathname.slice(1)),
      digits: Number(p.get('digits') || 6),
      period: Number(p.get('period') || 30),
      algorithm: (p.get('algorithm') || 'SHA1').toLowerCase(),
    };
  }
  return { key: base32Decode(s), label: '', digits: 6, period: 30, algorithm: 'sha1' };
}

// ---------- 输入:隐藏回显 / 管道 ----------

function readHidden(prompt) {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    process.stderr.write(prompt);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let buf = '';
    let count = 0;
    const done = (err) => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.removeListener('data', onData);
      process.stderr.write('\n');
      err ? reject(err) : resolve(buf);
    };
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') return done();
        if (ch === '\u0003') return done(new Error('已取消'));        // Ctrl-C
        if (ch === '\u007f' || ch === '\b') {                           // 退格
          if (buf.length) { buf = buf.slice(0, -1); count--; process.stderr.write('\b \b'); }
          continue;
        }
        buf += ch;
        count++;
        process.stderr.write('*');
      }
    };
    stdin.on('data', onData);
  });
}

function readPipe() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (data += c));
    process.stdin.on('end', () => resolve(data));
  });
}

function copyToClipboard(text) {
  const cmd = process.platform === 'darwin' ? 'pbcopy'
    : process.platform === 'win32' ? 'clip'
    : 'xclip -selection clipboard';
  try {
    execSync(cmd, { input: text, stdio: ['pipe', 'ignore', 'ignore'] });
    return true;
  } catch {
    return false;
  }
}

// ---------- 自检:RFC 6238 附录 B 测试向量 ----------

function selftest() {
  const keys = {
    sha1: Buffer.from('12345678901234567890'),
    sha256: Buffer.from('12345678901234567890123456789012'),
    sha512: Buffer.from('1234567890123456789012345678901234567890123456789012345678901234'),
  };
  const vectors = [
    [59, '94287082', '46119246', '90693936'],
    [1111111109, '07081804', '68084774', '25091201'],
    [1111111111, '14050471', '67062674', '99943326'],
    [1234567890, '89005924', '91819424', '93441116'],
    [2000000000, '69279037', '90698825', '38618901'],
    [20000000000, '65353130', '77737706', '47863826'],
  ];
  let fail = 0;
  for (const [t, ...expected] of vectors) {
    ['sha1', 'sha256', 'sha512'].forEach((alg, i) => {
      const got = totp(keys[alg], { timeSec: t, digits: 8, algorithm: alg });
      const ok = got === expected[i];
      if (!ok) fail++;
      console.log(`${ok ? 'PASS' : 'FAIL'}  T=${String(t).padEnd(11)} ${alg.padEnd(6)} expected=${expected[i]} got=${got}`);
    });
  }
  // Base32 解码校验:"12345678901234567890" 的 Base32 形式
  const b32ok = base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ').equals(keys.sha1);
  if (!b32ok) fail++;
  console.log(`${b32ok ? 'PASS' : 'FAIL'}  base32 decode`);
  console.log(fail ? `\n${fail} 项失败` : '\n全部通过');
  process.exit(fail ? 1 : 0);
}

// ---------- 主流程 ----------

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--selftest')) return selftest();
  if (args.includes('-h') || args.includes('--help')) {
    console.log('用法: node totp.js [-c]   |   node totp.js --selftest');
    return;
  }
  const stray = args.filter((a) => !a.startsWith('-'));
  if (stray.length) {
    console.error('不要把 key 写在命令行参数里(会留在 shell 历史)。直接运行后按提示输入。');
    process.exit(2);
  }

  const raw = process.stdin.isTTY ? await readHidden('Setup key 或 otpauth 链接: ') : await readPipe();
  const cfg = parseInput(raw);

  const now = Date.now() / 1000;
  const code = totp(cfg.key, { timeSec: now, ...cfg });
  const remain = cfg.period - Math.floor(now % cfg.period);

  if (cfg.label) console.log(`账号: ${cfg.label}`);
  console.log(`验证码: ${code}   (剩余 ${remain}s)`);
  if (remain <= 5) {
    const next = totp(cfg.key, { timeSec: now + cfg.period, ...cfg });
    console.log(`下一个: ${next}   (即将切换,可等几秒用这个)`);
  }
  if (args.includes('-c')) {
    console.log(copyToClipboard(code) ? '已复制到剪贴板' : '复制失败(剪贴板工具不可用)');
  }
}

main().catch((e) => {
  console.error(`错误: ${e.message}`);
  process.exit(1);
});
