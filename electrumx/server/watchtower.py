'''Atomic swap watchtower.

A wallet that swaps BTC for MARS normally has to stay online: it must
claim the MARS once the maker reveals the secret on the Bitcoin chain, or
refund its BTC once the timelock passes. The watchtower does both on the
wallet's behalf.

At payment time the wallet hands over transactions it has already
signed: one MARS claim (with 32 zero bytes where the secret belongs) and
up to four BTC refunds at rising fees. Their outputs are fixed by the
wallet's signatures, so the watchtower can only finish the swap the way
the wallet intended. It holds no keys and cannot redirect funds.

Every minute, for each watch:

* Ask Bitcoin Esplora services whether the BTC lockbox is spent. If the
  spending transaction carries the secret (checked by hashing it), put
  the secret into the MARS claim and broadcast it through our daemon.
* Otherwise, once the Bitcoin tip reaches the timelock, post the refund
  and step up to the next higher-fee refund about every six blocks.

Two rules are never broken: the MARS claim is not broadcast without a
secret whose hash160 matches, and a refund is not posted before the
Bitcoin tip reaches its timelock.

Esplora services are not trusted for anything that could cost the user
money without a second opinion. A secret proves itself. "Your refund
confirmed" is only believed when no answering service still reports the
lockbox unspent. A spend we cannot make sense of only delays refunds
for a bounded time.

Watches are stored in SQLite and survive a restart. This module has no
network code of its own beyond the small Esplora client; the daemon and
clock are passed in, so everything can be tested without a server.
'''

import asyncio
import hashlib
import json
import logging
import os
import sqlite3
import time

DAY = 24 * 3600
PROTOCOL_VERSION = 1
MAX_PACKAGE_BYTES = 16 * 1024
MAX_REFUND_TXS = 4
MAX_MONEY = 21_000_000 * 100_000_000 * 1000   # generous for both chains
LOCKTIME_THRESHOLD = 500_000_000              # above this nLockTime is a time
BTC_BLOCK_SECONDS = 600
MARS_BLOCK_SECONDS = 123
ESPLORA_DEFAULT = ('https://mempool.space/api', 'https://blockstream.info/api')
ZERO32 = bytes(32)

WATCHING, CLAIMED, REFUNDING = 'watching', 'claimed', 'refunding'
REFUNDED, EXPIRED, FAILED = 'refunded', 'expired', 'failed'

# Substrings of node replies meaning "the network already has this tx".
ALREADY_KNOWN = ('already in block chain', 'already in chain', 'already-in-mempool',
                 'already in mempool', 'already-known', 'already known',
                 'already have transaction', 'outputs already in utxo set')
FEE_TOO_LOW = ('min relay fee not met', 'mempool min fee not met')
# A refund whose input the network does not have: the contract was never
# funded, or its funding was replaced or spent some other way.
MISSING_INPUTS = ('bad-txns-inputs-missingorspent', 'missing-inputs', 'missing inputs',
                  'missingorspent')
# How long every service must keep saying so before the watch is given up.
ORPHAN_SECONDS = 3 * 3600


class WatchtowerError(Exception):
    '''A request the watchtower refuses; the message is safe to show a user.'''


def _env_int(name, default):
    value = os.environ.get(name)
    return int(value) if value not in (None, '') else default


def enabled_from_env():
    return os.environ.get('WATCHTOWER_ENABLED', '1').strip().lower() not in (
        '0', 'false', 'no', 'off')


# ---------------------------------------------------------------- hashing

def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff


_RMD_R = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8),
    (3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12),
    (1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2),
    (4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13))
_RMD_RP = (
    (5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12),
    (6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2),
    (15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13),
    (8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14),
    (12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11))
_RMD_S = (
    (11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8),
    (7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12),
    (11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5),
    (11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12),
    (9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6))
_RMD_SP = (
    (8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6),
    (9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11),
    (9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5),
    (15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8),
    (8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11))
_RMD_K = (0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e)
_RMD_KP = (0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0)


def _rmd_f(j, x, y, z):
    if j == 0:
        return x ^ y ^ z
    if j == 1:
        return (x & y) | (~x & 0xffffffff & z)
    if j == 2:
        return (x | (~y & 0xffffffff)) ^ z
    if j == 3:
        return (x & z) | (y & (~z & 0xffffffff))
    return x ^ (y | (~z & 0xffffffff))


def ripemd160_py(data):
    '''Pure Python RIPEMD-160. OpenSSL 3 builds often ship without it.'''
    h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
    msg = data + b'\x80' + bytes((55 - len(data)) % 64) + (8 * len(data)).to_bytes(8, 'little')
    for start in range(0, len(msg), 64):
        x = [int.from_bytes(msg[start + 4 * i:start + 4 * i + 4], 'little')
             for i in range(16)]
        a, b, c, d, e = h
        ap, bp, cp, dp, ep = h
        for rnd in range(5):
            for i in range(16):
                t = (a + _rmd_f(rnd, b, c, d) + x[_RMD_R[rnd][i]] + _RMD_K[rnd]) & 0xffffffff
                a, e, d, c, b = e, d, _rol(c, 10), b, (_rol(t, _RMD_S[rnd][i]) + e) & 0xffffffff
                t = (ap + _rmd_f(4 - rnd, bp, cp, dp) + x[_RMD_RP[rnd][i]]
                     + _RMD_KP[rnd]) & 0xffffffff
                ap, ep, dp, cp, bp = (ep, dp, _rol(cp, 10), bp,
                                      (_rol(t, _RMD_SP[rnd][i]) + ep) & 0xffffffff)
        t = (h[1] + c + dp) & 0xffffffff
        h[1] = (h[2] + d + ep) & 0xffffffff
        h[2] = (h[3] + e + ap) & 0xffffffff
        h[3] = (h[4] + a + bp) & 0xffffffff
        h[4] = (h[0] + b + cp) & 0xffffffff
        h[0] = t
    return b''.join(v.to_bytes(4, 'little') for v in h)


def ripemd160(data):
    try:
        return hashlib.new('ripemd160', data).digest()
    except ValueError:
        return ripemd160_py(data)


def sha256(data):
    return hashlib.sha256(data).digest()


def hash160(data):
    return ripemd160(sha256(data))


# ---------------------------------------------------------------- parsing

class ParsedTx:
    '''A strictly parsed transaction. witness_spans[i][j] is the
    (offset, length) of input i's witness item j in the raw bytes.'''
    __slots__ = ('raw', 'version', 'inputs', 'outputs', 'witnesses',
                 'witness_spans', 'locktime', 'txid', 'segwit')


def _malformed():
    return WatchtowerError('malformed transaction')


def parse_tx(raw, max_inputs=10_000, max_outputs=10_000):
    '''Parse a raw transaction, requiring every byte to be accounted for.
    Raises WatchtowerError on anything unexpected.'''
    n = len(raw)
    pos = 0

    def take(count):
        nonlocal pos
        if count < 0 or pos + count > n:
            raise _malformed()
        chunk = raw[pos:pos + count]
        pos += count
        return chunk

    def uint(count):
        return int.from_bytes(take(count), 'little')

    def varint():
        first = uint(1)
        if first < 0xfd:
            return first
        return uint({0xfd: 2, 0xfe: 4, 0xff: 8}[first])

    tx = ParsedTx()
    tx.raw = raw
    tx.version = uint(4)
    tx.segwit = n > 6 and raw[4] == 0 and raw[5] == 1
    if tx.segwit:
        take(2)
    body_start = pos
    count = varint()
    if not 0 < count <= max_inputs:
        raise _malformed()
    tx.inputs = []
    for _ in range(count):
        prev_hash = take(32)[::-1].hex()
        prev_idx = uint(4)
        script_sig = take(varint())
        tx.inputs.append((prev_hash, prev_idx, script_sig, uint(4)))
    count = varint()
    if not 0 < count <= max_outputs:
        raise _malformed()
    tx.outputs = []
    for _ in range(count):
        value = uint(8)
        tx.outputs.append((value, take(varint())))
    body_end = pos
    tx.witnesses = []
    tx.witness_spans = []
    if tx.segwit:
        for _ in tx.inputs:
            items, spans = [], []
            item_count = varint()
            if item_count > 1000:
                raise _malformed()
            for _ in range(item_count):
                length = varint()
                spans.append((pos, length))
                items.append(take(length))
            tx.witnesses.append(items)
            tx.witness_spans.append(spans)
    else:
        tx.witnesses = [[] for _ in tx.inputs]
        tx.witness_spans = [[] for _ in tx.inputs]
    locktime_raw = take(4)
    tx.locktime = int.from_bytes(locktime_raw, 'little')
    if pos != n:
        raise _malformed()
    stripped = raw[:4] + raw[body_start:body_end] + locktime_raw
    tx.txid = sha256(sha256(stripped))[::-1].hex()
    return tx


def parse_htlc_script(script):
    '''Return (hash160, recipient_pubkey, locktime, sender_pubkey) for a
    script that matches the swap HTLC template exactly, else raise.'''
    bad = WatchtowerError('htlc_script is not the expected swap script')
    if len(script) < 97 or script[:3] != b'\x63\xa9\x14':
        raise bad
    h160 = script[3:23]
    if script[23:25] != b'\x88\x21':
        raise bad
    recipient = script[25:58]
    if script[58:60] != b'\xac\x67':
        raise bad
    push = script[60]
    if not 1 <= push <= 4:
        raise bad
    number = script[61:61 + push]
    rest = script[61 + push:]
    if len(number) != push or len(rest) != 38:
        raise bad
    if rest[:3] != b'\xb1\x75\x21' or rest[36:] != b'\xac\x68':
        raise bad
    sender = rest[3:36]
    if recipient[0] not in (2, 3) or sender[0] not in (2, 3):
        raise bad
    # A positive, minimally encoded script number.
    if number[-1] & 0x80:
        raise bad
    if number[-1] == 0 and (push == 1 or not number[-2] & 0x80):
        raise bad
    locktime = int.from_bytes(number, 'little')
    # 1..16 would have to be OP_1..OP_16; heights that low aren't real anyway.
    if not 16 < locktime < LOCKTIME_THRESHOLD:
        raise bad
    return h160, recipient, locktime, sender


def p2wsh_script(witness_script):
    return b'\x00\x20' + sha256(witness_script)


def watch_id_for(btc_txid, btc_vout, payment_hash160):
    text = f'{btc_txid}:{btc_vout}:{payment_hash160}'
    return hashlib.sha256(text.encode('ascii')).hexdigest()


def find_preimage(tx, payment_hash160):
    '''Return a 32-byte witness item of tx whose hash160 matches, or None.'''
    for items in tx.witnesses:
        for item in items:
            if len(item) == 32 and hash160(item) == payment_hash160:
                return item
    return None


# ---------------------------------------------------------------- validation

def _hex(value, name, exact=None, max_bytes=None):
    if not isinstance(value, str):
        raise WatchtowerError(f'{name} must be a hex string')
    if exact is not None and len(value) != 2 * exact:
        raise WatchtowerError(f'{name} must be {exact} bytes of hex')
    if max_bytes is not None and len(value) > 2 * max_bytes:
        raise WatchtowerError(f'{name} is too long')
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise WatchtowerError(f'{name} must be a hex string') from None
    if not raw or raw.hex() != value.lower():
        raise WatchtowerError(f'{name} must be a hex string')
    return raw


def _int(value, name, low, high):
    if isinstance(value, bool) or not isinstance(value, int):
        raise WatchtowerError(f'{name} must be an integer')
    if not low <= value <= high:
        raise WatchtowerError(f'{name} is out of range')
    return value


def _side(package, name, tx_field):
    side = package.get(name)
    if not isinstance(side, dict):
        raise WatchtowerError(f'{name} must be an object')
    expected = {'htlc_script', 'funding_txid', 'funding_vout', 'funding_value',
                'locktime', tx_field}
    if set(side) != expected:
        raise WatchtowerError(f'{name} has missing or unexpected fields')
    script = _hex(side['htlc_script'], f'{name}.htlc_script', max_bytes=128)
    return {
        'htlc_script': script,
        'funding_txid': _hex(side['funding_txid'], f'{name}.funding_txid', exact=32).hex(),
        'funding_vout': _int(side['funding_vout'], f'{name}.funding_vout', 0, 0xffffffff),
        'funding_value': _int(side['funding_value'], f'{name}.funding_value', 1, MAX_MONEY),
        'locktime': _int(side['locktime'], f'{name}.locktime', 1, LOCKTIME_THRESHOLD - 1),
    }


def _single_spend(raw, side, what):
    '''Parse a pre-signed tx and check the parts common to claim and refund.'''
    try:
        tx = parse_tx(raw, max_inputs=1, max_outputs=1)
    except WatchtowerError:
        raise WatchtowerError(f'{what} is not a valid single-input, '
                              'single-output transaction') from None
    if not tx.segwit:
        raise WatchtowerError(f'{what} must be a segwit transaction')
    prev_hash, prev_idx, script_sig, _sequence = tx.inputs[0]
    if (prev_hash, prev_idx) != (side['funding_txid'], side['funding_vout']):
        raise WatchtowerError(f'{what} does not spend the funding output')
    if script_sig:
        raise WatchtowerError(f'{what} must have an empty scriptSig')
    value, script_pubkey = tx.outputs[0]
    if not 0 < value <= side['funding_value']:
        raise WatchtowerError(f'{what} output value is not within the funding value')
    if not 0 < len(script_pubkey) <= 64:
        raise WatchtowerError(f'{what} has an unusual output script')
    return tx


def validate_package(package):
    '''Check a registration package completely and return the watch record
    core (no client or timing data). Raises WatchtowerError if anything is off.'''
    if not isinstance(package, dict):
        raise WatchtowerError('package must be an object')
    try:
        size = len(json.dumps(package))
    except (TypeError, ValueError, RecursionError):
        raise WatchtowerError('package is not valid') from None
    if size > MAX_PACKAGE_BYTES:
        raise WatchtowerError('package is too large')
    if set(package) != {'version', 'payment_hash160', 'btc', 'mars'}:
        raise WatchtowerError('package has missing or unexpected fields')
    if isinstance(package['version'], bool) or package['version'] != PROTOCOL_VERSION:
        raise WatchtowerError('unsupported watchtower package version')
    h160 = _hex(package['payment_hash160'], 'payment_hash160', exact=20)

    btc = _side(package, 'btc', 'refund_txs')
    mars = _side(package, 'mars', 'claim_tx')
    for name, side in (('btc', btc), ('mars', mars)):
        script_h160, _recipient, locktime, _sender = parse_htlc_script(side['htlc_script'])
        if script_h160 != h160:
            raise WatchtowerError(f'{name}.htlc_script does not contain payment_hash160')
        if locktime != side['locktime']:
            raise WatchtowerError(f'{name}.locktime does not match its htlc_script')

    refunds = package['btc']['refund_txs']
    if not isinstance(refunds, list) or not 1 <= len(refunds) <= MAX_REFUND_TXS:
        raise WatchtowerError(f'btc.refund_txs must hold 1 to {MAX_REFUND_TXS} transactions')
    refund_hex, refund_txids, last_value = [], [], None
    for n, item in enumerate(refunds):
        what = f'refund_txs[{n}]'
        tx = _single_spend(_hex(item, what, max_bytes=1024), btc, what)
        if tx.locktime != btc['locktime']:
            raise WatchtowerError(f'{what} nLockTime must equal btc.locktime')
        if tx.inputs[0][3] >= 0xffffffff:
            raise WatchtowerError(f'{what} input sequence must enable the timelock')
        witness = tx.witnesses[0]
        if len(witness) != 3 or witness[1] != b'' or witness[2] != btc['htlc_script']:
            raise WatchtowerError(f'{what} does not have a refund witness')
        if not witness[0]:
            raise WatchtowerError(f'{what} is not signed')
        value = tx.outputs[0][0]
        if last_value is not None and value > last_value:
            raise WatchtowerError('btc.refund_txs must be in ascending fee order')
        if tx.txid in refund_txids:
            raise WatchtowerError('btc.refund_txs contains a duplicate')
        last_value = value
        refund_hex.append(tx.raw.hex())
        refund_txids.append(tx.txid)

    claim = _single_spend(_hex(package['mars']['claim_tx'], 'mars.claim_tx', max_bytes=1024),
                          mars, 'claim_tx')
    witness = claim.witnesses[0]
    if (len(witness) != 4 or witness[1] != ZERO32 or witness[2] != b'\x01'
            or witness[3] != mars['htlc_script']):
        raise WatchtowerError('claim_tx witness must be [signature, 32 zero bytes, 01, '
                              'htlc_script]')
    if not witness[0]:
        raise WatchtowerError('claim_tx is not signed')

    canonical = {
        'version': PROTOCOL_VERSION,
        'payment_hash160': h160.hex(),
        'btc': dict(btc, htlc_script=btc['htlc_script'].hex(), refund_txs=refund_hex),
        'mars': dict(mars, htlc_script=mars['htlc_script'].hex(), claim_tx=claim.raw.hex()),
    }
    return {
        'watch_id': watch_id_for(btc['funding_txid'], btc['funding_vout'], h160.hex()),
        'package': canonical,
        'refund_txids': refund_txids,
        'claim_txid': claim.txid,
        'claim_preimage_offset': claim.witness_spans[0][1][0],
    }


def build_claim(record, preimage):
    '''The registered claim with the placeholder replaced by the secret.
    Refuses unless the secret hashes to the watch's payment hash.'''
    if len(preimage) != 32 or hash160(preimage).hex() != record['package']['payment_hash160']:
        raise ValueError('preimage does not match payment hash')
    raw = bytes.fromhex(record['package']['mars']['claim_tx'])
    offset = record['claim_preimage_offset']
    if raw[offset:offset + 32] != ZERO32:
        raise ValueError('claim placeholder not where expected')
    return (raw[:offset] + preimage + raw[offset + 32:]).hex()


# ---------------------------------------------------------------- storage

class WatchStore:
    '''Watch records in a small SQLite file. Each write is one committed
    transaction, so a crash leaves either the old or the new record.'''

    def __init__(self, path):
        self.path = path
        self.conn = sqlite3.connect(path or ':memory:')
        if path:
            self.conn.execute('PRAGMA journal_mode=WAL')
            self.conn.execute('PRAGMA synchronous=FULL')
        self.conn.execute('CREATE TABLE IF NOT EXISTS watches '
                          '(watch_id TEXT PRIMARY KEY, record TEXT NOT NULL)')
        self.conn.commit()

    def load(self):
        records = {}
        for watch_id, text in self.conn.execute('SELECT watch_id, record FROM watches'):
            try:
                record = json.loads(text)
                if record['watch_id'] == watch_id:
                    records[watch_id] = record
            except (ValueError, KeyError, TypeError):
                continue
        return records

    def save(self, record):
        with self.conn:
            self.conn.execute('INSERT OR REPLACE INTO watches (watch_id, record) VALUES (?, ?)',
                              (record['watch_id'], json.dumps(record)))

    def delete(self, watch_id):
        with self.conn:
            self.conn.execute('DELETE FROM watches WHERE watch_id = ?', (watch_id,))

    def close(self):
        self.conn.close()


# ---------------------------------------------------------------- Esplora

class EsploraHTTP:
    '''Minimal HTTP client: get/post return (status, text). Responses are
    size-capped and every request has a timeout.'''

    MAX_BODY = 2_000_000

    def __init__(self, timeout=15):
        self.timeout = timeout
        self._session = None

    def _get_session(self):
        import aiohttp
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={'User-Agent': 'electrumx-watchtower'})
        return self._session

    async def _read(self, response):
        chunks, size = [], 0
        async for chunk in response.content.iter_chunked(65536):
            size += len(chunk)
            if size > self.MAX_BODY:
                raise ValueError('response too large')
            chunks.append(chunk)
        return response.status, b''.join(chunks).decode('utf-8', 'replace')

    async def get(self, url):
        async with self._get_session().get(url) as response:
            return await self._read(response)

    async def post(self, url, body):
        async with self._get_session().post(
                url, data=body.encode(), headers={'Content-Type': 'text/plain'}) as response:
            return await self._read(response)

    async def close(self):
        if self._session is not None and not self._session.closed:
            await self._session.close()


def _is_txid(value):
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        return bytes.fromhex(value).hex() == value
    except ValueError:
        return False


def _error_text(e):
    '''Short text for an exception; understands DaemonError's error dict.'''
    arg = e.args[0] if e.args else None
    if isinstance(arg, dict) and 'message' in arg:
        return str(arg['message'])[:200]
    return (str(e) or e.__class__.__name__)[:200]


def _contains(text, needles):
    text = text.lower()
    return any(needle in text for needle in needles)


# ---------------------------------------------------------------- watchtower

class Watchtower:
    '''Registration, the periodic check, and persistence.

    Injected collaborators (all optional so tests can fake them):

    http                 object with async get(url) and post(url, body),
                         each returning (status, text)
    broadcast_mars       async raw_hex -> txid; raises with the node's
                         message on rejection
    mars_raw_tx          async txid -> raw hex, or None if the node does
                         not know the transaction; raises if unavailable
    mars_confirmations   async txid -> confirmations (0 if unconfirmed or
                         unknown)
    mars_height          () -> current MARS height, or None
    clock                () -> unix time
    '''

    def __init__(self, db_path=None, http=None, broadcast_mars=None, mars_raw_tx=None,
                 mars_confirmations=None, mars_height=None, clock=time.time,
                 esplora_urls=ESPLORA_DEFAULT, max_active_per_tag=3,
                 max_registrations_per_day=12, max_active=2000, interval=60,
                 escalate_blocks=6, grace_hours=48, keep_days=7, max_days=14,
                 claim_confirmations=3, foreign_hold_seconds=1800,
                 strict_funding=False, daemon_timeout=30, register_timeout=8, logger=None):
        self.store = WatchStore(db_path)
        self.http = http if http is not None else EsploraHTTP()
        self.broadcast_mars = broadcast_mars
        self.mars_raw_tx = mars_raw_tx
        self.mars_confirmations = mars_confirmations
        self.mars_height = mars_height
        self.clock = clock
        self.esplora_urls = tuple(url.rstrip('/') for url in esplora_urls)
        self.max_active_per_tag = max_active_per_tag
        self.max_registrations_per_day = max_registrations_per_day
        self.max_active = max_active
        self.interval = interval
        self.escalate_blocks = max(1, escalate_blocks)
        self.grace_seconds = grace_hours * 3600
        self.keep_seconds = keep_days * DAY
        self.max_seconds = max_days * DAY
        self.claim_confirmations = claim_confirmations
        self.foreign_hold_seconds = foreign_hold_seconds
        self.strict_funding = strict_funding
        self.daemon_timeout = daemon_timeout
        self.register_timeout = register_timeout
        self._tip_seen = (None, 0)     # (height, when) for registrations
        self.logger = logger or logging.getLogger(__name__)
        self.watches = self.store.load()

    @classmethod
    def from_env(cls, db_dir, **collaborators):
        urls = os.environ.get('WATCHTOWER_ESPLORA_URLS')
        urls = [u.strip() for u in urls.split(',') if u.strip()] if urls else ESPLORA_DEFAULT
        path = os.environ.get('WATCHTOWER_DB') or os.path.join(db_dir, 'watchtower.sqlite')
        return cls(
            db_path=path,
            esplora_urls=urls,
            max_active_per_tag=_env_int('WATCHTOWER_MAX_ACTIVE_PER_CLIENT', 3),
            max_registrations_per_day=_env_int('WATCHTOWER_MAX_REGISTRATIONS_PER_DAY', 12),
            max_active=_env_int('WATCHTOWER_MAX_ACTIVE', 2000),
            interval=_env_int('WATCHTOWER_INTERVAL', 60),
            strict_funding=_env_int('WATCHTOWER_STRICT_FUNDING', 0) != 0,
            **collaborators)

    # ------------------------------------------------------------ helpers

    @staticmethod
    def _active(record):
        return record.get('finished_at') is None

    def _save(self, record):
        record['updated_at'] = int(self.clock())
        try:
            self.store.save(record)
        except sqlite3.Error as e:
            self.logger.error(f'watchtower: cannot store {record["watch_id"][:8]}: {e}')

    def _update(self, record, **changes):
        '''Apply changes and persist, only if something actually changed.'''
        if all(record.get(k) == v for k, v in changes.items()):
            return
        record.update(changes)
        self._save(record)

    def _finish(self, record, state, detail, **changes):
        self.logger.info(f'watchtower: {record["watch_id"][:8]} finished: {state} ({detail})')
        self._update(record, state=state, detail=detail,
                     finished_at=int(self.clock()), **changes)

    async def _daemon(self, coro, timeout=None):
        return await asyncio.wait_for(coro, timeout or self.daemon_timeout)

    # ------------------------------------------------------------ Esplora

    async def _btc_tip(self):
        '''Highest tip height among the services that answer, else None.'''
        heights = []
        for base in self.esplora_urls:
            try:
                status, text = await self.http.get(f'{base}/blocks/tip/height')
                if status == 200:
                    height = int(text.strip())
                    if 0 < height < LOCKTIME_THRESHOLD:
                        heights.append(height)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.logger.debug(f'watchtower: tip from {base}: {_error_text(e)}')
        tip = max(heights) if heights else None
        if tip is not None:
            self._tip_seen = (tip, self.clock())
        return tip

    async def _btc_tip_for_registration(self):
        '''A tip no older than a minute, without making a client wait
        long or letting clients trigger a request each.'''
        tip, when = self._tip_seen
        if tip is not None and 0 <= self.clock() - when < 60:
            return tip
        try:
            return await asyncio.wait_for(self._btc_tip(), self.register_timeout)
        except asyncio.TimeoutError:
            return None

    async def _outspend(self, base, txid, vout):
        '''Return None if the service gave no usable answer, else
        (spender_txid or None, confirmed).'''
        try:
            status, text = await self.http.get(f'{base}/tx/{txid}/outspend/{vout}')
            if status != 200:
                return None
            data = json.loads(text)
            if not isinstance(data, dict) or not isinstance(data.get('spent'), bool):
                return None
            if not data['spent']:
                return (None, False)
            spender = data.get('txid')
            if not _is_txid(spender):
                return None
            spend_status = data.get('status')
            confirmed = isinstance(spend_status, dict) and spend_status.get('confirmed') is True
            return (spender, confirmed)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.debug(f'watchtower: outspend from {base}: {_error_text(e)}')
            return None

    async def _verified_spender(self, base, spender, txid, vout):
        '''Fetch a spending tx and return it parsed, but only if its bytes
        hash to the reported txid and it really spends our outpoint.'''
        try:
            status, text = await self.http.get(f'{base}/tx/{spender}/hex')
            if status != 200:
                return None
            tx = parse_tx(bytes.fromhex(text.strip()))
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.debug(f'watchtower: spender hex from {base}: {_error_text(e)}')
            return None
        if tx.txid != spender:
            self.logger.warning(f'watchtower: {base} returned bytes that do not hash to {spender}')
            return None
        if not any((prev_hash, prev_idx) == (txid, vout)
                   for prev_hash, prev_idx, _script, _seq in tx.inputs):
            self.logger.warning(f'watchtower: {base} named {spender} as spender but it '
                                f'does not spend {txid}:{vout}')
            return None
        return tx

    # ------------------------------------------------------------ registration

    async def _check_mars_funding(self, mars):
        '''True if our node confirms the MARS lockbox, False if it could
        not say. Raises if the node shows something different.'''
        if self.mars_raw_tx is None:
            return False
        try:
            raw_hex = await self._daemon(self.mars_raw_tx(mars['funding_txid']),
                                         self.register_timeout)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.info(f'watchtower: MARS funding lookup unavailable: {_error_text(e)}')
            return False
        if raw_hex is None:
            if self.strict_funding:
                raise WatchtowerError('the MARS lockbox transaction is not known to this '
                                      'server yet; try again shortly')
            return False
        mismatch = WatchtowerError('the MARS funding output does not match the package')
        try:
            tx = parse_tx(bytes.fromhex(raw_hex))
        except (WatchtowerError, ValueError, TypeError):
            return False
        if tx.txid != mars['funding_txid']:
            return False
        if mars['funding_vout'] >= len(tx.outputs):
            raise mismatch
        value, script_pubkey = tx.outputs[mars['funding_vout']]
        expected = p2wsh_script(bytes.fromhex(mars['htlc_script']))
        if script_pubkey != expected or value != mars['funding_value']:
            raise mismatch
        return True

    def _check_caps(self, tag, now):
        active = [r for r in self.watches.values() if self._active(r)]
        if len(active) >= self.max_active or len(self.watches) >= 5 * self.max_active:
            raise WatchtowerError('the watchtower is full; keep your wallet open to '
                                  'finish this swap')
        if sum(1 for r in active if r['tag'] == tag) >= self.max_active_per_tag:
            raise WatchtowerError('too many swaps are already being watched for this '
                                  'connection')
        recent = sum(1 for r in self.watches.values()
                     if r['tag'] == tag and r['created_at'] > now - DAY)
        if recent >= self.max_registrations_per_day:
            raise WatchtowerError('daily limit for watchtower registrations reached')

    def _expiry(self, package, now, btc_tip, mars_tip):
        '''When both timelocks will plausibly have passed, plus the grace
        period. Raises if a timelock is unreasonably far away.'''
        waits = []
        if btc_tip is not None:
            waits.append(max(0, package['btc']['locktime'] - btc_tip) * BTC_BLOCK_SECONDS)
        if mars_tip is not None:
            waits.append(max(0, package['mars']['locktime'] - mars_tip) * MARS_BLOCK_SECONDS)
        if any(wait > self.max_seconds for wait in waits):
            raise WatchtowerError('timelock is too far in the future for the watchtower')
        hard = now + self.max_seconds + self.grace_seconds + 2 * DAY
        if len(waits) < 2:
            return hard, hard, False
        # Blocks can be slow; allow half as long again.
        return min(hard, now + int(max(waits) * 1.5) + self.grace_seconds), hard, True

    async def register(self, package, tag):
        '''Validate and store a watch. Returns {'watch_id', 'expires_at'}.'''
        core = validate_package(package)
        watch_id = core['watch_id']

        def existing_reply():
            existing = self.watches.get(watch_id)
            if existing is None:
                return None
            if existing['package'] != core['package']:
                raise WatchtowerError('a different package is already registered for this swap')
            return {'watch_id': watch_id, 'expires_at': existing['expires_at']}

        reply = existing_reply()
        if reply:
            return reply
        now = int(self.clock())
        self._check_caps(tag, now)

        funding_verified = await self._check_mars_funding(core['package']['mars'])
        btc_tip = await self._btc_tip_for_registration()
        mars_tip = self.mars_height() if self.mars_height else None

        # The awaits above let other registrations in; check again.
        reply = existing_reply()
        if reply:
            return reply
        now = int(self.clock())
        self._check_caps(tag, now)
        expires_at, hard_expires_at, expiry_known = self._expiry(
            core['package'], now, btc_tip, mars_tip)
        record = dict(
            core, tag=tag, created_at=now, updated_at=now, expires_at=expires_at,
            hard_expires_at=hard_expires_at, expiry_known=expiry_known, finished_at=None,
            state=WATCHING, detail='watching the Bitcoin lockbox',
            funding_verified=funding_verified, preimage=None, mars_claim_txid=None,
            btc_refund_txid=None, refund_start_height=None, refund_floor=0,
            foreign_spend_since=None, claim_confirmed=False)
        try:
            self.store.save(record)
        except sqlite3.Error as e:
            self.logger.error(f'watchtower: cannot store new watch: {e}')
            raise WatchtowerError('the watchtower could not store this swap; keep your '
                                  'wallet open to finish it') from None
        self.watches[watch_id] = record
        self.logger.info(f'watchtower: registered {watch_id[:8]} '
                         f'(funding verified: {funding_verified})')
        return {'watch_id': watch_id, 'expires_at': expires_at}

    def status(self, watch_id):
        record = self.watches.get(watch_id) if isinstance(watch_id, str) else None
        if record is None:
            return None
        return {
            'state': record['state'],
            'mars_claim_txid': record['mars_claim_txid'],
            'btc_refund_txid': record['btc_refund_txid'],
            'preimage_seen': record['preimage'] is not None,
            'updated_at': record['updated_at'],
            'detail': record['detail'],
        }

    # ------------------------------------------------------------ the loop

    async def run(self):
        '''Check all watches forever. Nothing escapes except cancellation.'''
        self.logger.info(f'watchtower: started with {len(self.watches)} stored watches, '
                         f'checking every {self.interval}s')
        try:
            while True:
                try:
                    await self.tick()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    self.logger.exception('watchtower: tick failed')
                await asyncio.sleep(self.interval)
        finally:
            close = getattr(self.http, 'close', None)
            if close:
                try:
                    await close()
                except Exception:
                    pass

    async def tick(self):
        now = int(self.clock())
        for watch_id in [k for k, r in self.watches.items()
                         if not self._active(r) and r['finished_at'] <= now - self.keep_seconds]:
            del self.watches[watch_id]
            try:
                self.store.delete(watch_id)
            except sqlite3.Error as e:
                self.logger.error(f'watchtower: cannot purge {watch_id[:8]}: {e}')
        active = [r for r in self.watches.values() if self._active(r)]
        if not active:
            return
        btc_tip = await self._btc_tip()
        for record in active:
            try:
                await self._process(record, int(self.clock()), btc_tip)
            except asyncio.CancelledError:
                raise
            except Exception:
                self.logger.exception(f'watchtower: error on {record.get("watch_id", "?")[:8]}')

    async def _process(self, record, now, btc_tip):
        if record['preimage'] is None:
            await self._check_bitcoin(record, now, btc_tip)
        if not self._active(record):
            return
        if record['preimage'] is not None:
            await self._push_claim(record)
        if self._active(record):
            self._maybe_expire(record, now, btc_tip)

    def _maybe_expire(self, record, now, btc_tip):
        package = record['package']
        if not record['expiry_known'] and btc_tip is not None and self.mars_height:
            # The Bitcoin height was unknown at registration; settle it now.
            mars_tip = self.mars_height()
            if mars_tip is not None:
                waits = (max(0, package['btc']['locktime'] - btc_tip) * BTC_BLOCK_SECONDS,
                         max(0, package['mars']['locktime'] - mars_tip) * MARS_BLOCK_SECONDS)
                expires_at = min(record['hard_expires_at'],
                                 now + int(max(waits) * 1.5) + self.grace_seconds)
                self._update(record, expires_at=expires_at, expiry_known=True)
        if now < record['expires_at']:
            return
        if now < record['hard_expires_at']:
            # Don't give up on a time estimate alone while the refund
            # timelock has not had a day to play out.
            if btc_tip is None or btc_tip < package['btc']['locktime'] + 144:
                return
        if record['state'] == CLAIMED:
            self._finish(record, CLAIMED, 'MARS claim sent; stopped watching')
        elif record['preimage'] is not None:
            self._finish(record, FAILED, 'secret seen but the MARS claim was not accepted')
        else:
            self._finish(record, EXPIRED, 'stopped watching')

    # ------------------------------------------------------------ Bitcoin side

    async def _check_bitcoin(self, record, now, btc_tip):
        btc = record['package']['btc']
        txid, vout = btc['funding_txid'], btc['funding_vout']
        payment_hash160 = bytes.fromhex(record['package']['payment_hash160'])
        answers = []
        for base in self.esplora_urls:
            answer = await self._outspend(base, txid, vout)
            if answer is not None:
                answers.append((base, answer[0], answer[1]))
        if not answers:
            return

        ours = set(record['refund_txids'])
        foreign_seen = False
        checked = set()
        for base, spender, _confirmed in answers:
            if spender is None or spender in ours or spender in checked:
                continue
            foreign_seen = True
            # Any service may hold the bytes; the hash check makes the source irrelevant.
            for source in [base] + [b for b in self.esplora_urls if b != base]:
                tx = await self._verified_spender(source, spender, txid, vout)
                if tx is None:
                    continue
                checked.add(spender)
                preimage = find_preimage(tx, payment_hash160)
                if preimage is not None:
                    self.logger.info(f'watchtower: {record["watch_id"][:8]} secret revealed '
                                     f'by {spender}')
                    self._update(record, preimage=preimage.hex(),
                                 detail='secret seen; claiming MARS')
                    return
                break

        unspent_reported = any(spender is None for _b, spender, _c in answers)
        refund_confirmed = [spender for _b, spender, confirmed in answers
                            if spender in ours and confirmed]
        if refund_confirmed and not unspent_reported:
            self._finish(record, REFUNDED, 'BTC refund confirmed',
                         btc_refund_txid=refund_confirmed[0])
            return

        if foreign_seen:
            # Probably the maker's claim, not readable yet. Hold refunds
            # for a while, but not forever on a service's say-so.
            since = record['foreign_spend_since'] or now
            self._update(record, foreign_spend_since=since,
                         detail='BTC lockbox spent; waiting to read the spending transaction')
            if now - since < self.foreign_hold_seconds:
                return
        elif record['foreign_spend_since'] is not None:
            self._update(record, foreign_spend_since=None)

        if btc_tip is None or btc_tip < btc['locktime']:
            return
        await self._push_refund(record, btc_tip)

    async def _push_refund(self, record, btc_tip):
        btc = record['package']['btc']
        if btc_tip < btc['locktime']:     # the one rule; checked again here
            return
        refunds = btc['refund_txs']
        start = record['refund_start_height']
        if start is None:
            start = btc_tip
        index = max(record['refund_floor'], (btc_tip - start) // self.escalate_blocks)
        index = min(index, len(refunds) - 1)
        raw_hex, refund_txid = refunds[index], record['refund_txids'][index]
        accepted, replies = False, []
        for base in self.esplora_urls:
            try:
                status, text = await self.http.post(f'{base}/tx', raw_hex)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                replies.append(_error_text(e))
                continue
            text = text.strip()
            if (status == 200 and text == refund_txid) or _contains(text, ALREADY_KNOWN):
                accepted = True
            else:
                replies.append(text[:200])
        changes = {'refund_start_height': start}
        orphaned = (not accepted and len(replies) == len(self.esplora_urls)
                    and all(_contains(r, MISSING_INPUTS) for r in replies))
        if orphaned:
            # Nothing to refund as far as any service can tell. Keep trying for
            # a while (services lag, and a claim may yet show), then stop
            # rather than resubmit a dead transaction for days.
            since = record.get('refund_orphan_since')
            now = int(self.clock())
            if since is None:
                changes['refund_orphan_since'] = now
            elif now - since >= ORPHAN_SECONDS:
                self._finish(record, FAILED,
                             'the Bitcoin contract was never funded, or was spent before its refund',
                             refund_start_height=start)
                return
        elif record.get('refund_orphan_since') is not None:
            changes['refund_orphan_since'] = None
        if accepted:
            changes.update(state=REFUNDING, btc_refund_txid=refund_txid,
                           detail=f'BTC refund sent (fee step {index + 1} of {len(refunds)})')
        else:
            reply = replies[0] if replies else 'no reply'
            if record['state'] != REFUNDING:
                changes['detail'] = f'BTC refund not accepted yet: {reply}'[:200]
            if (index + 1 < len(refunds) and replies
                    and all(_contains(r, FEE_TOO_LOW) for r in replies)):
                changes['refund_floor'] = index + 1
            self.logger.info(f'watchtower: {record["watch_id"][:8]} refund step {index + 1} '
                             f'not accepted: {reply}')
        self._update(record, **changes)

    # ------------------------------------------------------------ MARS side

    async def _push_claim(self, record):
        claim_txid = record['claim_txid']
        if record['state'] == CLAIMED and self.mars_confirmations is not None:
            try:
                confirmations = await self._daemon(self.mars_confirmations(claim_txid))
            except asyncio.CancelledError:
                raise
            except Exception:
                confirmations = 0
            if confirmations and confirmations >= self.claim_confirmations:
                self._finish(record, CLAIMED, 'MARS claim confirmed', claim_confirmed=True)
                return
            if confirmations:
                return   # in a block; nothing to rebroadcast
        if self.broadcast_mars is None:
            return
        # build_claim refuses anything but the matching secret.
        raw_hex = build_claim(record, bytes.fromhex(record['preimage']))
        try:
            await self._daemon(self.broadcast_mars(raw_hex))
        except asyncio.CancelledError:
            raise
        except Exception as e:
            reply = _error_text(e)
            if not _contains(reply, ALREADY_KNOWN):
                if record['state'] != CLAIMED:
                    self._update(record, detail=f'MARS claim not accepted yet: {reply}'[:200])
                self.logger.info(f'watchtower: {record["watch_id"][:8]} claim not '
                                 f'accepted: {reply}')
                return
        if record['state'] != CLAIMED:
            self.logger.info(f'watchtower: {record["watch_id"][:8]} MARS claim sent: {claim_txid}')
        self._update(record, state=CLAIMED, mars_claim_txid=claim_txid,
                     detail='MARS claim sent; waiting for confirmation')
