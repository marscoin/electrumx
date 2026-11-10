import asyncio
import copy
import hashlib
import json

import pytest

from electrumx.server import watchtower as wt
from electrumx.server.watchtower import (DAY, Watchtower, WatchtowerError, build_claim,
                                         hash160, parse_htlc_script, parse_tx,
                                         ripemd160_py, validate_package, watch_id_for)

# ---------------------------------------------------------------- reference vector
# From the reference wallet: preimage 00..1f.

PREIMAGE = bytes(range(32))
H160 = 'ea4beb47def8492389a1e16634795441e1b87245'
FUND = '11' * 32
BTC_SCRIPT = ('63a914ea4beb47def8492389a1e16634795441e1b872458821031b84c5567b126440995d3ed5aa'
              'ba0565d71e1834604819ff9c17f5e9d5dd078fac670386e10eb17521024d4b6cd1361032ca9bd2'
              'aeb9d900aa4d45d9ead80ac9423374c451a7254d0766ac68')
BTC_LOCKTIME = 975238
BTC_VALUE = 6239
BTC_REFUND = ('02000000000101111111111111111111111111111111111111111111111111111111111111111101'
              '00000000feffffff01971700000000000016001432d702d8186a958b538160ee228a11467bc487'
              '5a0347304402202b0d9203ce91bf7af1336bbbad2f7f8c05ae6da9f868a300e50535d31de796d4'
              '022029c0a5a96c2df3ccb06901b628c64e699aa5e1ba29df5406cf50883630c86e7601006663a9'
              '14ea4beb47def8492389a1e16634795441e1b872458821031b84c5567b126440995d3ed5aaba05'
              '65d71e1834604819ff9c17f5e9d5dd078fac670386e10eb17521024d4b6cd1361032ca9bd2aeb9'
              'd900aa4d45d9ead80ac9423374c451a7254d0766ac6886e10e00')
MARS_SCRIPT = ('63a914ea4beb47def8492389a1e16634795441e1b872458821024d4b6cd1361032ca9bd2aeb9d9'
               '00aa4d45d9ead80ac9423374c451a7254d0766ac670374e836b17521031b84c5567b126440995d'
               '3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fac68')
MARS_LOCKTIME = 3598452
MARS_VALUE = 7050000000
MARS_CLAIM_REAL = ('020000000001011111111111111111111111111111111111111111111111111111111111111'
                   '1110000000000feffffff01e0ef34a4010000002200209c5d7eb45519dca905337b861a3515'
                   '40f18e10c20d20637e96b9834f1739464c04473044022038cd4b29a761e445d1c188d285757'
                   '479fbdfafddf86c7bc5cad5e8ed33e211b402207251454dd68ecd66b74e0b8bb49063391b95'
                   '2e4e20bd4c9119cbfe5efd7e2ea20120000102030405060708090a0b0c0d0e0f10111213141'
                   '5161718191a1b1c1d1e1f01016663a914ea4beb47def8492389a1e16634795441e1b8724588'
                   '21024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766ac67037'
                   '4e836b17521031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd07'
                   '8fac6800000000')
MARS_CLAIM = MARS_CLAIM_REAL.replace(PREIMAGE.hex(), '00' * 32)

MEMPOOL = 'https://mempool.space/api'
BLOCKSTREAM = 'https://blockstream.info/api'
TAG = 'tag-a'
NOW = 1_800_000_000
BTC_TIP = BTC_LOCKTIME - 100
MARS_TIP = MARS_LOCKTIME - 300


# ---------------------------------------------------------------- tx helpers

def varint(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    return b'\xfe' + n.to_bytes(4, 'little')


def make_tx(inputs, outputs, witnesses=None, locktime=0, version=2):
    '''inputs: (txid_hex, vout, sequence); outputs: (value, script);
    witnesses: per input a list of items, or None for a legacy tx.'''
    out = version.to_bytes(4, 'little')
    if witnesses is not None:
        out += b'\x00\x01'
    out += varint(len(inputs))
    for txid, vout, sequence in inputs:
        out += (bytes.fromhex(txid)[::-1] + vout.to_bytes(4, 'little') + b'\x00'
                + sequence.to_bytes(4, 'little'))
    out += varint(len(outputs))
    for value, script in outputs:
        out += value.to_bytes(8, 'little') + varint(len(script)) + script
    for items in witnesses or []:
        out += varint(len(items))
        for item in items:
            out += varint(len(item)) + item
    return out + locktime.to_bytes(4, 'little')


def txid_of(raw_hex):
    '''txid from the non-witness serialization, computed independently
    of the module under test for the single-input shapes used here.'''
    raw = bytes.fromhex(raw_hex)
    tx = parse_tx(raw)
    stripped = make_tx([(h, i, s) for h, i, _sig, s in tx.inputs], tx.outputs,
                       None, tx.locktime, tx.version)
    return hashlib.sha256(hashlib.sha256(stripped).digest()).digest()[::-1].hex()


FAKE_SIG = bytes.fromhex('30440220' + '11' * 32 + '0220' + '22' * 32 + '01')
P2WPKH = bytes.fromhex('001432d702d8186a958b538160ee228a11467bc4875a')


def refund_tx(value, txid=FUND, vout=1, locktime=BTC_LOCKTIME, sequence=0xfffffffe,
              witness=None, script=BTC_SCRIPT):
    witness = witness if witness is not None else [FAKE_SIG, b'', bytes.fromhex(script)]
    return make_tx([(txid, vout, sequence)], [(value, P2WPKH)], [witness], locktime).hex()


REFUND_2 = refund_tx(5800)
REFUND_3 = refund_tx(5200)


def maker_claim(preimage=PREIMAGE, txid=FUND, vout=1):
    '''What the maker broadcasts on Bitcoin: reveals the preimage.'''
    witness = [FAKE_SIG, preimage, b'\x01', bytes.fromhex(BTC_SCRIPT)]
    return make_tx([(txid, vout, 0xffffffff)], [(6000, P2WPKH)], [witness]).hex()


def mars_funding_tx(script=MARS_SCRIPT, value=MARS_VALUE):
    spk = b'\x00\x20' + hashlib.sha256(bytes.fromhex(script)).digest()
    return make_tx([('22' * 32, 0, 0xffffffff)], [(value, spk)], [[FAKE_SIG, b'\x02' * 33]]).hex()


def package(**changes):
    p = {
        'version': 1,
        'payment_hash160': H160,
        'btc': {'htlc_script': BTC_SCRIPT, 'funding_txid': FUND, 'funding_vout': 1,
                'funding_value': BTC_VALUE, 'locktime': BTC_LOCKTIME,
                'refund_txs': [BTC_REFUND, REFUND_2, REFUND_3]},
        'mars': {'htlc_script': MARS_SCRIPT, 'funding_txid': FUND, 'funding_vout': 0,
                 'funding_value': MARS_VALUE, 'locktime': MARS_LOCKTIME,
                 'claim_tx': MARS_CLAIM},
    }
    for path, value in changes.items():
        side, _, field = path.partition('__')
        if field:
            p[side][field] = value
        else:
            p[side] = value
    return p


def other_package(n):
    '''A distinct valid swap: different BTC funding outpoint.'''
    txid = f'{n:02x}' * 32
    return package(btc__funding_txid=txid,
                   btc__refund_txs=[refund_tx(6000, txid=txid), refund_tx(5500, txid=txid)])


WATCH_ID = watch_id_for(FUND, 1, H160)

# The vector's funding txid (11..11) cannot be the hash of a real
# transaction, so funding checks use a swap whose MARS lockbox is real.
MARS_FUNDING = mars_funding_tx()
MARS_FUND = txid_of(MARS_FUNDING)


def claim_tx(txid=None, vout=0, value=MARS_VALUE - 1000, witness=None):
    witness = witness or [FAKE_SIG, bytes(32), b'\x01', bytes.fromhex(MARS_SCRIPT)]
    return make_tx([(txid or MARS_FUND, vout, 0xfffffffe)], [(value, P2WPKH)], [witness]).hex()


def funded_package(**changes):
    return package(mars__funding_txid=MARS_FUND, mars__claim_tx=claim_tx(), **changes)


# ---------------------------------------------------------------- fakes

class Clock:
    def __init__(self, now=NOW):
        self.now = now

    def __call__(self):
        return self.now


class FakeHTTP:
    '''Two Esplora services. outspend/hex are keyed by base URL.'''

    def __init__(self):
        self.tip = {MEMPOOL: BTC_TIP, BLOCKSTREAM: BTC_TIP}
        self.outspend = {}       # (base, txid, vout) -> dict; default unspent
        self.hex = {}            # (base, txid) -> text
        self.posts = []          # (base, body)
        self.post_reply = None   # (base, body) -> (status, text)
        self.gets = []
        self.fail = set()        # funding txids whose lookups raise

    async def get(self, url):
        self.gets.append(url)
        base = MEMPOOL if url.startswith(MEMPOOL) else BLOCKSTREAM
        path = url[len(base):].strip('/').split('/')
        if path == ['blocks', 'tip', 'height']:
            if self.tip[base] is None:
                raise OSError('down')
            return 200, str(self.tip[base])
        if len(path) == 4 and path[2] == 'outspend':
            if path[1] in self.fail:
                raise RuntimeError('boom')
            reply = self.outspend.get((base, path[1], int(path[3])), {'spent': False})
            return 200, json.dumps(reply)
        if len(path) == 3 and path[2] == 'hex':
            text = self.hex.get((base, path[1]))
            return (200, text) if text is not None else (404, 'Transaction not found')
        return 404, 'not found'

    async def post(self, url, body):
        base = url[:-len('/tx')]
        self.posts.append((base, body))
        if self.post_reply:
            return self.post_reply(base, body)
        return 200, txid_of(body)

    def spend(self, spender_hex, confirmed=True, bases=(MEMPOOL, BLOCKSTREAM), txid=FUND,
              vout=1, claimed_txid=None, served_hex=None):
        spender_txid = claimed_txid or txid_of(spender_hex)
        for base in bases:
            self.outspend[(base, txid, vout)] = {
                'spent': True, 'txid': spender_txid, 'vin': 0,
                'status': {'confirmed': confirmed}}
            self.hex[(base, spender_txid)] = spender_hex if served_hex is None else served_hex
        return spender_txid


class FakeMars:
    def __init__(self):
        self.broadcasts = []
        self.txs = {MARS_FUND: MARS_FUNDING}
        self.confirmations = 0
        self.reject = None
        self.lookup_error = None
        self.height = MARS_TIP

    async def broadcast(self, raw_hex):
        self.broadcasts.append(raw_hex)
        if self.reject:
            raise Exception({'code': -26, 'message': self.reject})
        return txid_of(raw_hex)

    async def raw_tx(self, txid):
        if self.lookup_error:
            raise self.lookup_error
        return self.txs.get(txid)

    async def confs(self, txid):
        return self.confirmations


def run(coro):
    return asyncio.run(coro)


def make_tower(path, http, mars, clock, **kwargs):
    return Watchtower(db_path=path, http=http, broadcast_mars=mars.broadcast,
                      mars_raw_tx=mars.raw_tx, mars_confirmations=mars.confs,
                      mars_height=lambda: mars.height, clock=clock, **kwargs)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def http():
    return FakeHTTP()


@pytest.fixture
def mars():
    return FakeMars()


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / 'watchtower.sqlite')


@pytest.fixture
def tower(db_path, http, mars, clock):
    return make_tower(db_path, http, mars, clock)


DEFAULT = object()


def register(tower, pkg=DEFAULT, tag=TAG):
    return run(tower.register(package() if pkg is DEFAULT else pkg, tag))


def refused(tower, pkg, match):
    with pytest.raises(WatchtowerError, match=match):
        register(tower, pkg)
    assert tower.watches == {}


# ---------------------------------------------------------------- primitives

def test_reference_vector_parses():
    assert hash160(PREIMAGE).hex() == H160
    assert wt.ripemd160_py(hashlib.sha256(PREIMAGE).digest()).hex() == H160
    h160, recipient, locktime, sender = parse_htlc_script(bytes.fromhex(BTC_SCRIPT))
    assert (h160.hex(), locktime) == (H160, BTC_LOCKTIME)
    m_h160, m_recipient, m_locktime, m_sender = parse_htlc_script(bytes.fromhex(MARS_SCRIPT))
    assert (m_h160.hex(), m_locktime) == (H160, MARS_LOCKTIME)
    assert (recipient, sender) == (m_sender, m_recipient)

    refund = parse_tx(bytes.fromhex(BTC_REFUND))
    assert refund.inputs[0][:2] == (FUND, 1) and refund.locktime == BTC_LOCKTIME
    assert refund.outputs[0][0] == 0x1797
    claim = parse_tx(bytes.fromhex(MARS_CLAIM_REAL))
    assert claim.witnesses[0][1] == PREIMAGE
    assert parse_tx(bytes.fromhex(MARS_CLAIM)).txid == claim.txid


def test_pure_python_ripemd160():
    vectors = {b'': '9c1185a5c5e9fc54612808977ee8f548b2258d31',
               b'abc': '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc',
               b'a' * 1000: 'aa69deee9a8922e92f8105e007f76110f381e9cf'}
    for data, digest in vectors.items():
        assert ripemd160_py(data).hex() == digest
    for n in (55, 56, 63, 64, 65, 119, 120):
        data = bytes(range(n))
        try:
            expected = hashlib.new('ripemd160', data).digest()
        except ValueError:
            pytest.skip('no native ripemd160 to compare against')
        assert ripemd160_py(data) == expected


def test_txid_uses_non_witness_serialization():
    raw = bytes.fromhex(MARS_CLAIM_REAL)
    assert parse_tx(raw).txid != hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
    assert parse_tx(raw).txid == txid_of(MARS_CLAIM_REAL)


@pytest.mark.parametrize('raw', [b'', b'\x00' * 3, b'\x02\x00\x00\x00\x00\x01',
                                 bytes.fromhex(BTC_REFUND)[:-1],
                                 bytes.fromhex(BTC_REFUND) + b'\x00',
                                 b'\x02\x00\x00\x00\xff' + b'\xff' * 8,
                                 b'\xff' * 400])
def test_parse_tx_rejects_garbage(raw):
    with pytest.raises(WatchtowerError):
        parse_tx(raw)


def test_watch_id():
    expected = hashlib.sha256(f'{FUND}:1:{H160}'.encode()).hexdigest()
    assert WATCH_ID == expected


# ---------------------------------------------------------------- registration

def test_valid_package_accepted(tower, clock):
    result = register(tower)
    assert result['watch_id'] == WATCH_ID
    # MARS lock is 300 blocks out, BTC 100 blocks: ~25 h at 1.5x, plus 48 h grace.
    assert clock.now + 48 * 3600 < result['expires_at'] < clock.now + 5 * DAY
    status = tower.status(WATCH_ID)
    assert status['state'] == 'watching'
    assert status['mars_claim_txid'] is None and status['btc_refund_txid'] is None
    assert status['preimage_seen'] is False and status['updated_at'] == clock.now
    assert set(status) == {'state', 'mars_claim_txid', 'btc_refund_txid', 'preimage_seen',
                           'updated_at', 'detail'}
    # The vector's MARS funding txid is unknown to the node: advisory only.
    assert tower.watches[WATCH_ID]['funding_verified'] is False


def test_mars_funding_verified_against_the_node(tower):
    assert register(tower, funded_package())['watch_id'] == WATCH_ID
    assert tower.watches[WATCH_ID]['funding_verified'] is True


def test_status_unknown_is_none(tower):
    assert tower.status('00' * 32) is None
    assert tower.status(None) is None
    assert tower.status(['x']) is None


def test_uppercase_hex_is_the_same_package(tower):
    register(tower)
    upper = package(payment_hash160=H160.upper(), mars__claim_tx=MARS_CLAIM.upper())
    assert register(tower, upper)['watch_id'] == WATCH_ID


def test_single_refund_accepted(tower):
    assert register(tower, package(btc__refund_txs=[BTC_REFUND]))['watch_id'] == WATCH_ID


def other_hash_script(script):
    return script.replace(H160, 'bb' * 20)


BAD_PACKAGES = {
    'not a dict': ('nope', 'must be an object'),
    'missing side': ({k: v for k, v in package().items() if k != 'mars'}, 'fields'),
    'extra field': (dict(package(), extra=1), 'fields'),
    'wrong version': (package(version=2), 'version'),
    'bool version': (package(version=True), 'version'),
    'bad hash hex': (package(payment_hash160='zz' * 20), 'hex'),
    'short hash': (package(payment_hash160=H160[:-2]), '20 bytes'),
    'wrong script (opcode changed)': (
        package(btc__htlc_script=BTC_SCRIPT.replace('63a914', '64a914', 1)), 'expected swap'),
    'wrong script (trailing byte)': (package(mars__htlc_script=MARS_SCRIPT + '00'),
                                     'expected swap'),
    'wrong script (truncated)': (package(mars__htlc_script=MARS_SCRIPT[:-2]), 'expected swap'),
    'wrong script (non-minimal locktime)': (
        package(btc__htlc_script=BTC_SCRIPT.replace('0386e10e', '0486e10e00')), 'expected swap'),
    'hash mismatch': (package(payment_hash160='bb' * 20), 'payment_hash160'),
    'hash mismatch on one side': (
        package(mars__htlc_script=other_hash_script(MARS_SCRIPT)), 'mars.htlc_script'),
    'btc locktime mismatch': (package(btc__locktime=BTC_LOCKTIME + 1), 'btc.locktime'),
    'mars locktime mismatch': (package(mars__locktime=MARS_LOCKTIME - 1), 'mars.locktime'),
    'refund not spending the outpoint (txid)': (
        package(btc__refund_txs=[refund_tx(6000, txid='33' * 32)]), 'does not spend'),
    'refund not spending the outpoint (vout)': (
        package(btc__refund_txs=[refund_tx(6000, vout=0)]), 'does not spend'),
    'refund wrong nLockTime': (
        package(btc__refund_txs=[refund_tx(6000, locktime=BTC_LOCKTIME - 1)]), 'nLockTime'),
    'refund final sequence': (
        package(btc__refund_txs=[refund_tx(6000, sequence=0xffffffff)]), 'sequence'),
    'refund non-empty witness slot': (
        package(btc__refund_txs=[refund_tx(
            6000, witness=[FAKE_SIG, b'\x01', bytes.fromhex(BTC_SCRIPT)])]), 'refund witness'),
    'refund with claim-shaped witness': (
        package(btc__refund_txs=[refund_tx(
            6000, witness=[FAKE_SIG, PREIMAGE, b'\x01', bytes.fromhex(BTC_SCRIPT)])]),
        'refund witness'),
    'refund with other script': (
        package(btc__refund_txs=[refund_tx(6000, script=MARS_SCRIPT)]), 'refund witness'),
    'refund output above funding': (
        package(btc__refund_txs=[refund_tx(BTC_VALUE + 1)]), 'output value'),
    'refund zero output': (package(btc__refund_txs=[refund_tx(0)]), 'output value'),
    'refund two outputs': (
        package(btc__refund_txs=[make_tx(
            [(FUND, 1, 0xfffffffe)], [(3000, P2WPKH), (3000, P2WPKH)],
            [[FAKE_SIG, b'', bytes.fromhex(BTC_SCRIPT)]], BTC_LOCKTIME).hex()]), 'single-output'),
    'refund two inputs': (
        package(btc__refund_txs=[make_tx(
            [(FUND, 1, 0xfffffffe), (FUND, 2, 0xfffffffe)], [(3000, P2WPKH)],
            [[FAKE_SIG, b'', bytes.fromhex(BTC_SCRIPT)]] * 2, BTC_LOCKTIME).hex()]),
        'single-input'),
    'refund not segwit': (
        package(btc__refund_txs=[make_tx([(FUND, 1, 0xfffffffe)], [(3000, P2WPKH)], None,
                                         BTC_LOCKTIME).hex()]), 'segwit'),
    'refund garbage': (package(btc__refund_txs=['00' * 80]), 'not a valid'),
    'refund not hex': (package(btc__refund_txs=['xyz']), 'hex'),
    'refund not a string': (package(btc__refund_txs=[123]), 'hex'),
    'refunds in descending fee order': (
        package(btc__refund_txs=[REFUND_2, BTC_REFUND]), 'ascending fee'),
    'duplicate refunds': (package(btc__refund_txs=[BTC_REFUND, BTC_REFUND]), 'duplicate'),
    'no refunds': (package(btc__refund_txs=[]), '1 to 4'),
    'refunds not a list': (package(btc__refund_txs=BTC_REFUND), '1 to 4'),
    'too many refunds': (
        package(btc__refund_txs=[refund_tx(6000 - 100 * i) for i in range(5)]), '1 to 4'),
    'claim with the real preimage': (package(mars__claim_tx=MARS_CLAIM_REAL), 'zero bytes'),
    'claim with other placeholder': (
        package(mars__claim_tx=MARS_CLAIM_REAL.replace(PREIMAGE.hex(), '00' * 31 + '01')),
        'zero bytes'),
    'claim with refund-shaped witness': (
        package(mars__claim_tx=make_tx(
            [(FUND, 0, 0xfffffffe)], [(MARS_VALUE - 1000, P2WPKH)],
            [[FAKE_SIG, b'', bytes.fromhex(MARS_SCRIPT)]]).hex()), 'zero bytes'),
    'claim with wrong selector': (
        package(mars__claim_tx=make_tx(
            [(FUND, 0, 0xfffffffe)], [(MARS_VALUE - 1000, P2WPKH)],
            [[FAKE_SIG, bytes(32), b'', bytes.fromhex(MARS_SCRIPT)]]).hex()), 'zero bytes'),
    'claim with btc script': (
        package(mars__claim_tx=make_tx(
            [(FUND, 0, 0xfffffffe)], [(MARS_VALUE - 1000, P2WPKH)],
            [[FAKE_SIG, bytes(32), b'\x01', bytes.fromhex(BTC_SCRIPT)]]).hex()), 'zero bytes'),
    'claim not spending the outpoint': (package(mars__funding_vout=3), 'does not spend'),
    'claim output above funding': (package(mars__funding_value=MARS_VALUE - 1_000_000_000),
                                   'output value'),
    'negative vout': (package(btc__funding_vout=-1), 'out of range'),
    'float value': (package(btc__funding_value=6239.0), 'integer'),
    'bool vout': (package(mars__funding_vout=False), 'integer'),
    'string locktime': (package(btc__locktime=str(BTC_LOCKTIME)), 'integer'),
    'short txid': (package(btc__funding_txid='11' * 31), '32 bytes'),
    'oversize': (dict(package(), padding='00' * 9000), 'too large'),
    'oversize refund': (package(btc__refund_txs=[BTC_REFUND + '00' * 2000]), 'too long'),
    'side not a dict': (package(btc=[1, 2, 3]), 'must be an object'),
    'side with extra field': (package(btc__note='hi'), 'fields'),
}


@pytest.mark.parametrize('name', list(BAD_PACKAGES))
def test_malformed_package_rejected(tower, mars, name):
    pkg, match = BAD_PACKAGES[name]
    refused(tower, pkg, match)
    assert mars.broadcasts == []


def test_garbage_never_crashes(tower):
    for junk in (None, 1, [], 'x', {'version': 1}, {'version': 1, 'payment_hash160': None,
                                                    'btc': None, 'mars': None},
                 package(btc__htlc_script=''), package(mars__claim_tx=''),
                 package(mars__claim_tx='00'), package(btc__refund_txs=[None]),
                 package(btc__refund_txs=[[]]), package(payment_hash160=[H160])):
        with pytest.raises(WatchtowerError):
            register(tower, junk)


def test_idempotent_reregister(tower, clock):
    first = register(tower)
    clock.now += 500
    assert register(tower) == first
    assert len(tower.watches) == 1
    # It doesn't count against the daily limit or need the same client.
    for _ in range(20):
        assert register(tower, tag='someone-else') == first


def test_conflicting_reregister_refused(tower):
    register(tower)
    with pytest.raises(WatchtowerError, match='different package'):
        register(tower, package(btc__refund_txs=[BTC_REFUND]))
    different_claim = make_tx([(FUND, 0, 0xfffffffe)], [(MARS_VALUE - 5000, P2WPKH)],
                              [[FAKE_SIG, bytes(32), b'\x01', bytes.fromhex(MARS_SCRIPT)]]).hex()
    with pytest.raises(WatchtowerError, match='different package'):
        register(tower, package(mars__claim_tx=different_claim))
    assert tower.watches[WATCH_ID]['package']['mars']['claim_tx'] == MARS_CLAIM


def test_mars_funding_mismatch_rejected(tower, mars):
    wrong_value = mars_funding_tx(value=MARS_VALUE - 1)
    mars.txs = {txid_of(wrong_value): wrong_value}
    refused(tower, package(mars__funding_txid=txid_of(wrong_value),
                           mars__claim_tx=claim_tx(txid_of(wrong_value))), 'does not match')

    wrong_script = mars_funding_tx(script=BTC_SCRIPT)
    mars.txs = {txid_of(wrong_script): wrong_script}
    refused(tower, package(mars__funding_txid=txid_of(wrong_script),
                           mars__claim_tx=claim_tx(txid_of(wrong_script))), 'does not match')

    mars.txs = {MARS_FUND: MARS_FUNDING}
    refused(tower, package(mars__funding_txid=MARS_FUND, mars__funding_vout=1,
                           mars__claim_tx=claim_tx(vout=1)), 'does not match')


def test_mars_funding_lookup_is_advisory_when_it_cannot_answer(db_path, http, mars, clock):
    tower = make_tower(db_path, http, mars, clock)
    mars.txs = {}
    assert register(tower, funded_package())['watch_id'] == WATCH_ID
    assert tower.watches[WATCH_ID]['funding_verified'] is False

    mars.lookup_error = RuntimeError('daemon down')
    assert register(tower, other_package(0x44))['watch_id'] in tower.watches

    mars.lookup_error = None
    mars.txs = {MARS_FUND: 'not hex at all'}
    assert register(tower, dict(other_package(0x45)))['watch_id'] in tower.watches


def test_strict_funding_rejects_unknown_tx(db_path, http, mars, clock):
    tower = make_tower(db_path, http, mars, clock, strict_funding=True)
    mars.txs = {}
    refused(tower, funded_package(), 'not known')


def test_timelock_too_far_away_rejected(tower, http, mars, clock):
    http.tip = {MEMPOOL: BTC_LOCKTIME - 5000, BLOCKSTREAM: None}
    refused(tower, package(), 'too far')
    clock.now += 61      # the tip is cached for a minute
    http.tip = {MEMPOOL: BTC_TIP, BLOCKSTREAM: BTC_TIP}
    mars.height = MARS_LOCKTIME - 50_000
    refused(tower, package(), 'too far')


def test_registration_works_without_bitcoin_tip(tower, http, clock):
    http.tip = {MEMPOOL: None, BLOCKSTREAM: None}
    result = register(tower)
    assert result['expires_at'] > clock.now + 14 * DAY
    # The estimate is settled once a tip is known.
    http.tip[MEMPOOL] = BTC_TIP
    run(tower.tick())
    assert tower.watches[WATCH_ID]['expires_at'] < clock.now + 5 * DAY


def test_per_client_active_cap(tower):
    for n in range(3):
        register(tower, other_package(0x40 + n))
    with pytest.raises(WatchtowerError, match='too many swaps'):
        register(tower, other_package(0x50))
    register(tower, other_package(0x50), tag='tag-b')


def test_daily_registration_cap(db_path, http, mars, clock):
    tower = make_tower(db_path, http, mars, clock, max_active_per_tag=100,
                       max_registrations_per_day=4)
    for n in range(4):
        register(tower, other_package(0x40 + n))
    with pytest.raises(WatchtowerError, match='daily limit'):
        register(tower, other_package(0x50))
    clock.now += DAY + 1
    register(tower, other_package(0x50))


def test_global_cap(db_path, http, mars, clock):
    tower = make_tower(db_path, http, mars, clock, max_active=2)
    register(tower, other_package(0x40), tag='a')
    register(tower, other_package(0x41), tag='b')
    with pytest.raises(WatchtowerError, match='full'):
        register(tower, other_package(0x42), tag='c')


def test_finished_watch_frees_the_active_slot(db_path, http, mars, clock):
    tower = make_tower(db_path, http, mars, clock, max_active_per_tag=1)
    register(tower)
    http.spend(BTC_REFUND, confirmed=True)
    run(tower.tick())
    assert tower.status(WATCH_ID)['state'] == 'refunded'
    register(tower, other_package(0x40))


# ---------------------------------------------------------------- claim path

def test_claim_when_preimage_revealed(tower, http, mars):
    register(tower)
    run(tower.tick())
    assert mars.broadcasts == [] and http.posts == []

    http.spend(maker_claim(), confirmed=False)
    run(tower.tick())
    assert mars.broadcasts == [MARS_CLAIM_REAL]
    sent = parse_tx(bytes.fromhex(mars.broadcasts[0]))
    assert sent.witnesses[0][1] == PREIMAGE
    start = MARS_CLAIM_REAL.index(PREIMAGE.hex())
    assert (mars.broadcasts[0][:start], mars.broadcasts[0][start + 64:]) == (
        MARS_CLAIM[:start], MARS_CLAIM[start + 64:])
    status = tower.status(WATCH_ID)
    assert status['state'] == 'claimed' and status['preimage_seen'] is True
    assert status['mars_claim_txid'] == txid_of(MARS_CLAIM_REAL)
    assert PREIMAGE.hex() not in json.dumps(status)
    assert http.posts == []


def test_preimage_found_from_one_service_only(tower, http, mars):
    register(tower)
    http.spend(maker_claim(), bases=(BLOCKSTREAM,))
    run(tower.tick())
    assert mars.broadcasts == [MARS_CLAIM_REAL]


def test_spender_hex_can_come_from_the_other_service(tower, http, mars):
    register(tower)
    spender = http.spend(maker_claim(), bases=(MEMPOOL,))
    http.hex[(BLOCKSTREAM, spender)] = http.hex.pop((MEMPOOL, spender))
    run(tower.tick())
    assert mars.broadcasts == [MARS_CLAIM_REAL]


def test_preimage_in_a_batched_claim(tower, http, mars):
    register(tower)
    batch = make_tx([('77' * 32, 0, 0xffffffff), (FUND, 1, 0xffffffff)], [(9000, P2WPKH)],
                    [[FAKE_SIG, b'\x03' * 33],
                     [FAKE_SIG, PREIMAGE, b'\x01', bytes.fromhex(BTC_SCRIPT)]]).hex()
    http.spend(batch)
    run(tower.tick())
    assert mars.broadcasts == [MARS_CLAIM_REAL]


def test_claim_rebroadcast_until_confirmed(tower, http, mars, clock):
    register(tower)
    http.spend(maker_claim())
    run(tower.tick())
    run(tower.tick())
    assert mars.broadcasts == [MARS_CLAIM_REAL] * 2
    gets = len(http.gets)

    mars.confirmations = 1     # in a block but shallow: wait, don't resend
    run(tower.tick())
    assert len(mars.broadcasts) == 2 and tower.watches[WATCH_ID]['finished_at'] is None

    mars.confirmations = 3
    clock.now += 60
    run(tower.tick())
    status = tower.status(WATCH_ID)
    assert status['state'] == 'claimed' and 'confirmed' in status['detail']
    assert tower.watches[WATCH_ID]['finished_at'] == clock.now

    run(tower.tick())
    run(tower.tick())
    assert len(mars.broadcasts) == 2
    # Once the secret is known the Bitcoin lockbox is no longer polled.
    assert not any('outspend' in url for url in http.gets[gets:])


@pytest.mark.parametrize('message', ['transaction already in block chain',
                                     'txn-already-in-mempool', 'txn-already-known',
                                     'Transaction outputs already in utxo set'])
def test_already_known_claim_counts_as_success(tower, http, mars, message):
    register(tower)
    http.spend(maker_claim())
    mars.reject = message
    run(tower.tick())
    status = tower.status(WATCH_ID)
    assert status['state'] == 'claimed'
    assert status['mars_claim_txid'] == txid_of(MARS_CLAIM_REAL)


def test_rejected_claim_is_retried_then_fails_at_expiry(tower, http, mars, clock):
    register(tower)
    http.spend(maker_claim())
    mars.reject = 'bad-txns-inputs-missingorspent'
    run(tower.tick())
    status = tower.status(WATCH_ID)
    assert (status['state'], status['preimage_seen']) == ('watching', True)
    assert status['mars_claim_txid'] is None and 'missingorspent' in status['detail']

    mars.reject = None
    run(tower.tick())
    assert tower.status(WATCH_ID)['state'] == 'claimed'
    assert len(mars.broadcasts) == 2


def test_never_accepted_claim_ends_failed(tower, http, mars, clock):
    register(tower)
    http.spend(maker_claim())
    mars.reject = 'bad-txns-inputs-missingorspent'
    http.tip = {MEMPOOL: BTC_LOCKTIME + 500, BLOCKSTREAM: BTC_LOCKTIME + 500}
    clock.now += 10 * DAY
    run(tower.tick())
    assert tower.status(WATCH_ID)['state'] == 'failed'
    assert http.posts == []


def test_build_claim_refuses_wrong_preimage(tower):
    register(tower)
    record = tower.watches[WATCH_ID]
    assert build_claim(record, PREIMAGE) == MARS_CLAIM_REAL
    for wrong in (bytes(32), b'\x01' * 32, PREIMAGE[:31], PREIMAGE + b'\x00'):
        with pytest.raises(ValueError):
            build_claim(record, wrong)


# ---------------------------------------------------------------- lying services

def assert_nothing_sent(tower, http, mars):
    assert mars.broadcasts == [] and http.posts == []
    status = tower.status(WATCH_ID)
    assert status['state'] == 'watching' and status['preimage_seen'] is False
    assert status['mars_claim_txid'] is None


def test_spender_hex_not_hashing_to_txid(tower, http, mars):
    register(tower)
    # The bytes carry the real preimage, but they are not the named tx.
    http.spend(maker_claim(), claimed_txid='ab' * 32)
    run(tower.tick())
    assert_nothing_sent(tower, http, mars)


def test_spender_hash_checked_on_non_witness_bytes(tower, http, mars):
    register(tower)
    raw = bytes.fromhex(maker_claim())
    with_witness = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
    http.spend(maker_claim(), claimed_txid=with_witness)
    run(tower.tick())
    assert_nothing_sent(tower, http, mars)


def test_spender_not_spending_the_outpoint(tower, http, mars):
    register(tower)
    for unrelated in (maker_claim(txid='99' * 32), maker_claim(vout=0)):
        http.spend(unrelated)
        run(tower.tick())
        assert_nothing_sent(tower, http, mars)


def test_spender_with_wrong_32_byte_item(tower, http, mars):
    register(tower)
    for wrong in (b'\x07' * 32, bytes(32), PREIMAGE[::-1]):
        http.spend(maker_claim(preimage=wrong))
        run(tower.tick())
        assert_nothing_sent(tower, http, mars)


def test_spender_hex_garbage(tower, http, mars):
    register(tower)
    for served in ('zz', '', '00' * 50, MARS_CLAIM_REAL[:-2], '{"error": "x"}'):
        http.spend(maker_claim(), served_hex=served)
        run(tower.tick())
        assert_nothing_sent(tower, http, mars)


def test_malformed_outspend_answers(tower, http, mars):
    register(tower)
    for reply in ({'spent': True}, {'spent': True, 'txid': 'xyz'}, {'spent': 'yes'},
                  [], 'spent', {'spent': True, 'txid': 5}):
        http.outspend[(MEMPOOL, FUND, 1)] = reply
        http.outspend[(BLOCKSTREAM, FUND, 1)] = reply
        run(tower.tick())
        assert_nothing_sent(tower, http, mars)


def test_unreadable_spender_holds_refund_only_for_a_while(tower, http, mars, clock):
    register(tower)
    http.tip = {MEMPOOL: BTC_LOCKTIME + 1, BLOCKSTREAM: BTC_LOCKTIME + 1}
    http.spend(maker_claim(), claimed_txid='ab' * 32)
    run(tower.tick())
    clock.now += 600
    run(tower.tick())
    assert_nothing_sent(tower, http, mars)
    # A service cannot block the refund forever by naming a bogus spender.
    clock.now += 1800
    run(tower.tick())
    assert mars.broadcasts == []
    assert {body for _base, body in http.posts} == {BTC_REFUND}
    assert tower.status(WATCH_ID)['state'] == 'refunding'


def test_false_refund_confirmation_needs_agreement(tower, http, mars):
    register(tower)
    http.tip = {MEMPOOL: BTC_LOCKTIME, BLOCKSTREAM: BTC_LOCKTIME}
    # One service claims our refund confirmed; the other still sees it unspent.
    http.spend(BTC_REFUND, confirmed=True, bases=(MEMPOOL,))
    run(tower.tick())
    assert tower.status(WATCH_ID)['state'] == 'refunding'
    assert http.posts


# ---------------------------------------------------------------- refund path

def set_tip(http, height):
    http.tip = {MEMPOOL: height, BLOCKSTREAM: height}


def posted(http):
    bodies = [body for _base, body in http.posts]
    http.posts.clear()
    return bodies


def test_no_refund_before_locktime(tower, http, mars):
    register(tower)
    for height in (BTC_TIP, BTC_LOCKTIME - 2, BTC_LOCKTIME - 1):
        set_tip(http, height)
        run(tower.tick())
    assert http.posts == [] and mars.broadcasts == []
    assert tower.status(WATCH_ID)['state'] == 'watching'


def test_refund_posted_at_locktime_to_both_services(tower, http, mars):
    register(tower)
    set_tip(http, BTC_LOCKTIME)
    run(tower.tick())
    assert http.posts == [(MEMPOOL, BTC_REFUND), (BLOCKSTREAM, BTC_REFUND)]
    status = tower.status(WATCH_ID)
    assert status['state'] == 'refunding'
    assert status['btc_refund_txid'] == txid_of(BTC_REFUND)
    assert mars.broadcasts == []


MISSING = (400, 'sendrawtransaction RPC error: {"code":-25,"message":"bad-txns-inputs-missingorspent"}')


def test_gives_up_when_the_contract_never_appears(tower, http, mars, clock):
    """A payment that was withdrawn, or never made, leaves nothing to refund.
    The refund is retried for a while, then the watch ends instead of posting
    a dead transaction every minute for days."""
    register(tower)
    set_tip(http, BTC_LOCKTIME)
    http.post_reply = lambda base, body: MISSING
    run(tower.tick())
    assert tower.status(WATCH_ID)['state'] == 'watching'
    clock.now += 2 * 3600
    run(tower.tick())
    assert tower.status(WATCH_ID)['state'] == 'watching'
    clock.now += 3600
    run(tower.tick())
    status = tower.status(WATCH_ID)
    assert status['state'] == 'failed'
    assert 'never funded' in status['detail']
    posts = len(http.posts)
    run(tower.tick())
    assert len(http.posts) == posts and mars.broadcasts == []


def test_does_not_give_up_while_any_service_disagrees_or_is_silent(tower, http, clock):
    register(tower)
    set_tip(http, BTC_LOCKTIME)
    # One service says the input is missing; the other fails for another reason.
    http.post_reply = lambda base, body: MISSING if base == MEMPOOL else (503, 'Service Unavailable')
    run(tower.tick())
    clock.now += 6 * 3600
    run(tower.tick())
    assert tower.status(WATCH_ID)['state'] == 'watching'
    # The count starts afresh once the missing-input answers are unanimous.
    http.post_reply = lambda base, body: MISSING
    run(tower.tick())
    clock.now += 3600
    run(tower.tick())
    assert tower.status(WATCH_ID)['state'] == 'watching'
    # An accepted refund ends any doubt.
    http.post_reply = None
    run(tower.tick())
    assert tower.status(WATCH_ID)['state'] == 'refunding'


def test_tip_is_the_highest_answer(tower, http):
    register(tower)
    http.tip = {MEMPOOL: None, BLOCKSTREAM: BTC_LOCKTIME - 1}
    run(tower.tick())
    assert http.posts == []
    http.tip = {MEMPOOL: BTC_LOCKTIME - 1, BLOCKSTREAM: BTC_LOCKTIME}
    run(tower.tick())
    assert posted(http) == [BTC_REFUND, BTC_REFUND]


def test_no_refund_without_any_tip(tower, http):
    register(tower)
    http.tip = {MEMPOOL: None, BLOCKSTREAM: None}
    run(tower.tick())
    assert http.posts == []


def test_refund_escalates_every_six_blocks(tower, http):
    register(tower)
    set_tip(http, BTC_LOCKTIME + 2)
    run(tower.tick())
    assert posted(http) == [BTC_REFUND] * 2
    set_tip(http, BTC_LOCKTIME + 7)
    run(tower.tick())
    assert posted(http) == [BTC_REFUND] * 2

    set_tip(http, BTC_LOCKTIME + 8)
    run(tower.tick())
    assert posted(http) == [REFUND_2] * 2
    assert tower.status(WATCH_ID)['btc_refund_txid'] == txid_of(REFUND_2)

    set_tip(http, BTC_LOCKTIME + 14)
    run(tower.tick())
    assert posted(http) == [REFUND_3] * 2
    set_tip(http, BTC_LOCKTIME + 500)
    run(tower.tick())
    assert posted(http) == [REFUND_3] * 2    # stays on the last one
    assert tower.status(WATCH_ID)['btc_refund_txid'] == txid_of(REFUND_3)


def test_refund_in_mempool_still_escalates(tower, http):
    register(tower)
    set_tip(http, BTC_LOCKTIME)
    run(tower.tick())
    http.spend(BTC_REFUND, confirmed=False)
    set_tip(http, BTC_LOCKTIME + 6)
    run(tower.tick())
    assert posted(http)[-2:] == [REFUND_2] * 2
    assert tower.status(WATCH_ID)['state'] == 'refunding'


def test_refunded_when_spender_is_ours(tower, http, mars):
    register(tower)
    set_tip(http, BTC_LOCKTIME)
    run(tower.tick())
    posted(http)
    http.spend(REFUND_2, confirmed=True)
    run(tower.tick())
    status = tower.status(WATCH_ID)
    assert status['state'] == 'refunded'
    assert status['btc_refund_txid'] == txid_of(REFUND_2)
    assert status['preimage_seen'] is False
    run(tower.tick())
    assert http.posts == [] and mars.broadcasts == []


def test_non_final_rejection_is_retried(tower, http):
    register(tower)
    set_tip(http, BTC_LOCKTIME)
    http.post_reply = lambda base, body: (
        400, 'sendrawtransaction RPC error: {"code":-26,"message":"non-final"}')
    run(tower.tick())
    status = tower.status(WATCH_ID)
    assert status['state'] == 'watching' and status['btc_refund_txid'] is None
    assert 'non-final' in status['detail']
    http.post_reply = None
    run(tower.tick())
    assert tower.status(WATCH_ID)['state'] == 'refunding'
    assert set(posted(http)) == {BTC_REFUND}


@pytest.mark.parametrize('reply', [
    'sendrawtransaction RPC error: {"code":-27,"message":"Transaction already in block chain"}',
    'sendrawtransaction RPC error: {"code":-27,"message":"txn-already-known"}',
    'sendrawtransaction RPC error: {"code":-26,"message":"txn-already-in-mempool"}'])
def test_already_known_refund_counts_as_sent(tower, http, reply):
    register(tower)
    set_tip(http, BTC_LOCKTIME)
    http.post_reply = lambda base, body: (400, reply)
    run(tower.tick())
    status = tower.status(WATCH_ID)
    assert status['state'] == 'refunding'
    assert status['btc_refund_txid'] == txid_of(BTC_REFUND)


def test_fee_too_low_moves_to_next_refund(tower, http):
    register(tower)
    set_tip(http, BTC_LOCKTIME)
    http.post_reply = lambda base, body: (
        400, 'sendrawtransaction RPC error: {"code":-26,"message":"min relay fee not met"}')
    run(tower.tick())
    assert posted(http) == [BTC_REFUND] * 2
    http.post_reply = None
    run(tower.tick())
    assert posted(http) == [REFUND_2] * 2


def test_one_service_down_is_enough(tower, http):
    register(tower)
    set_tip(http, BTC_LOCKTIME)

    def reply(base, body):
        if base == MEMPOOL:
            raise OSError('timeout')
        return 200, txid_of(body)
    http.post_reply = reply
    run(tower.tick())
    assert tower.status(WATCH_ID)['state'] == 'refunding'


def test_preimage_wins_over_refund_after_locktime(tower, http, mars):
    register(tower)
    set_tip(http, BTC_LOCKTIME + 10)
    http.spend(maker_claim())
    run(tower.tick())
    assert http.posts == []
    assert mars.broadcasts == [MARS_CLAIM_REAL]


# ---------------------------------------------------------------- expiry

def test_expires_after_grace_and_is_purged_after_a_week(tower, http, mars, clock):
    expires_at = register(tower)['expires_at']
    http.post_reply = lambda base, body: (400, 'bad-txns-inputs-missingorspent')
    set_tip(http, BTC_LOCKTIME + 200)
    clock.now = expires_at - 1
    run(tower.tick())
    assert tower.status(WATCH_ID)['state'] == 'watching'
    clock.now = expires_at
    run(tower.tick())
    assert tower.status(WATCH_ID)['state'] == 'expired'
    http.posts.clear()
    run(tower.tick())
    assert http.posts == []

    clock.now += 7 * DAY - 1
    run(tower.tick())
    assert tower.status(WATCH_ID) is not None
    clock.now += 2
    run(tower.tick())
    assert tower.status(WATCH_ID) is None
    assert wt.WatchStore(tower.store.path).load() == {}


def test_expiry_waits_for_the_bitcoin_timelock(tower, http, clock):
    # Bitcoin blocks came far slower than estimated: keep watching.
    expires_at = register(tower)['expires_at']
    clock.now = expires_at + 3600
    set_tip(http, BTC_LOCKTIME - 5)
    run(tower.tick())
    assert tower.status(WATCH_ID)['state'] == 'watching'
    set_tip(http, BTC_LOCKTIME)
    run(tower.tick())
    assert tower.status(WATCH_ID)['state'] == 'refunding'
    # ... but not past the hard limit.
    clock.now = tower.watches[WATCH_ID]['hard_expires_at']
    run(tower.tick())
    assert tower.status(WATCH_ID)['state'] == 'expired'


# ---------------------------------------------------------------- persistence

def test_watch_survives_restart_and_claims(db_path, http, mars, clock):
    tower = make_tower(db_path, http, mars, clock)
    result = register(tower)
    tower.store.close()
    del tower

    reloaded = make_tower(db_path, http, mars, clock)
    assert reloaded.status(WATCH_ID)['state'] == 'watching'
    assert register(reloaded) == result
    http.spend(maker_claim())
    run(reloaded.tick())
    assert mars.broadcasts == [MARS_CLAIM_REAL]
    reloaded.store.close()

    # The claimed state and the secret survive too: rebroadcast continues.
    again = make_tower(db_path, http, mars, clock)
    status = again.status(WATCH_ID)
    assert status['state'] == 'claimed' and status['preimage_seen'] is True
    http.outspend.clear()
    http.hex.clear()
    run(again.tick())
    assert mars.broadcasts == [MARS_CLAIM_REAL] * 2


def test_refund_progress_survives_restart(db_path, http, mars, clock):
    tower = make_tower(db_path, http, mars, clock)
    register(tower)
    set_tip(http, BTC_LOCKTIME)
    run(tower.tick())
    posted(http)
    tower.store.close()

    reloaded = make_tower(db_path, http, mars, clock)
    assert reloaded.status(WATCH_ID)['state'] == 'refunding'
    set_tip(http, BTC_LOCKTIME + 6)
    run(reloaded.tick())
    assert posted(http) == [REFUND_2] * 2


def test_caps_survive_restart(db_path, http, mars, clock):
    tower = make_tower(db_path, http, mars, clock)
    for n in range(3):
        register(tower, other_package(0x40 + n))
    tower.store.close()
    reloaded = make_tower(db_path, http, mars, clock)
    with pytest.raises(WatchtowerError, match='too many swaps'):
        register(reloaded, other_package(0x50))


def test_corrupt_rows_are_skipped(db_path, http, mars, clock):
    tower = make_tower(db_path, http, mars, clock)
    register(tower)
    tower.store.conn.execute("INSERT INTO watches VALUES ('junk', 'not json')")
    tower.store.conn.execute("INSERT INTO watches VALUES ('junk2', '{\"watch_id\": \"x\"}')")
    tower.store.conn.commit()
    tower.store.close()
    assert list(make_tower(db_path, http, mars, clock).watches) == [WATCH_ID]


def test_registration_refused_if_it_cannot_be_stored(tower):
    tower.store.close()
    with pytest.raises(WatchtowerError, match='could not store'):
        register(tower)
    assert tower.watches == {}


# ---------------------------------------------------------------- robustness

def test_one_bad_watch_does_not_stop_the_others(tower, http, mars):
    bad = other_package(0x40)
    register(tower, bad)
    register(tower)
    bad_id = watch_id_for('40' * 32, 1, H160)
    assert list(tower.watches) == [bad_id, WATCH_ID]

    http.fail.add('40' * 32)                      # its HTTP lookups blow up
    tower.watches[bad_id]['package'] = None       # and its record is damaged
    http.spend(maker_claim())
    run(tower.tick())
    assert mars.broadcasts == [MARS_CLAIM_REAL]
    assert tower.status(WATCH_ID)['state'] == 'claimed'


def test_broadcast_exception_does_not_stop_the_others(tower, http, mars):
    register(tower, other_package(0x40))
    register(tower)
    http.spend(maker_claim(txid='40' * 32), txid='40' * 32)
    http.spend(maker_claim())
    calls = []

    async def broadcast(raw_hex):
        calls.append(raw_hex)
        if len(calls) == 1:
            raise RuntimeError('daemon exploded')
        return txid_of(raw_hex)
    tower.broadcast_mars = broadcast
    run(tower.tick())
    assert len(calls) == 2
    assert tower.status(WATCH_ID)['state'] == 'claimed'


def test_run_loop_survives_a_failing_tick(tower, http):
    register(tower)
    ticks = []

    async def tick():
        ticks.append(1)
        if len(ticks) == 1:
            raise RuntimeError('boom')
        if len(ticks) == 3:
            raise asyncio.CancelledError
    tower.tick = tick
    tower.interval = 0
    with pytest.raises(asyncio.CancelledError):
        run(tower.run())
    assert len(ticks) == 3


def test_slow_daemon_times_out(db_path, http, mars, clock):
    tower = make_tower(db_path, http, mars, clock, daemon_timeout=0.01)
    register(tower)
    http.spend(maker_claim())

    async def hang(raw_hex):
        await asyncio.sleep(5)
    tower.broadcast_mars = hang
    run(tower.tick())
    status = tower.status(WATCH_ID)
    assert (status['state'], status['preimage_seen']) == ('watching', True)


# ---------------------------------------------------------------- configuration

def test_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv('WATCHTOWER_MAX_ACTIVE_PER_CLIENT', '5')
    monkeypatch.setenv('WATCHTOWER_MAX_REGISTRATIONS_PER_DAY', '20')
    monkeypatch.setenv('WATCHTOWER_MAX_ACTIVE', '50')
    monkeypatch.setenv('WATCHTOWER_INTERVAL', '30')
    monkeypatch.setenv('WATCHTOWER_ESPLORA_URLS', 'https://a.example/api/, https://b.example')
    tower = Watchtower.from_env(str(tmp_path), http=FakeHTTP())
    assert tower.store.path == str(tmp_path / 'watchtower.sqlite')
    assert (tower.max_active_per_tag, tower.max_registrations_per_day, tower.max_active,
            tower.interval) == (5, 20, 50, 30)
    assert tower.esplora_urls == ('https://a.example/api', 'https://b.example')

    monkeypatch.setenv('WATCHTOWER_DB', str(tmp_path / 'elsewhere.db'))
    monkeypatch.delenv('WATCHTOWER_ESPLORA_URLS')
    tower = Watchtower.from_env(str(tmp_path), http=FakeHTTP())
    assert tower.store.path == str(tmp_path / 'elsewhere.db')
    assert tower.esplora_urls == (MEMPOOL, BLOCKSTREAM)


def test_enabled_from_env(monkeypatch):
    monkeypatch.delenv('WATCHTOWER_ENABLED', raising=False)
    assert wt.enabled_from_env() is True
    for value in ('0', 'false', 'off', 'No'):
        monkeypatch.setenv('WATCHTOWER_ENABLED', value)
        assert wt.enabled_from_env() is False
    monkeypatch.setenv('WATCHTOWER_ENABLED', '1')
    assert wt.enabled_from_env() is True


def test_validate_package_does_not_mutate_input():
    pkg = package()
    before = copy.deepcopy(pkg)
    validate_package(pkg)
    assert pkg == before


def test_ripemd160_fallback_is_used_when_openssl_lacks_it(monkeypatch):
    def no_ripemd(name, data=b''):
        raise ValueError('unsupported hash type ripemd160')
    monkeypatch.setattr(wt.hashlib, 'new', no_ripemd)
    assert hash160(PREIMAGE).hex() == H160


def test_server_advertises_watchtower(monkeypatch):
    from electrumx.server.session import ElectrumX
    monkeypatch.delenv('WATCHTOWER_ENABLED', raising=False)
    assert ElectrumX.atomicswap_capabilities() == {
        'abuse_controls': True, 'watchtower': True, 'watchtower_version': 1}
    monkeypatch.setenv('WATCHTOWER_ENABLED', '0')
    assert ElectrumX.atomicswap_capabilities()['watchtower'] is False


def test_registrations_share_one_tip_lookup(tower, http, clock):
    register(tower, other_package(0x40))
    register(tower, other_package(0x41))
    assert sum('tip/height' in url for url in http.gets) == 2     # one per service
    clock.now += 61
    register(tower, other_package(0x42))
    assert sum('tip/height' in url for url in http.gets) == 4


def test_registration_does_not_wait_long_for_slow_services(db_path, http, mars, clock):
    tower = make_tower(db_path, http, mars, clock, register_timeout=0.01)

    async def slow_get(url):
        await asyncio.sleep(5)
    http.get = slow_get

    async def slow_raw_tx(txid):
        await asyncio.sleep(5)
    tower.mars_raw_tx = slow_raw_tx
    assert register(tower)['expires_at'] > clock.now + 14 * DAY
