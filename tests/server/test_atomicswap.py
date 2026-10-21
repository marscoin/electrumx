import pytest

from electrumx.server.atomicswap import DAY, SwapRelay, SwapRelayError

MAKER = '198.51.100.7'
TAKER = '203.0.113.10'
OTHER = '203.0.113.99'


class Clock:
    def __init__(self, now=1_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


def offer(offer_id='o1', expires_in=3600, now=1_000_000.0, **extra):
    o = {'offer_id': offer_id, 'mars_amount_sat': 104_0000_0000, 'btc_amount_sat': 3652,
         'maker_pubkey': '02' + 'aa' * 32, 'payment_hash160': 'bb' * 20,
         'expires_at': now + expires_in}
    o.update(extra)
    return o


def acceptance(pubkey='03' + 'cc' * 32, address='bc1qtaker'):
    return {'taker_pubkey': pubkey, 'btc_htlc_address': address, 'btc_locktime': 900_000}


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def relay(clock):
    return SwapRelay(secret=b'test', max_open_per_tag=1, max_accepts_per_day=3,
                     strike_hours=24, clock=clock)


# ---------------------------------------------------------------- tags

def test_tag_hides_ip_and_is_stable(relay):
    t = relay.tag(TAKER)
    assert t == relay.tag(TAKER)
    assert TAKER not in t and len(t) == 32
    assert relay.tag(OTHER) != t


def test_tag_depends_on_secret():
    assert SwapRelay(secret=b'a').tag(TAKER) != SwapRelay(secret=b'b').tag(TAKER)


def test_ipv6_grouped_by_slash_64(relay):
    assert relay.tag('2001:db8:1:2::1') == relay.tag('2001:db8:1:2:ffff::9')
    assert relay.tag('2001:db8:1:2::1') != relay.tag('2001:db8:1:3::1')


def test_ipv4_mapped_ipv6_matches_ipv4(relay):
    assert relay.tag('::ffff:203.0.113.10') == relay.tag(TAKER)


# ---------------------------------------------------------------- offers

def test_post_and_list(relay):
    assert relay.post_offer(offer(), MAKER) is True
    assert [o['offer_id'] for o in relay.get_offers()] == ['o1']


def test_expired_offers_disappear(relay, clock):
    relay.post_offer(offer(expires_in=60), MAKER)
    clock.now += 61
    assert relay.get_offers() == []


def test_only_poster_can_replace(relay):
    relay.post_offer(offer(), MAKER)
    relay.post_offer(offer(btc_amount_sat=999_999), OTHER)
    assert relay.get_offers()[0]['btc_amount_sat'] == 3652
    relay.post_offer(offer(btc_amount_sat=4000), MAKER)
    assert relay.get_offers()[0]['btc_amount_sat'] == 4000


def test_peer_copy_never_overwrites_and_cannot_be_claimed(relay):
    relay.post_offer(offer(), MAKER)
    relay.post_offer(offer(btc_amount_sat=1), OTHER, from_peer=True)
    assert relay.get_offers()[0]['btc_amount_sat'] == 3652

    relay.post_offer(offer('o2'), OTHER, from_peer=True)
    relay.post_offer(offer('o2', btc_amount_sat=1), OTHER)
    with pytest.raises(SwapRelayError):
        relay.cancel_offer('o2', OTHER)


def test_gossip_only_once(relay):
    assert relay.post_offer(offer(), MAKER) is True
    relay.cancel_offer('o1', MAKER)
    assert relay.post_offer(offer(), MAKER) is False


def test_only_poster_can_cancel(relay):
    relay.post_offer(offer(), MAKER)
    with pytest.raises(SwapRelayError):
        relay.cancel_offer('o1', OTHER)
    assert relay.cancel_offer('o1', MAKER) is True
    assert relay.cancel_offer('o1', MAKER) is False


# ---------------------------------------------------------------- acceptances

def test_first_accept_wins(relay):
    relay.post_offer(offer(), MAKER)
    assert relay.accept_offer('o1', acceptance(), TAKER) is True
    with pytest.raises(SwapRelayError, match='already taken'):
        relay.accept_offer('o1', acceptance(pubkey='03' + 'dd' * 32), OTHER)
    assert relay.get_acceptance('o1')['taker_tag'] == relay.tag(TAKER)


def test_retrying_the_same_accept_is_fine(relay):
    relay.post_offer(offer(), MAKER)
    relay.accept_offer('o1', acceptance(), TAKER)
    assert relay.accept_offer('o1', acceptance(), TAKER) is True


def test_cannot_accept_unknown_or_expired_offer(relay, clock):
    with pytest.raises(SwapRelayError, match='unknown'):
        relay.accept_offer('nope', acceptance(), TAKER)
    relay.post_offer(offer(expires_in=10), MAKER)
    clock.now += 11
    with pytest.raises(SwapRelayError, match='unknown'):
        relay.accept_offer('o1', acceptance(), TAKER)


def test_acceptance_carries_tag_not_ip(relay):
    relay.post_offer(offer(), MAKER)
    relay.accept_offer('o1', acceptance(), TAKER)
    record = relay.get_acceptance('o1')
    assert TAKER not in repr(record)
    assert record['taker_pubkey'] == acceptance()['taker_pubkey']


def test_one_open_acceptance_per_client(relay):
    relay.post_offer(offer('o1'), MAKER)
    relay.post_offer(offer('o2'), MAKER)
    relay.accept_offer('o1', acceptance(), TAKER)
    with pytest.raises(SwapRelayError, match='in progress'):
        relay.accept_offer('o2', acceptance(), TAKER)
    relay.accept_offer('o2', acceptance(), OTHER)


def test_open_slot_frees_when_offer_ends(relay):
    relay.post_offer(offer('o1'), MAKER)
    relay.post_offer(offer('o2'), MAKER)
    relay.accept_offer('o1', acceptance(), TAKER)
    relay.cancel_offer('o1', MAKER)
    relay.accept_offer('o2', acceptance(), TAKER)


def test_daily_limit(relay, clock):
    for i in range(3):
        relay.post_offer(offer(f'o{i}'), MAKER)
        relay.accept_offer(f'o{i}', acceptance(), TAKER)
        relay.cancel_offer(f'o{i}', MAKER)
    relay.post_offer(offer('o9', now=clock.now), MAKER)
    with pytest.raises(SwapRelayError, match='daily limit'):
        relay.accept_offer('o9', acceptance(), TAKER)
    clock.now += DAY + 1
    relay.post_offer(offer('o10', now=clock.now), MAKER)
    assert relay.accept_offer('o10', acceptance(), TAKER) is True


# ---------------------------------------------------------------- abandoned swaps

def test_report_abandoned_blocks_taker(relay, clock):
    relay.post_offer(offer('o1'), MAKER)
    relay.accept_offer('o1', acceptance(), TAKER)
    assert relay.report_abandoned('o1', MAKER) is True
    assert relay.get_acceptance('o1') is None

    relay.post_offer(offer('o2'), MAKER)
    with pytest.raises(SwapRelayError, match='abandoned'):
        relay.accept_offer('o2', acceptance(), TAKER)
    relay.accept_offer('o2', acceptance(), OTHER)

    clock.now += 24 * 3600 + 1
    relay.post_offer(offer('o3', now=clock.now), MAKER)
    assert relay.accept_offer('o3', acceptance(), TAKER) is True


def test_only_poster_can_report(relay):
    relay.post_offer(offer(), MAKER)
    relay.accept_offer('o1', acceptance(), TAKER)
    with pytest.raises(SwapRelayError, match='only the client'):
        relay.report_abandoned('o1', OTHER)
    assert relay.get_acceptance('o1') is not None


def test_report_without_acceptance_is_noop(relay):
    relay.post_offer(offer(), MAKER)
    assert relay.report_abandoned('o1', MAKER) is False


# ---------------------------------------------------------------- configuration

def test_from_env(monkeypatch):
    monkeypatch.setenv('ATOMICSWAP_TAG_SECRET', 'fixed')
    monkeypatch.setenv('ATOMICSWAP_MAX_OPEN_PER_CLIENT', '2')
    monkeypatch.setenv('ATOMICSWAP_MAX_ACCEPTS_PER_DAY', '10')
    monkeypatch.setenv('ATOMICSWAP_BLOCK_HOURS', '6')
    r = SwapRelay.from_env()
    assert (r.max_open_per_tag, r.max_accepts_per_day, r.strike_seconds) == (2, 10, 6 * 3600)
    assert r.tag(TAKER) == SwapRelay(secret=b'fixed').tag(TAKER)
