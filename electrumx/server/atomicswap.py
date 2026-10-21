'''Atomic swap order-book relay: state and abuse controls.

ElectrumX relays atomic swap offers and acceptances between wallets. It
never touches funds; the wallets verify every HTLC on chain before they
lock anything. This module keeps the relay state and the anti-abuse rules
separate from the network code so they can be tested on their own.

Abuse controls (no wallet changes needed):

* An offer belongs to the client that posted it. Only that client can
  replace or cancel it. Copies relayed from peer servers never overwrite
  an existing offer and can't be claimed by a client.
* First accept wins. A second taker gets "offer already taken".
* Each client may have one open acceptance at a time and a few per day.
* The maker can report an acceptance that never became a funded BTC
  lockbox. The taker is then blocked from accepting for a while.

Clients are identified by a "tag": a keyed hash of their IP address
(IPv6 by /64, because addresses within a /64 are trivial to rotate).
Raw IPs are never stored or returned. Unless ATOMICSWAP_TAG_SECRET is
set, tags change whenever the server restarts.

These limits stop casual abuse. They don't stop someone with many
addresses, which is why makers should also cap how much inventory can be
locked at once.
'''

import hashlib
import hmac
import os
import time
from ipaddress import IPv6Address, ip_address

DAY = 24 * 3600


class SwapRelayError(Exception):
    '''A request the relay refuses; the message is safe to show a user.'''


def _env_int(name, default):
    value = os.environ.get(name)
    return int(value) if value not in (None, '') else default


class SwapRelay:

    def __init__(self, secret=None, max_open_per_tag=1, max_accepts_per_day=6,
                 strike_hours=24, clock=time.time):
        self.secret = secret or os.urandom(32)
        self.max_open_per_tag = max_open_per_tag
        self.max_accepts_per_day = max_accepts_per_day
        self.strike_seconds = strike_hours * 3600
        self.clock = clock
        self.offers = {}        # offer_id -> offer dict
        self.owner = {}         # offer_id -> poster tag, or None if relayed by a peer
        self.seen = set()       # offer_ids already gossiped
        self.acceptances = {}   # offer_id -> acceptance dict
        self.accept_times = {}  # tag -> timestamps of accepts in the last day
        self.blocked_until = {}  # tag -> timestamp

    @classmethod
    def from_env(cls):
        secret = os.environ.get('ATOMICSWAP_TAG_SECRET')
        return cls(
            secret=secret.encode() if secret else None,
            max_open_per_tag=_env_int('ATOMICSWAP_MAX_OPEN_PER_CLIENT', 1),
            max_accepts_per_day=_env_int('ATOMICSWAP_MAX_ACCEPTS_PER_DAY', 6),
            strike_hours=_env_int('ATOMICSWAP_BLOCK_HOURS', 24),
        )

    # ------------------------------------------------------------ identity

    def tag(self, host):
        '''Keyed hash of a client address; IPv6 is grouped by /64.'''
        try:
            addr = ip_address(str(host))
        except ValueError:
            key = b'name:' + str(host).encode()
        else:
            if isinstance(addr, IPv6Address) and addr.ipv4_mapped:
                addr = addr.ipv4_mapped
            if isinstance(addr, IPv6Address):
                key = b'v6:' + addr.packed[:8]
            else:
                key = b'v4:' + addr.packed
        return hmac.new(self.secret, key, hashlib.sha256).hexdigest()[:32]

    # ------------------------------------------------------------ housekeeping

    def _prune(self):
        now = self.clock()
        for offer_id in [k for k, v in self.offers.items()
                         if v.get('expires_at', 0) < now]:
            del self.offers[offer_id]
            self.owner.pop(offer_id, None)
            self.seen.discard(offer_id)
        for offer_id in [k for k in self.acceptances if k not in self.offers]:
            del self.acceptances[offer_id]
        for tag in list(self.accept_times):
            recent = [t for t in self.accept_times[tag] if t > now - DAY]
            if recent:
                self.accept_times[tag] = recent
            else:
                del self.accept_times[tag]
        for tag in [k for k, v in self.blocked_until.items() if v <= now]:
            del self.blocked_until[tag]

    # ------------------------------------------------------------ offers

    def get_offers(self):
        self._prune()
        return list(self.offers.values())

    def post_offer(self, offer, host=None, from_peer=False):
        '''Store an offer. Returns True if it is new and should be gossiped.'''
        offer_id = offer['offer_id']
        self._prune()
        if offer_id in self.offers:
            # Only the original poster may replace an offer. Relayed copies
            # never overwrite, and nobody can claim a relayed offer.
            if from_peer or self.owner.get(offer_id) != self.tag(host):
                return False
            self.offers[offer_id] = offer
            return False
        self.offers[offer_id] = offer
        self.owner[offer_id] = None if from_peer else self.tag(host)
        is_new = offer_id not in self.seen
        self.seen.add(offer_id)
        return is_new

    def cancel_offer(self, offer_id, host):
        if offer_id not in self.offers:
            return False
        if self.owner.get(offer_id) != self.tag(host):
            raise SwapRelayError('only the client that posted an offer can cancel it')
        del self.offers[offer_id]
        self.owner.pop(offer_id, None)
        self.acceptances.pop(offer_id, None)
        return True

    # ------------------------------------------------------------ acceptances

    def accept_offer(self, offer_id, acceptance, host):
        self._prune()
        if offer_id not in self.offers:
            raise SwapRelayError('unknown or expired offer')
        tag = self.tag(host)
        existing = self.acceptances.get(offer_id)
        if existing is not None:
            # A retry of the same acceptance is fine; anything else is a second taker.
            same = (existing['taker_tag'] == tag
                    and existing.get('taker_pubkey') == acceptance.get('taker_pubkey')
                    and existing.get('btc_htlc_address') == acceptance.get('btc_htlc_address'))
            if same:
                return True
            raise SwapRelayError('offer already taken')
        now = self.clock()
        if self.blocked_until.get(tag, 0) > now:
            raise SwapRelayError('too many abandoned swaps from this connection; '
                                 'try again later')
        open_count = sum(1 for a in self.acceptances.values() if a['taker_tag'] == tag)
        if open_count >= self.max_open_per_tag:
            raise SwapRelayError('you already have a swap in progress; '
                                 'finish it before accepting another')
        if len(self.accept_times.get(tag, [])) >= self.max_accepts_per_day:
            raise SwapRelayError('daily limit for accepting offers reached')
        record = dict(acceptance)
        record['taker_tag'] = tag
        record['accepted_at'] = now
        self.acceptances[offer_id] = record
        self.accept_times.setdefault(tag, []).append(now)
        return True

    def get_acceptance(self, offer_id):
        self._prune()
        return self.acceptances.get(offer_id)

    def report_abandoned(self, offer_id, host):
        '''The maker reports that the taker never funded the BTC lockbox.'''
        self._prune()
        if offer_id not in self.offers:
            raise SwapRelayError('unknown or expired offer')
        if self.owner.get(offer_id) != self.tag(host):
            raise SwapRelayError('only the client that posted an offer can report it')
        acceptance = self.acceptances.pop(offer_id, None)
        if acceptance is None:
            return False
        self.blocked_until[acceptance['taker_tag']] = self.clock() + self.strike_seconds
        return True
