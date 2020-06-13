#
# convention: a parent has two children
#
#    parent
#     / \
#    /   \
#   c1   c2   children
#


from electrumx.lib.hash import blake2b

def Hash(x, y=b''):
    return blake2b(x+y)


class Accumulator:

    def __init__(self):
        self.acc = {}     # n -> hash
        self.counter = 0

    def leaf(self, utxo):
        return Hash(utxo)

    def parent(self, x, y, is_left):
        # is_left: whether y is the left leaf
        if is_left:
            x, y = y, x
        return Hash(x + y)

    def add(self, utxo):
        n = self.leaf(utxo)
        h = 0
        r = self.acc.pop(h, None)
        while r != None:
            n = self.parent(r, n, False)  # n is not left
            h += 1
            r = self.acc.pop(h, None)
        self.acc[h] = n
        self.counter += 1

    def verify(self, utxo, proof):
        n = self.leaf(utxo)
        h = 0
        while h < len(proof):
            p, is_left = proof[h]
            n = self.parent(p, n, is_left)
            h += 1
        assert self.acc.get(h)._hash == n, (self.acc.get(h), n)

    def delete(self, utxo, proof):
        n = None
        h = 0
        while h < len(proof):
            p, is_left = proof[h]
            if n is not None:
                n = self.parent(p, n, is_left)
            else:
                r = self.acc.pop(h, None)
                if r is None:
                    self.acc[h] = p
                else:
                    n = self.parent(p, r, is_left)
            h += 1
        self.acc[h] = n
        self.counter -= 1

    def dump(self):
        n = max(self.acc.keys())
        return [self.acc.get(i) for i in range(0, n + 1)]


#######################

class Leaf:
    def __init__(self, utxo):
        self.parent = None
        self._hash = Hash(utxo)

class Parent:
    def __init__(self, x, y, is_left):
        if is_left:
            x, y = y, x
        self.parent = None
        self._hash = Hash(x._hash + y._hash)
        x.parent = self
        y.parent = self
        x.sibling = y, True
        y.sibling = x, False


class Forest:

    def __init__(self):
        self.acc = {}     # n -> hash
        self.counter = 0
        self.utxos = {}   # hash -> Node

    def get_leaf(self, utxo):
        return self.utxos.get(utxo)

    def get_proof(self, utxo):
        l = self.get_leaf(utxo)
        proof = []
        while l.parent is not None:
            S, b = l.sibling
            proof.append((S._hash, b))
            l = l.parent
        return proof

    def get_pos(self, l:Leaf):
        p = 0
        h = 0
        while l.parent is not None:
            s, b = l.sibling
            p |= int(b) * pow(2, h)
            h += 1
            l = l.parent
        p += pow(2, h)
        return p

    def add(self, utxo):
        n = Leaf(utxo)
        self.utxos[utxo] = n
        h = 0
        r = self.acc.pop(h, None)
        while r != None:
            n = Parent(r, n, False)  # n is not left
            h += 1
            r = self.acc.pop(h, None)
        self.acc[h] = n
        self.counter += 1

    def verify_leaf(self, utxo):
        proof = self.get_proof(utxo)
        self.verify(utxo, proof)

    def remove(self, utxo):
        n = None
        h = 0
        N = self.get_leaf(utxo)
        while N.parent is not None:
            P, is_left = N.sibling
            if n is not None:
                n = Parent(P, n, is_left)
            else:
                r = self.acc.pop(h, None)
                if r is None:
                    self.acc[h] = P
                    P.parent = None
                else:
                    n = Parent(P, r, is_left)
            h += 1
            N = N.parent
        self.acc[h] = n
        self.counter -= 1
        # we need to store the proof, for block verification
        self.utxos.pop(utxo)

    def batch_delete(self, utxo_set):
        if not utxo_set:
            return
        #print('batch_delete', len(utxo_set))
        leaves = [self.utxos.pop(utxo) for utxo in utxo_set]
        to_delete = [(self.get_pos(l), l) for l in leaves]
        to_delete = sorted(to_delete)
        # height of the highest tree
        max_h = max([x[0].bit_length() for x in to_delete])
        touched = set()
        for h in range(max_h):
            #print('h=%d:'% h, 'to_delete=', [(x[0], x[1]._hash) for x in to_delete])
            if not to_delete:
                #print('terminating at level', h)
                break
            #print('to delete0', h, [x[0] for x in to_delete])
            # delete roots marked for deletion
            k0, node_0 = to_delete[0]
            if node_0 == self.acc.get(h):
                self.acc.pop(h)
                to_delete = to_delete[1:]
            next_keys = []
            # 1. twins:
            for i in range(len(to_delete) - 1):
                if to_delete[i] is None:
                    continue
                ki, node_i = to_delete[i]
                kj, node_j = to_delete[i+1]
                if kj == ki ^ 1:
                    #print('twins')
                    assert node_i.parent == node_j.parent
                    #delete them:
                    to_delete[i] = None
                    to_delete[i+1] = None
                    #mark parent for deletion
                    next_keys.append((ki >> 1, node_i.parent))
            to_delete = list(filter(None, to_delete))

            # 2. swaps
            for i in range(0, len(to_delete) - 1, 2):
                ki, node_i = to_delete[i]
                kj, node_j = to_delete[i+1]
                assert kj != ki ^ 1, (ki, kj)
                assert node_i.parent is not None, (ki, 'h=%d'%h)
                assert node_j.parent is not None, (kj, 'h=%d'%h)
                # move node from kj^1 to ki
                si, bi = node_i.sibling
                sj, bj = node_j.sibling
                #print('swap', sj._hash, '->', node_i._hash )
                sj.sibling = si, bi
                si.sibling = sj, not bi
                sj.parent = si.parent
                touched.add(si)
                to_delete[i] = None
                to_delete[i+1] = None
                # mark parent for deletion
                next_keys.append((kj >> 1, node_j.parent))
                #
                del node_j

            # 3. root
            to_delete = list(filter(None, to_delete))
            if to_delete:
                assert len(to_delete) == 1
                ki, node_i = to_delete[0]
                si, b = node_i.sibling
                r = self.acc.pop(h, None)
                #print('root', bin(ki), r)
                if r is not None:
                    assert r.parent is None
                    r.parent = si.parent
                    r.sibling = si, b
                    si.sibling = r, not b
                    touched.add(si)
                else:
                    si.parent = None
                    self.acc[h] = si
                    # mark parent for deletion
                    next_keys.append((ki >> 1, node_i.parent))
                del node_i

            # 4. climb
            next_touched = set()
            for ni in touched:
                if ni.parent:
                    si, b = ni.sibling
                    x = Hash(si._hash + ni._hash)
                    ni.parent._hash = x
                    next_touched.add(ni.parent)
            touched = next_touched
            to_delete = sorted(next_keys) # need to be sorted again


    def dump(self):
        n = max(self.acc.keys())
        roots = [self.acc.get(i) for i in range(0, n + 1)]
        return [r._hash if r else None for r in roots]



######################
#
#  


from io import BytesIO

    
HSIZE = 32


def treesize(h):
    return pow(2, h+1) - 1


def first_zero_bit(n):
    i = 0
    while n % 2:
        n = n >> 1
        i += 1
    return i


class HashTree:

    def __init__(self, h):
        self.h = h
        self.size = treesize(self.h)
        self.zero = bytearray().zfill(HSIZE)
        data = bytearray().zfill(self.size * HSIZE)
        self.data = BytesIO(data)

    def read(self, pos, n):
        self.data.seek(pos*HSIZE)
        return self.data.read(n*HSIZE)
        #return self.data[pos*HSIZE:(pos + n)*HSIZE]

    def write(self, pos, data):
        self.data.seek(pos*HSIZE)
        return self.data.write(data)
        #self.data[pos*HSIZE:pos*HSIZE + len(data)] = data

    def get_data(self):
        return self.read(0, self.size)

    def get_hash(self, index):
        return self.read(index, 1)

    def set_hash(self, index, _hash):
        assert len(_hash) == HSIZE, (len(_hash), HSIZE)
        self.write(index, _hash)

    def get_root(self):
        return self.get_hash(self.size - 1)

    def set_root(self, _hash):
        return self.set_hash(self.size - 1, _hash)

    def blank(self):
        self.set_root(self.zero)

    def is_empty(self):
        return self.get_root() == self.zero

    def get_offset(self, s):
        size = treesize(self.h - len(s))
        offset = 0
        for i in range(len(s)):
            if s[i] == '1':
                offset += treesize(self.h - 1 - i)
        return offset, size

    def write_tree(self, s, data):
        offset, size = self.get_offset(s)
        assert len(data) == size *HSIZE
        self.write(offset, data)

    def read_tree(self, s):
        offset, size = self.get_offset(s)
        return self.read(offset, size)

    def read_root(self, s):
        offset, size = self.get_offset(s)
        return self.read(offset + size - 1, 1)

    def write_root(self, s, data):
        offset, size = self.get_offset(s)
        self.write(offset + size - 1, data)

    def update_root(self, s):
        r1 = self.read_root(s + '0')
        r2 = self.read_root(s + '1')
        self.write_root(s, Hash(r1, r2))

    def get_leaves(self, s=''):
        if len(s) == self.h:
            return [bytes(self.read_tree(s))]
        else:
            l1 = self.get_leaves(s + '0')
            l2 = self.get_leaves(s + '1')
            return l1 + l2

    def maybe_get_leaves(self):
        self.data.seek(0)
        for i in range(self.size):
            yield self.data.read(HSIZE)

"""
indices of leaves:     
0 : 0
1 : 0, 1
2 : 0, 1, -, 3, 4, -, -
3 : 0, 1, -, 3, 4, -, -, 7, 8, -, 10, 11, -, -, -

0 : 0
1 : -, 1, 2
2 : -, -, 



size(h) = pow(2, h+1) - 1

offset(s) = sum( s_i * size(i) )


simpler mapping:
 - each row has the same width

0

0, 
1, 
(01)

0, 1, (01)
2, 3, (23)
(0123), -, -


    size(h) = size(h-1) * 3
=>  size(h) = pow(3,h)


def offset(s):

   size(h)


"""

FORBIDDEN = [
    bytes.fromhex('d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599')[::-1],
    bytes.fromhex('e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468')[::-1]
]



class HashForest:

    def __init__(self):
        self.acc = {}
        self.counter = 0
        self.utxos = {} # hash -> index

    def get_hashtree(self, h):
        # allocate data if needed
        if h not in self.acc:
            self.acc[h] = HashTree(h)
        return self.acc[h]

    def decrement_indices(self, r, prefix):
        n = len(prefix)
        #for l in r.get_leaves([]):
        for l in r.maybe_get_leaves():
            s = self.utxos.get(l)
            if s is None:
                continue
            assert s[0:n] == prefix
            #s >> n
            s = s[n:]
            self.utxos[l] = s

    def increment_indices(self, r, prefix):
        n = len(prefix)
        #for l in r.get_leaves([]):
        for l in r.maybe_get_leaves():
            s = self.utxos.get(l)
            if s is None:
                continue
            self.utxos[l] = prefix + s

    def add(self, utxo):
        target = self.get_hashtree(first_zero_bit(self.counter))
        _hash = Hash(utxo)
        # write leaf into target
        s = '0'*target.h
        target.write_tree(s, _hash)
        self.utxos[_hash] = s
        for h in range(target.h):
            r = self.acc[h]
            s = s[0:-1]
            target.write_tree(s + '1', r.get_data())
            target.update_root(s)
            self.increment_indices(r, s + '1')
            r.blank()
        self.counter += 1

    def remove(self, utxo):
        utxo_hash = Hash(utxo)
        s = self.utxos.pop(utxo_hash)
        target_h = len(s)
        target = self.acc[target_h]
        assert target.read_tree(s) == utxo_hash
        n = None
        h = 0
        for h in range(target_h):
            parent, is_left = s[0:-1], s[-1]
            if n is not None:
                target.update_root(parent)
                n = parent
            else:
                r = self.acc[h]
                if r.is_empty():
                    sibling = parent + ('1' if is_left == '0' else '0')
                    data = target.read_tree(sibling)
                    r.write_tree('', data)
                    self.decrement_indices(r, sibling) # remove parent path to leaves of r 
                else:
                    target.write_tree(s, r.get_data())
                    target.update_root(parent) # should maybe update all roots..
                    self.increment_indices(r, s) # prepend parent path to indices of r
                    n = parent
                    r.blank()
            s = parent
        if n is not None:
            n_data = target.read_tree(n)
            self.acc[target_h].write_tree('', n_data)
        else:
            self.acc[target_h].blank()
        self.counter -= 1
        # we need to store the proof, for block verification

    def serialize_utxo(self, tx_hash: bytes, index: int):
        return tx_hash[::-1] + index.to_bytes(4, 'big')

    def add_utxo(self, tx_hash, index):
        if tx_hash not in FORBIDDEN:
            self.add(self.serialize_utxo(tx_hash, index))

    def remove_utxo(self, tx_hash, index):
        if tx_hash not in FORBIDDEN:
            self.remove(self.serialize_utxo(tx_hash, index))