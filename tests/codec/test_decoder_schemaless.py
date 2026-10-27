#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import io
import sys
import unittest
from itertools import product

from tests.base import BaseTestCase

from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.cer import decoder as cer_decoder
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.error import SubstrateUnderrunError
from pyasn1.type import tag
from pyasn1.type import univ


class SchemalessContainerDecoderTestCase(BaseTestCase):
    codecs = (
        ('ber-def', ber_decoder, False),
        ('ber-indef', ber_decoder, True),
        ('cer-def', cer_decoder, False),
        ('cer-indef', cer_decoder, True),
        ('der', der_decoder, False),
    )
    containers = (
        (0x30, univ.SequenceOf, univ.Sequence),
        (0x31, univ.SetOf, univ.Set),
    )

    def _encodeLength(self, length):
        if length < 128:
            return bytes([length])

        octets = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        return bytes([0x80 | len(octets)]) + octets

    def _encodeConstructed(self, identifier, body, indefinite):
        if indefinite:
            return identifier + b'\x80' + body + b'\x00\x00'

        return identifier + self._encodeLength(len(body)) + body

    def _substrate(self, containerTag, tagIds, indefinite, definiteTags=False):
        components = []
        for idx, tagId in enumerate(tagIds):
            octets = [tagId & 0x7f]
            tagId >>= 7
            while tagId:
                octets.append((tagId & 0x7f) | 0x80)
                tagId >>= 7

            # Long-form context tag, explicitly wrapping a one-octet value.
            identifier = b'\xbf' + bytes(reversed(octets))
            body = b'\x04\x01' + bytes([idx % 256])
            components.append(self._encodeConstructed(
                identifier, body, indefinite and not definiteTags))

        return self._encodeConstructed(
            bytes([containerTag]), b''.join(components), indefinite)

    def _tagSet(self, tagId):
        return univ.OctetString.tagSet.tagExplicitly(
            tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, tagId))

    def _assertValue(self, value, expectedType, tagIds):
        assert type(value) is expectedType
        assert len(value) == len(tagIds)
        for idx, tagId in enumerate(tagIds):
            component = value.getComponentByPosition(idx)
            assert type(component) is univ.OctetString
            assert component.asOctets() == bytes([idx % 256])
            assert component.tagSet == self._tagSet(tagId)

    def testHomogeneous(self):
        for codec, container, tagIds in product(
                self.codecs, self.containers,
                ((32,), (32, 32, 32), (32 + sys.hash_info.modulus,) * 3)):
            name, decoder, indefinite = codec
            containerTag, sequenceType, recordType = container
            with self.subTest(codec=name, container=sequenceType, tags=tagIds):
                value, tail = decoder.decode(
                    self._substrate(containerTag, tagIds, indefinite))
                self._assertValue(value, sequenceType, tagIds)
                assert tail == b''

    def testHeterogeneous(self):
        for codec, container, tagIds in product(
                self.codecs, self.containers,
                ((32, 33), (32, 32, 33, 32), (32, 33, 34, 33, 32))):
            name, decoder, indefinite = codec
            containerTag, sequenceType, recordType = container
            with self.subTest(codec=name, container=recordType, tags=tagIds):
                value, tail = decoder.decode(
                    self._substrate(containerTag, tagIds, indefinite))
                self._assertValue(value, recordType, tagIds)
                assert tail == b''

    def testCollidingTags(self):
        for codec, container, count in product(
                self.codecs, self.containers, (16, 32, 64)):
            name, decoder, indefinite = codec
            containerTag, sequenceType, recordType = container
            with self.subTest(codec=name, container=recordType, count=count):
                # Distinct integer IDs separated by the hash modulus collide
                # without replacing TagSet's public hash implementation.
                tagIds = [32 + idx * sys.hash_info.modulus
                          for idx in range(count)]
                assert len({hash(self._tagSet(tagId)) for tagId in tagIds}) == 1
                substrate = self._substrate(containerTag, tagIds, indefinite)
                comparisons = 0
                originalEq = tag.TagSet.__eq__

                def countedEq(left, right):
                    nonlocal comparisons
                    # Exclude fixed dispatch-table lookups and count only
                    # comparisons between explicitly tagged components.
                    if (isinstance(right, tag.TagSet) and
                            len(left) == len(right) == 2 and
                            left[-1].tagClass == tag.tagClassContext and
                            right[-1].tagClass == tag.tagClassContext):
                        comparisons += 1
                    return originalEq(left, right)

                tag.TagSet.__eq__ = countedEq
                try:
                    value, tail = decoder.decode(substrate)
                finally:
                    tag.TagSet.__eq__ = originalEq

                self._assertValue(value, recordType, tagIds)
                assert tail == b''
                assert comparisons <= count, (
                    '%d tag comparisons for %d components' %
                    (comparisons, count))

    def testStreaming(self):
        class NonBlockingStream(io.BytesIO):
            def read(self, size=-1):
                chunk = io.BytesIO.read(self, size)
                if not chunk and size:
                    return None
                return chunk

        for codec, container, tagIds in product(
                self.codecs, self.containers,
                ((32, 32, 32), (32, 32, 32 + sys.hash_info.modulus, 32))):
            name, decoder, indefinite = codec
            containerTag, sequenceType, recordType = container
            expectedType = sequenceType if len(set(tagIds)) == 1 else recordType
            with self.subTest(codec=name, container=expectedType, tags=tagIds):
                # Keep explicit wrappers definite so resumption exercises
                # the container's own indefinite-length path.
                substrate = self._substrate(
                    containerTag, tagIds, indefinite, definiteTags=True)
                stream = NonBlockingStream()
                iterator = iter(decoder.StreamingDecoder(stream))
                supplied = 0
                underruns = 0
                while True:
                    value = next(iterator)
                    if not isinstance(value, SubstrateUnderrunError):
                        break

                    assert supplied < len(substrate), 'Decoder did not resume'
                    position = stream.tell()
                    stream.seek(0, io.SEEK_END)
                    supplied += stream.write(substrate[supplied:supplied + 3])
                    stream.seek(position)
                    underruns += 1

                assert underruns > 1
                assert supplied == stream.tell() == len(substrate)
                self._assertValue(value, expectedType, tagIds)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
