#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import sys
import unittest
from itertools import product

from tests.base import BaseTestCase

from pyasn1.codec.ber import encoder as ber_encoder
from pyasn1.codec.cer import encoder as cer_encoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.native import encoder as native_encoder
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ


class DefaultedComponentsNoMutationTestCase(BaseTestCase):
    codecs = (
        ('ber-def', lambda value: ber_encoder.encode(value, defMode=True)),
        ('ber-indef', lambda value: ber_encoder.encode(value, defMode=False)),
        ('cer', cer_encoder.encode),
        ('der', der_encoder.encode),
        ('native', native_encoder.encode),
    )

    def _makeRecord(self, containerType, optionalPresent, defaultState):
        roomTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        houseTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)

        record = containerType(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.OptionalNamedType(
                    'room', univ.Integer().subtype(implicitTag=roomTag)
                ),
                namedtype.DefaultedNamedType(
                    'house', univ.Integer(0).subtype(implicitTag=houseTag)
                )
            )
        )

        record['id'] = 123

        if optionalPresent:
            record['room'] = 321

        if defaultState == 'explicit-default':
            record['house'] = 0

        elif defaultState == 'explicit-nondefault':
            record['house'] = 7

        elif defaultState != 'absent':
            raise AssertionError('unknown default state %r' % (defaultState,))

        return record

    def _snapshot(self, value, names):
        snapshot = []

        for name in names:
            component = value.getComponentByName(name, instantiate=False)

            if component is univ.noValue:
                snapshot.append((name, univ.noValue))

            else:
                snapshot.append(
                    (name, component.prettyPrint(), component.isValue,
                     str(component.tagSet))
                )

        return tuple(snapshot)

    def _assertDefaultedState(self, record, defaultState):
        component = record.getComponentByName('house', instantiate=False)

        if defaultState == 'absent':
            assert component is univ.noValue

        else:
            assert component is not univ.noValue

    def _assertEncodedRecord(self, codecName, encoded, optionalPresent, defaultState):
        if codecName == 'native':
            if optionalPresent:
                assert encoded['room'] == 321
            else:
                assert 'room' not in encoded

            if defaultState in ('absent', 'explicit-default'):
                assert encoded['house'] == 0
            else:
                assert encoded['house'] == 7

            return

        if optionalPresent:
            assert b'\x80\x02\x01\x41' in encoded
        else:
            assert b'\x80\x02\x01\x41' not in encoded

        if defaultState == 'explicit-nondefault':
            assert b'\x81\x01\x07' in encoded
        else:
            assert b'\x81\x01\x00' not in encoded
            assert b'\x81\x01\x07' not in encoded

    def testOptionalAndDefaultedComponentsAreNotMutated(self):
        for containerType, optionalPresent, defaultState in product(
                (univ.Sequence, univ.Set),
                (False, True),
                ('absent', 'explicit-default', 'explicit-nondefault')):

            for codecName, encodeFun in self.codecs:
                with self.subTest(
                        containerType=containerType.__name__,
                        optionalPresent=optionalPresent,
                        defaultState=defaultState,
                        codecName=codecName):

                    record = self._makeRecord(
                        containerType, optionalPresent, defaultState
                    )
                    before = self._snapshot(record, ('id', 'room', 'house'))

                    encoded = encodeFun(record)

                    assert self._snapshot(record, ('id', 'room', 'house')) == before
                    self._assertDefaultedState(record, defaultState)

                    if not optionalPresent:
                        assert record.getComponentByName(
                            'room', instantiate=False
                        ) is univ.noValue

                    self._assertEncodedRecord(
                        codecName, encoded, optionalPresent, defaultState
                    )

    def testAbsentDefaultedConstructedComponentIsNotMutated(self):
        inner = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.OptionalNamedType('note', univ.OctetString()),
                namedtype.DefaultedNamedType('count', univ.Integer(5)),
            )
        )

        outer = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.DefaultedNamedType('inner', inner),
            )
        )

        expected = {
            'ber-def': bytes((48, 3, 2, 1, 1)),
            'ber-indef': bytes((48, 128, 2, 1, 1, 0, 0)),
            'cer': bytes((48, 128, 2, 1, 1, 0, 0)),
            'der': bytes((48, 3, 2, 1, 1)),
            'native': {'id': 1, 'inner': {'count': 5}},
        }

        for codecName, encodeFun in self.codecs:
            with self.subTest(codecName=codecName):
                record = outer.clone()
                record['id'] = 1

                before = self._snapshot(record, ('id', 'inner'))

                assert encodeFun(record) == expected[codecName]
                assert self._snapshot(record, ('id', 'inner')) == before
                assert record.getComponentByName(
                    'inner', instantiate=False
                ) is univ.noValue


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
