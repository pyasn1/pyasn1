#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
from pyasn1 import error
from pyasn1.codec.cer import encoder
from pyasn1.type import univ

__all__ = ['Encoder', 'encode']


class SetEncoder(encoder.SetEncoder):
    @staticmethod
    def _componentSortKey(componentAndType):
        """Sort SET components by tag

        Sort depending on the actual Choice value (dynamic sort)
        """
        component, asn1Spec = componentAndType

        if asn1Spec is None:
            compType = component
        else:
            compType = asn1Spec

        if compType.typeId == univ.Choice.typeId and not compType.tagSet:
            if asn1Spec is None:
                return component.getComponent().tagSet
            else:
                # TODO: move out of sorting key function
                names = [namedType.name for namedType in asn1Spec.componentType.namedTypes
                         if namedType.name in component]
                if len(names) != 1:
                    raise error.PyAsn1Error(
                        '%s components for Choice at %r' % (len(names) and 'Multiple ' or 'None ', component))

                # TODO: support nested CHOICE ordering
                return asn1Spec[names[0]].tagSet

        else:
            return compType.tagSet


TAG_MAP = encoder.TAG_MAP.copy()

TAG_MAP.update({
    # Set & SetOf have same tags
    univ.Set.tagSet: SetEncoder()
})

TYPE_MAP = encoder.TYPE_MAP.copy()

TYPE_MAP.update({
    # Set & SetOf have same tags
    univ.Set.typeId: SetEncoder()
})

# deprecated aliases, https://github.com/pyasn1/pyasn1/issues/9
tagMap = TAG_MAP
typeMap = TYPE_MAP


class SingleItemEncoder(encoder.SingleItemEncoder):
    fixedDefLengthMode = True
    fixedChunkSize = 0

    TAG_MAP = TAG_MAP
    TYPE_MAP = TYPE_MAP


class Encoder(encoder.Encoder):
    SINGLE_ITEM_ENCODER = SingleItemEncoder


#: Turns ASN.1 object into DER octet stream.
#:
#: Takes any ASN.1 object (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#: walks all its components recursively and produces a DER octet stream.
#:
#: Parameters
#: ----------
#: value: either a Python or pyasn1 object (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#:     A Python or pyasn1 object to encode. If Python object is given, `asnSpec`
#:     parameter is required to guide the encoding process.
#:
#: Keyword Args
#: ------------
#: asn1Spec:
#:     Optional ASN.1 schema or value object e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative
#:
#: Returns
#: -------
#: : :py:class:`bytes`
#:     Given ASN.1 object encoded into BER octet-stream
#:
#: Raises
#: ------
#: ~pyasn1.error.PyAsn1Error
#:     On encoding errors
#:
#: Examples
#: --------
#: Encode Python value into DER with ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> encode([1, 2, 3], asn1Spec=seq)
#:    b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03'
#:
#: Encode ASN.1 value object into DER
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> seq.extend([1, 2, 3])
#:    >>> encode(seq)
#:    b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03'
#:
encode = Encoder()
