"""Fixed span event names. Unlike the operation-specific ``ActivityNames``, an event's own name
stays constant regardless of which operation raised it - the operation itself is carried as the
``AttributeNames.OPERATION_NAME`` attribute instead - so event names stay low-cardinality and
stable for dashboards/queries.
"""


class EventNames:
    SENSITIVE_OPERATION = "hkdfguard.sensitive_operation"
