import operator
from typing import Any, Callable


OPS: dict[str, Callable[[Any, Any], bool]] = {
    "==": operator.eq,
    "!=": operator.ne,
    ">": operator.gt,
    "<": operator.lt,
    ">=": operator.ge,
    "<=": operator.le,
}


class PacketFilter:
    """Wireshark-inspired, tiny display-filter subset.

    Example: protocol==TCP and dst_port==80
    """

    def matches(self, packet: dict, expression: str | None) -> bool:
        if not expression:
            return True

        parts = expression.split(" and ")
        for part in parts:
            matched = False
            for symbol, op in OPS.items():
                if symbol in part:
                    left, right = [x.strip() for x in part.split(symbol, 1)]
                    left_value = packet.get(left)
                    right_value = self._coerce(right)
                    if isinstance(left_value, str) and isinstance(right_value, str):
                        right_value = right_value.upper()
                        left_value = left_value.upper()
                    if not op(left_value, right_value):
                        return False
                    matched = True
                    break
            if not matched:
                return False
        return True

    @staticmethod
    def _coerce(value: str):
        value = value.strip("'\"")
        if value.isdigit():
            return int(value)
        return value
