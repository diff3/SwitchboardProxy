from __future__ import annotations


def longest_common_prefix(values: list[str]) -> str:
    if not values:
        return ""
    prefix = values[0]
    for value in values[1:]:
        limit = min(len(prefix), len(value))
        idx = 0
        while idx < limit and prefix[idx] == value[idx]:
            idx += 1
        prefix = prefix[:idx]
        if not prefix:
            break
    return prefix
