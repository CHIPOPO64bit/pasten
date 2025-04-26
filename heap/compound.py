from __future__ import annotations
import heapq
import functools
from typing import Any, Mapping


@functools.total_ordering
class DictItem:
    def __init__(self, key: str, value: Any):
        self.key = key
        self.value = value

    def __lt__(self, other: DictItem) -> bool:
        return self.key < other.key

    def __eq__(self, other: DictItem) -> bool:
        return self.key == other.key

    def __iter__(self):
        yield self.key
        yield self.value
    
    def __repr__(self) -> str:
        return f'DictItem({repr(self.key)}, {repr(self.value)})'


class HeapDict(Mapping[str, Any]):
    def __init__(self, items: list[DictItem] = None):
        self._items = items if items else []
        heapq.heapify(self._items)

    def __setitem__(self, key: str, value: Any):
        if key in self:
            self._items[self._items.index(DictItem(key, None))].value = value
        heapq.heappush(self._items, DictItem(key, value))

    def __getitem__(self, key: str) -> Any:
        return self._items[self._items.index(DictItem(key, None))].value

    def __len__(self) -> int:
        return len(self._items)

    def items(self):
        return iter(self._items)

    def __iter__(self):
        for key, _ in self._items:
            yield key

    def __contains__(self, key):
        return key in iter(self)

    def __repr__(self) -> str:
        return f'HeapDict({self._items})'


class Compound:
    def __init__(self, data: Mapping[str, Any], *, parent: Compound = None, input_filter=lambda _: None):
        self._underlying_dict = HeapDict()
        self._parent = parent
        self._filter = input_filter
        for key in data:
            self._underlying_dict[key] = self._as_item(data[key])
        self.init = True

    def __setattr__(self, name: str, value: Any):
        if 'init' in self.__dict__:
            self.merge_to(name, value)
        else:
            self.__dict__[name] = value

    def ancestor(self) -> Compound:
        result = self
        while result._parent:
            result = result._parent
        return result

    def __getattr__(self, name: str) -> Any:
        if not name:
            return self

        split = name.rsplit('.', 1)
        parent = self if len(split) == 1 else getattr(self, split[0])
        name = split[-1]
        if not isinstance(parent, Compound):
            return getattr(parent, name)
        if name not in parent._underlying_dict:
            parent._underlying_dict[name] = Compound({}, parent=parent, input_filter=parent._filter)

        item = parent._underlying_dict[name]

        if isinstance(item, str) and item[0] == '$':
            item = getattr(self.ancestor(), item[1:])

        return item

    def merge_to(self, path: str, other: Compound):
        parent: Compound = getattr(self, path)
        for key, value in other._underlying_dict.items():
            self._filter(key)
            parent._underlying_dict[key] = parent._as_item(value)

    def _as_item(self, new_value: Any) -> Any:
        if isinstance(new_value, Compound):
            return Compound(new_value._underlying_dict, parent=self, input_filter=self._filter)
        if isinstance(new_value, dict):
            return Compound(new_value, parent=self, input_filter=self._filter)
        if isinstance(new_value, list):
            return [self._as_item(item) for item in new_value]
        return new_value

    @staticmethod
    def load_from_dict(source: dict, *, input_filter=lambda _: None) -> Compound:
        result = Compound({}, input_filter=input_filter)
        for key, value in source.items():
            result._underlying_dict[key] = result._as_item(value)
        return result
