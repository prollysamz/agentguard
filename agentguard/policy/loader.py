from pathlib import Path

import yaml

from agentguard.core.decision import GuardError
from agentguard.policy.schema import Policy


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def _mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError("Duplicate policy key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def load_policy(source: str | Path | dict | Policy) -> Policy:
    try:
        if isinstance(source, Policy):
            return source.model_copy(deep=True)
        if not isinstance(source, dict):
            raw = Path(source).read_text(encoding="utf-8")
            if len(raw) > 1_000_000:
                raise ValueError("Policy too large")
            # UniqueKeyLoader subclasses SafeLoader: no arbitrary object construction.
            source = yaml.load(raw, Loader=UniqueKeyLoader)  # nosec B506
        return Policy.model_validate(source)
    except Exception as exc:
        raise GuardError("Invalid policy; guard cannot start") from exc
