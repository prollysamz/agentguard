from agentguard.core.action import Action
from agentguard.core.decision import Effect
from agentguard.policy.matcher import matches
from agentguard.policy.schema import Policy


class PolicyEngine:
    def __init__(self, policy: Policy):
        self.policy = policy

    def evaluate(self, action: Action) -> tuple[Effect, str]:
        matched = [(i, rule) for i, rule in enumerate(self.policy.rules) if matches(rule, action)]
        # Explicit denial wins globally. Otherwise first-match order enables narrow exceptions.
        for i, rule in matched:
            if rule.effect == Effect.DENY:
                return Effect.DENY, f"Policy rule {i + 1}: deny"
        if matched:
            i, rule = matched[0]
            return rule.effect, f"Policy rule {i + 1}: {rule.effect.value}"
        return self.policy.defaults.effect, "Policy default: " + self.policy.defaults.effect.value
