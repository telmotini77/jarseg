from app.commands.base import ALLOWED_COMMANDS


CODE_ACTION_REGISTRY = frozenset(action for action in ALLOWED_COMMANDS if action.startswith("code_"))
