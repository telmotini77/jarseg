from __future__ import annotations


ACTION_REGISTRY: frozenset[str] = frozenset({
    "open_application",
    "open_folder",
    "open_url",
    "system_info",
    "wait_for_window",
    "focus_window",
    "capture_screen",
    "capture_active_window",
    "analyze_screen",
    "analyze_active_window",
    "list_windows",
    "active_window",
    "focus_previous_window",
    "minimize_window",
    "maximize_window",
    "restore_window",
    "move_mouse",
    "move_mouse_center",
    "mouse_position",
    "mouse_click",
    "mouse_double_click",
    "mouse_right_click",
    "scroll",
    "type_text",
    "press_key",
    "hotkey",
    "routine_execute",
    "browser_open",
    "browser_search",
    "browser_back",
    "browser_forward",
    "browser_reload",
    "browser_new_tab",
    "browser_switch_tab",
    "browser_scroll",
    "browser_read_page",
    "browser_find_text",
})


def is_registered_action(action: str) -> bool:
    return action in ACTION_REGISTRY
