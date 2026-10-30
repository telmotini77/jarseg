from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class RouteType(str, Enum):
    COMMAND = "command"
    TERMINAL_COMMAND = "terminal_command"
    CONVERSATION = "conversation"


class CommandName(str, Enum):
    EXIT = "exit"
    CANCEL = "cancel"


@dataclass(frozen=True, slots=True)
class Route:
    type: RouteType
    command: CommandName | None = None
    parsed_command: "Command | None" = None


@dataclass(frozen=True, slots=True)
class Command:
    """A parsed command that can only be executed through the allow-list."""

    action: str
    target: str | None = None
    arguments: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CommandResult:
    success: bool
    message: str


ALLOWED_COMMANDS: frozenset[str] = frozenset({
    "open_application",
    "list_applications",
    "wait_for_window",
    "close_application",
    "system_info",
    "set_volume",
    "volume_up",
    "volume_down",
    "open_url",
    "web_search",
    "browser_trusted_login",
    "open_folder",
    "list_files",
    "search_local_files",
    "capture_screen",
    "capture_active_window",
    "analyze_screen",
    "analyze_active_window",
    "list_windows",
    "active_window",
    "focus_window",
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
    "automation_sequence",
    "memory_remember",
    "memory_recall",
    "memory_forget",
    "memory_update",
    "memory_explain",
    "memory_when",
    "memory_stats",
    "memory_export",
    "memory_clear_all",
    "memory_last_session",
    "memory_backup",
    "reminder_create",
    "reminder_list",
    "reminder_list_today",
    "reminder_cancel",
    "reminder_complete",
    "routine_begin",
    "routine_add",
    "routine_save",
    "routine_execute",
    "browser_start",
    "browser_stop",
    "browser_open",
    "browser_search",
    "browser_search_history",
    "browser_back",
    "browser_forward",
    "browser_reload",
    "browser_new_tab",
    "browser_close_tab",
    "browser_switch_tab",
    "browser_click",
    "browser_scroll",
    "browser_current_page",
    "browser_list_tabs",
    "browser_read_page",
    "browser_summarize",
    "browser_ask_page",
    "browser_find_text",
    "browser_list_links",
    "browser_open_link",
    "browser_fill",
    "browser_fill_email",
    "browser_select",
    "browser_submit",
    "browser_sequence",
    "media_play_youtube",
    "media_pause",
    "media_resume",
    "media_volume_up",
    "media_volume_down",
    "media_fullscreen",
    "terminal_execute",
    "terminal_sequence",
    "terminal_preview",
    "terminal_context",
    "terminal_change_directory",
    "terminal_parent_directory",
    "terminal_set_project",
    "terminal_set_mode",
    "terminal_tool_status",
    "terminal_npm_scripts",
    "terminal_list_processes",
    "terminal_process_output",
    "terminal_stop_process",
    "terminal_open_here",
    "terminal_diagnose",
    "terminal_last_output",
    "code_scan_project",
    "code_read_file",
    "code_search",
    "code_explain",
    "code_plan_change",
    "code_project_plan",
    "code_project_apply",
    "code_apply_patch",
    "code_create_file",
    "code_rename_file",
    "code_delete_file",
    "code_run_tests",
    "code_run_lint",
    "code_run_build",
    "code_review",
    "code_open_vscode",
    "code_architecture",
    "code_dependencies",
    "code_changed_files",
    "code_diff",
    "code_diagnostics",
    "code_commit",
    "iot_connect",
    "iot_disconnect",
    "iot_list_devices",
    "iot_get_state",
    "iot_get_telemetry",
    "iot_set_led",
    "iot_set_relay",
    "iot_set_servo",
    "iot_set_buzzer",
    "iot_subscribe",
    "iot_create_rule",
    "iot_register_device",
    "iot_list_rules",
    "iot_disable_rule",
    "iot_disable_all_rules",
    "iot_check_tools",
    "cyberseg_status",
    "cyberseg_alerts",
    "cyberseg_threat_coverage",
    "cyberseg_start_capture",
    "cyberseg_stop_capture",
    "orchestrator_agents",
    "orchestrator_agent_status",
    "orchestrator_set_mode",
    "orchestrator_goal",
    "orchestrator_status",
    "orchestrator_cancel",
    "automation_list_engine",
    "automation_create_engine",
    "automation_enable_engine",
    "automation_disable_engine",
    "automation_run_engine",
})
