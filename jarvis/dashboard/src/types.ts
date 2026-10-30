export type Json = string | number | boolean | null | Json[] | { [key: string]: Json };
export interface Agent { id: string; name: string; health: string; status: string; capabilities: string[]; current_task: string | null; }
export interface TaskStep { id: string; index: number; agent: string; action: string; objective: string; status: string; risk: string; }
export interface Task { id: string; status: string; progress: { completed: number; total: number }; current_task_id: string | null; tasks: TaskStep[]; }
export interface Automation { id: string; name: string; enabled: boolean; trigger: { trigger_type?: string; time?: string; event_type?: string }; actions: { agent: string; action: string }[]; last_run_at: string | null; }
export interface Device { id: string; name: string; status: string; capabilities: string[]; last_seen: string | null; state: { outputs?: Record<string, Json>; details?: Record<string, Json> } | null; }
export interface Metrics { cpu_percent: number; memory: { used: number; total: number; percent: number }; disk: { free: number; total: number; percent: number }; battery_percent: number | null; }
export interface Experience { visual_state: string; interface_mode: string; level: number; agent?: string | null; action?: string | null; transcript?: string | null; response?: string | null; }
export interface CyberSegStatus { available: boolean; status: string; alerts: string; }
export interface Status { version: string; online: boolean; agents: { healthy: number; total: number }; orchestrator_mode: string; orchestrator_status: string; terminal_mode: string; wake_word: string; microphone: string; tasks: Task[]; automations_active: number; iot_online: number; metrics: Metrics; experience?: Experience; cyberseg?: CyberSegStatus; }
export interface EventMessage { type: string; source?: string; data?: Record<string, Json>; timestamp?: string; }
