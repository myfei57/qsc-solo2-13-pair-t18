"""审计相关的稳定常量（独立模块，避免包初始化循环导入）。"""

from __future__ import annotations

AUDIT_STREAM = "audit/events"
OUTCOMES = ("ok", "rejected", "failed")

__all__ = ["AUDIT_STREAM", "OUTCOMES"]
