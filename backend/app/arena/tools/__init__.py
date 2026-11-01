"""Synthetic target tools registry for AegisMesh Arena."""

from app.arena.tools.base_tool import BaseArenaTool, ToolActionLog
from app.arena.tools.browser_tool import SimulatedBrowserTool
from app.arena.tools.email_tool import SimulatedEmailTool
from app.arena.tools.files_tool import SimulatedFilesTool
from app.arena.tools.payment_tool import SimulatedPaymentTool


class SyntheticToolRegistry:
    """Manages the 4 simulated tools available to the Target Agent."""

    def __init__(self) -> None:
        self.browser = SimulatedBrowserTool()
        self.email = SimulatedEmailTool()
        self.files = SimulatedFilesTool()
        self.payment = SimulatedPaymentTool()

    def get_tool(self, tool_name: str) -> BaseArenaTool:
        mapping = {
            "browser": self.browser,
            "email": self.email,
            "files": self.files,
            "payment": self.payment,
        }
        if tool_name not in mapping:
            raise ValueError(f"Unknown tool name: {tool_name}")
        return mapping[tool_name]

    def reset_all(self) -> None:
        self.browser.reset()
        self.email.reset()
        self.files.reset()
        self.payment.reset()

    def get_summary(self) -> dict:
        return {
            "browser": {
                "name": self.browser.name,
                "capabilities": self.browser.get_capabilities(),
                "history_count": len(self.browser._history),
            },
            "email": {
                "name": self.email.name,
                "capabilities": self.email.get_capabilities(),
                "history_count": len(self.email._history),
            },
            "files": {
                "name": self.files.name,
                "capabilities": self.files.get_capabilities(),
                "history_count": len(self.files._history),
            },
            "payment": {
                "name": self.payment.name,
                "capabilities": self.payment.get_capabilities(),
                "history_count": len(self.payment._history),
            },
        }


__all__ = [
    "BaseArenaTool",
    "ToolActionLog",
    "SimulatedBrowserTool",
    "SimulatedEmailTool",
    "SimulatedFilesTool",
    "SimulatedPaymentTool",
    "SyntheticToolRegistry",
]

