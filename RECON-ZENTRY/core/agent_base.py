from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any
import uuid, json

@dataclass
class AgentResult:
    agent_id: str
    task: str
    findings: list = field(default_factory=list)
    artifacts: dict = field(default_factory=dict)
    status: str = "pending"
    children: list = field(default_factory=list)
    raw_output: str = ""

class BaseAgent(ABC):
    def __init__(self, task, context, llm, tool_executor, parent=None):
        self.id = str(uuid.uuid4())[:8]
        self.task = task
        self.context = context
        self.llm = llm
        self.tools = tool_executor
        self.parent = parent
        self.result = AgentResult(agent_id=self.id, task=task)
        self.max_iterations = 25

    @abstractmethod
    def get_system_prompt(self) -> str: ...

    @abstractmethod
    def allowed_tools(self) -> list: ...

    def run(self) -> AgentResult:
        print(f"[{self.__class__.__name__}:{self.id}] {self.task}")
        messages = [
            {"role": "system", "content": self.get_system_prompt()},
            {"role": "user", "content": f"TASK: {self.task}\n\nCONTEXT:\n{self.context.summary()}"}
        ]
        for i in range(self.max_iterations):
            try:
                response = self.llm.chat(messages, tools=self.tools.schemas(self.allowed_tools()))
            except Exception as e:
                self.result.status = "error"
                self.result.raw_output = str(e)
                break

            content = response.get("content", "")
            tool_calls = response.get("tool_calls", [])

            if not tool_calls:
                self.result.status = "completed"
                self.result.raw_output = content
                self._parse_findings(content)
                break

            messages.append({"role": "assistant", "content": content, "tool_calls": tool_calls})
            for call in tool_calls:
                output = self.tools.execute(call["name"], call.get("args", {}), self.allowed_tools())
                messages.append({"role": "tool", "tool_call_id": call.get("id", ""), "name": call["name"], "content": output[:6000]})
        else:
            self.result.status = "max_iterations"
        return self.result

    def _parse_findings(self, content: str):
        try:
            if "```json" in content:
                data = content.split("```json")[1].split("```")[0]
                parsed = json.loads(data)
                if isinstance(parsed, dict):
                    self.result.findings.append(parsed)
                elif isinstance(parsed, list):
                    self.result.findings.extend(parsed)
        except Exception:
            pass
