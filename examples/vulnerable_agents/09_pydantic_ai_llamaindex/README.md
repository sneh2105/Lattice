# Scenario 09 — PydanticAI + LlamaIndex

**Attack chain:** Secret retrieval + shell execution, registered via two
different non-LangChain Python frameworks in the same file.

## Why this scenario exists

PydanticAI and LlamaIndex use tool-registration patterns distinct from
LangChain/CrewAI: PydanticAI's `@agent.tool_plain` decorator (for
synchronous tools without `RunContext`) doesn't match the bare `@tool`
pattern, and LlamaIndex's `FunctionTool.from_defaults(func)` is a method
call on a class, not a decorator at all — requiring separate AST logic
to trace back from the call to the underlying function's docstring.

## Run
```bash
agentscan source pydantic_ai_agent.py
agentscan source llamaindex_agent.py
```

## Expected result
- PydanticAI file: risk **80/100**, both `@agent.tool` and
  `@agent.tool_plain` tools detected as CRITICAL
- LlamaIndex file: risk **100/100**, `FunctionTool.from_defaults()`
  call correctly traced to the underlying function and its docstring

## A known limitation found via this test
LlamaIndex's `query_internal_db` tool (described as "execute a SQL
query") was also flagged for `shell_exec` due to "execute" matching
loosely. As with other source-extracted findings, results carry MEDIUM
confidence specifically because of this — verify against actual runtime
behaviour before treating every flagged capability as certain.

## The fix
Same principle regardless of framework: don't combine secret access
with shell execution capability in one agent; scope each tool to the
minimum it needs.
