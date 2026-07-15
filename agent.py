
import os
import logging

from langchain.agents import create_agent
from langchain_core.tools import tool
from langgraph.checkpoint.memory import InMemorySaver

from tools.recon import subfinder as _subfinder
from tools.recon import httpx_probe as _httpx_probe

logger = logging.getLogger("osint-agent.agent")


# @tool wraps a plain function into something the agent can call. The
# description is passed explicitly rather than left to be inferred from
# the docstring — under `python -OO` (or PYTHONOPTIMIZE=2), Python strips
# docstrings entirely, which makes @tool alone fail with "Function must
# have a docstring." Passing description= explicitly makes this work
# regardless of how the interpreter is invoked. The docstring is kept
# too, purely for readability when someone opens this file.

@tool(description=(
    "Given a root domain (e.g. 'example.com'), returns newline-separated "
    "subdomains found via passive sources. Use this first for any new "
    "target, before httpx_probe."
))
def subfinder(domain: str) -> str:
    """Passive subdomain enumeration wrapper — see description= above."""
    return _subfinder(domain)


@tool(description=(
    "Given a single URL or hostname, returns its HTTP status code and "
    "page title if alive, or nothing if dead. Call this once per subdomain "
    "returned by subfinder — do not pass multiple hostnames in one call."
))
def httpx_probe(url: str) -> str:
    """Active HTTP probe wrapper — see description= above."""
    return _httpx_probe(url)


def _build_model():
   
    if os.environ.get("ANTHROPIC_API_KEY"):
        logger.info("Using Anthropic (Claude) as the agent's LLM")
        # Update this model string as needed — check docs.claude.com
        # for the current model list.
        return "anthropic:claude-sonnet-5"

    if os.environ.get("HUGGINGFACEHUB_API_TOKEN"):
        # langchain_community is being sunset by the LangChain team; the
        # HF chat model wrapper now lives in the standalone
        # langchain-huggingface package instead.
        from langchain_huggingface import ChatHuggingFace, HuggingFaceEndpoint
        logger.info("Using HuggingFace Inference API as the agent's LLM")
        llm = HuggingFaceEndpoint(
            repo_id="meta-llama/Llama-3.1-8B-Instruct",
            task="text-generation",
            temperature=0.01,  # HuggingFaceEndpoint rejects exactly 0
        )
        return ChatHuggingFace(llm=llm)

    raise RuntimeError(
        "No LLM provider configured. Set ANTHROPIC_API_KEY or "
        "HUGGINGFACEHUB_API_TOKEN in your .env file."
    )


def build_agent():
    
    model = _build_model()
    tools = [subfinder, httpx_probe]
    checkpointer = InMemorySaver()

    agent = create_agent(
        model=model,
        tools=tools,
        checkpointer=checkpointer,
    )
    return agent