"""Thoughtwire — Binary communication protocol for AI agent networks."""

__version__ = "0.2.0"

from .protocol import encode, decode, FRAME_TYPES, INTENTS, AGENTS
from .signing import sign_frame, verify_frame, AgentKeyPair
from .agent import Agent, EchoAgent, SilentAgent
