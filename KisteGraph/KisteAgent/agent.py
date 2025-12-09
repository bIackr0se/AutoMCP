# ===== Import libraries =====
import json
import os, getpass
from typing import Literal, Any, Optional, TypedDict, Annotated
from langgraph.graph import StateGraph, START, END
from langgraph.graph import MessagesState
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, AIMessage, HumanMessage, ToolMessage
from langgraph.types import interrupt
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel, Field, field_validator
from mcp.server.fastmcp import FastMCP
from elasticsearch import AsyncElasticsearch
from contextlib import asynccontextmanager
from dotenv import load_dotenv
import aiohttp


# ====================


# OpenAI API Key
def _set_env(var: str):
    if not os.environ.get(var):
        os.environ[var] = getpass.getpass(f"{var}: ")

_set_env("OPENAI_API_KEY")


# ====================


# Elastic Constants
load_dotenv()
ES_HOST = "http://localhost:9200"
ES_ALERTS_INDEX = ".internal.alerts-security.alerts-default*" # Index for security alerts
ES_INTEL_INDEX = "otx_pulses_minimal" # Index for threat intelligence
ES_API_KEY = os.getenv("ES_API_KEY") # Elasticsearch API Key from environment variable
LOCAL_TIMEZONE = 1
LOCAL_TZINFO = timezone(timedelta(hours=LOCAL_TIMEZONE)) # For correcting local time to UTC


# ====================


# State Class
class AppState(MessagesState):
    isBegin : Optional[bool]


# ====================


# Data Type Class
class QueryAlertParams(BaseModel):

    # Selected fields
    start_date        : Optional[str]       = None
    end_date          : Optional[str]       = None
    aggregation       : Optional[str]       = None
    description       : Optional[str]       = None
    severity          : Optional[list[str]] = None
    rule_name         : Optional[str]       = None
    mitre_attack_info : Optional[list[str]] = None
    host_ip           : Optional[str]       = None

    # Fill empty spaces with 'None'.
    @field_validator('*', mode='before')
    def empty_str_to_none(cls, v):
        if v == "": return None
        return v
    
    @field_validator('start_date', 'end_date')
    def validate_and_convert_to_utc(cls, value):
        if value is None: 
            return value
        
        try:
            # Turn the input string into 'datetime' object
            dt = datetime.fromisoformat(value)
            
            # Mark the input time as UTC+1
            dt_local_aware = dt.replace(tzinfo=LOCAL_TZINFO)
            
            # Turn this time into UTC
            dt_utc = dt_local_aware.astimezone(timezone.utc)

            # Return in 'Z' format for Elastics
            return dt_utc.isoformat().replace('+00:00', 'Z')

        except ValueError:
            raise ValueError(f"Invalid date format: '{value}'. Use 'YYYY-MM-DD' or 'YYYY-MM-DDTHH:MM:SS'.")
        
    # Handle aggregations
    @field_validator('aggregation')
    def validate_aggregation(cls, value):
        if value is None: return value
        valid_aggregations = ["hourly", "daily", "weekly", "monthly"]
        if value not in valid_aggregations:
            raise ValueError(f"Invalid aggregation. Use one of: {valid_aggregations}")
        return value


# ====================


# Initialize MCP Server
mcp = FastMCP("mcp_server")
elastic_client = AsyncElasticsearch([ES_HOST], api_key=ES_API_KEY)

# Initialize Elastic Client 
async def initialize_elastic(mcp: FastMCP, es_client: AsyncElasticsearch):
    try:
        yield elastic_client
    finally:
        await elastic_client.close()


# ====================


# Function for querying Elastic
# Query function
async def query_es(query: dict, index: str = ES_ALERTS_INDEX ) -> dict[str, Any] | None:

    # print(f"ES QUERY on {index}: {json.dumps(query)}")
    async with elastic_client() as client:
        try:
            response = await client.search(index=index, body=query)
            # !!!
            return response
        except Exception as e:
            print(f"Error querying Elasticsearch: {e}")
            return None


def chat_mode(state: AppState):
    """
    Switches to Chat Mode. Closes the previous tool call's with ToolMessage.
    Then sends welcome message to indicate we switched correctly (AIMessage).
    """
    messages = []
    
    # Take last message (Probably a tool call)
    last_message = state["messages"][-1]
    
    # If the last message is an AIMessage and contains a Tool Call:
    if isinstance(last_message, AIMessage) and last_message.tool_calls:
        for tool_call in last_message.tool_calls:
            if tool_call["name"] == "chat_mode":

                # OpenAI'nin beklediği 'ToolMessage'ı listeye 
                # OpenAI waits for the tool to close. Add ToolMessage to indicate that it closed.
                messages.append(
                    ToolMessage(
                        tool_call_id=tool_call["id"],
                        content="Successfully switched to Chat Mode."
                    )
                )
    
    # Kullanıcıya görünecek asıl mesajı ekle
    messages.append(AIMessage(content="Welcome to Chat Mode. How can I help with current data?"))
    
    return {"messages": messages}


# ====================


def user_prompt(state: AppState):
    """We get user input here."""

    prompt = interrupt("Your prompt:")

    return {"messages": [HumanMessage(content=prompt)]}


# ====================


def route_user_input(state: AppState):
    last_message = state["messages"][-1]

    # Check content
    if isinstance(last_message, HumanMessage) and last_message.content.strip().lower() == "exit":
        # Exit back to assistant
        return "assistant"
    
    # Exit not requested, continue normal flow (to LLM)
    return "call_llm"


# ====================


def call_llm(state: AppState):
    """
    We call the LLM and pass the system prompt and user prompt in it to get an answer.
    """

    llm = ChatOpenAI(model="gpt-3.5-turbo")
    
    sys_msg = SystemMessage(
        content = f"""
            ROLE & OBJECTIVE

            You are an expert Cybersecurity Data Analyst Assistant. Your goal 
            is to interpret database logs, detect anomalies, and answer user 
            questions based on the provided conversation history and data tools. Or
            simply answer cybersecurity related questions.

            INPUT STRUCTURE
            The input you receive is a conversation history. It MAY contain:
            1. User Messages: Questions or commands.
            2. Tool/System Outputs: Raw data logs (JSON) retrieved from the database.
            3. Assistant Messages: Your previous answers.

            RULES
            1. Priority on Data: Base your analysis STRICTLY on the provided 
            logs/data within the conversation history. Do not invent IPs, 
            timestamps, or events.

            2. Gap Handling: If the user asks a question that cannot be 
            answered with the current logs, politely state: "The current data does 
            not contain information about cybersecurity. Would you like to run a new
            query?"

            3. General Knowledge: You MAY use your general cybersecurity 
            knowledge to explain terms (e.g., "What is SQL Injection?"), but do NOT 
            use it to make claims about specific events not present in the logs.
            
            4. Tone: Be professional, concise, and alert-oriented.

            5. Continuity: Treat the input as a continuous conversation. If the
            user says "What about that IP?", refer to the IP mentioned in the most 
            recent log or message.
            """
    )

    response = llm.invoke([sys_msg] + state["messages"])

    return {"messages": [response]}


# ====================


def standby_mode(state: AppState):
    """
    Switches to Standby Mode. Closes the previous tool call's with ToolMessage.
    Then sends welcome message to indicate we switched correctly (AIMessage).
    """
    messages = []
    
    # Take last message (Probably a tool call)
    last_message = state["messages"][-1]
    
    # If the last message is an AIMessage and contains a Tool Call:
    if isinstance(last_message, AIMessage) and last_message.tool_calls:
        for tool_call in last_message.tool_calls:
            if tool_call["name"] == "standby_mode":

                # OpenAI'nin beklediği 'ToolMessage'ı listeye 
                # OpenAI waits for the tool to close. Add ToolMessage to indicate that it closed.
                messages.append(
                    ToolMessage(
                        tool_call_id=tool_call["id"],
                        content="Successfully switched to Standby Mode."
                    )
                )
    
    # Kullanıcıya görünecek asıl mesajı ekle
    messages.append(AIMessage(content="Welcome to Standby Mode. Waiting for security alerts..."))
    
    return {"messages": messages}


# ====================


def custom_query_mode(state: AppState):
    """
    Switches to Custom Query Mode. Closes the previous tool call's with ToolMessage.
    Then sends welcome message to indicate we switched correctly (AIMessage).
    """
    messages = []
    
    # Take last message (Probably a tool call)
    last_message = state["messages"][-1]
    
    # If the last message is an AIMessage and contains a Tool Call:
    if isinstance(last_message, AIMessage) and last_message.tool_calls:
        for tool_call in last_message.tool_calls:
            if tool_call["name"] == "custom_query_mode":

                # OpenAI'nin beklediği 'ToolMessage'ı listeye 
                # OpenAI waits for the tool to close. Add ToolMessage to indicate that it closed.
                messages.append(
                    ToolMessage(
                        tool_call_id=tool_call["id"],
                        content="Successfully switched to Custom Query Mode."
                    )
                )
    
    # Kullanıcıya görünecek asıl mesajı ekle
    messages.append(AIMessage(content="Welcome to Custom Query Mode. Waiting for security alerts..."))
    
    return {"messages": messages}


# ====================


tools = [chat_mode, standby_mode, custom_query_mode]
llm = ChatOpenAI(model="gpt-3.5-turbo")
llm_with_tools = llm.bind_tools(tools)
sys_msg = SystemMessage(content="You are a helpful routing assistant. Analyze the user input and route to the correct mode. Only respond with the name of the tools.")


# ====================


def assistant(state: AppState):
    is_beginning = state.get("isBegin", 1)
    
    if is_beginning:
        response = llm_with_tools.invoke([sys_msg] + state["messages"])

        return {
            "messages": [response],
            "isBegin": False
        }
    
    else:
        prompt = interrupt("Main Menu - Your command:")
        
        # Yeni mesajı oluştur
        new_message = HumanMessage(content=prompt)
        
        # Tüm mesaj listesiyle LLM'i çağır
        all_messages = [sys_msg] + state["messages"] + [new_message]
        response = llm_with_tools.invoke(all_messages)
        
        # State'e hem kullanıcının yeni komutunu hem de LLM'in cevabını ekle
        # isBegin 1 olarak kalmaya devam eder
        return {"messages": [new_message, response]}


# ====================


def route_mechanism(state: AppState):
    last_message = state["messages"][-1]
    
    # If there is a call
    if hasattr(last_message, "tool_calls") and len(last_message.tool_calls) > 0:

        tool_name = last_message.tool_calls[0]["name"]
        return tool_name

    return END


# ====================


builder = StateGraph(AppState)

builder.add_node("assistant", assistant)
builder.add_node("chat_mode", chat_mode)
builder.add_node("standby_mode", standby_mode)
builder.add_node("custom_query_mode", custom_query_mode)
builder.add_node("user_prompt", user_prompt)
builder.add_node("call_llm", call_llm)

builder.add_edge(START, "assistant")

builder.add_conditional_edges(
    "assistant",       # Kaynak node
    route_mechanism,   # Karar verici fonksiyon (Router)
    {
        "chat_mode": "chat_mode",
        "standby_mode": "standby_mode",
        "custom_query_mode": "custom_query_mode",
        END : END
    }
)

builder.add_edge("chat_mode", "user_prompt")
builder.add_conditional_edges(
    "user_prompt",       
    route_user_input,    
    {
        "assistant": "assistant",  # If 'assistant' returned, go here
        "call_llm": "call_llm"     # If 'call_llm' returned, go there
    }
)
builder.add_edge("call_llm", "chat_mode")
builder.add_edge("standby_mode", END)
builder.add_edge("custom_query_mode", END)

graph = builder.compile()