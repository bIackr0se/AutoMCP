# ===== Import libraries =====
import json
import asyncio
import os, getpass
import subprocess  # Added for recon tools
import re          # Added for regex operations
from typing import Any, Optional
from langgraph.graph import StateGraph, START, END
from langgraph.graph import MessagesState
from langchain_core.messages import SystemMessage, AIMessage, HumanMessage, ToolMessage
from langgraph.types import interrupt
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel, Field, field_validator, ValidationError
from mcp.server.fastmcp import FastMCP
from elasticsearch import AsyncElasticsearch
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from langchain_groq import ChatGroq

# ====================
# TOOL DEFINITIONS (PYDANTIC)
# ====================

class chat_mode(BaseModel):
    """
    Use this tool for:
    1. Analyzing, explaining, or interpreting the logs/data ALREADY retrieved in the conversation.
    2. Answering general cybersecurity questions.
    3. Greetings or small talk.
    
    DO NOT use this if the user specifically asks to perform a NEW search in the database.
    """
    request: str = Field(
        description="The user's question or comment regarding the existing data or general topic.", 
        default="Analyze this"
    )

class custom_query_mode(BaseModel):
    """
    Use this tool ONLY when the user asks to PERFORM A NEW SEARCH or QUERY in the database.
    Triggers: 'Find alerts', 'Check this IP', 'Search for...', 'Show logs from...'
    
    DO NOT use this if the user is just asking about the logs currently visible in the chat.
    """
    request: str = Field(
        description="The specific search criteria (e.g., 'Check IP 1.2.3.4').", 
        default="Check latest alerts"
    )

class standby_mode(BaseModel):
    """
    Use this tool ONLY when the user explicitly asks to wait, watch, or monitor for NEW incoming alerts.
    """
    request: str = Field(description="Ignored.", default="switch")

class analyze_attack_mode(BaseModel):
    """
    Use this tool when the user asks to ANALYZE a specific threat, attack, or alert structure based on MITRE ATT&CK or security expertise.
    Triggers: 'Analyze this attack', 'Classify this threat', 'What stage of kill chain is this?'
    """
    request: str = Field(
        description="The specific context or logs to analyze.", 
        default="Analyze recent alerts"
    )

class counter_recon_mode(BaseModel):
    """
    Use this tool when the user asks to investigate an EXTERNAL IP address or Domain using tools like NMAP, WHOIS, DIG, CURL.
    Triggers: 'Scan this IP', 'Who owns this domain?', 'Check DNS records for...', 'Investigate attacker infrastructure'
    """
    target: str = Field(
        description="The specific IP address or Domain to scan. EXTRACT this from user input.", 
        default="unknown"
    )

tools = [chat_mode, standby_mode, custom_query_mode, analyze_attack_mode, counter_recon_mode]

# ====================

# OpenAI / Groq API Key Setup
def _set_env(var: str):
    if not os.environ.get(var):
        os.environ[var] = getpass.getpass(f"{var}: ")

_set_env("GROQ_API_KEY")

# ====================

# Elastic Constants
load_dotenv()
ES_HOST = "http://localhost:9200"
ES_ALERTS_INDEX = ".internal.alerts-security.alerts-default*" # Index for security alerts
ES_INTEL_INDEX = "otx_pulses_minimal" # Index for threat intelligence
ES_API_KEY = os.getenv("ES_API_KEY") # Elasticsearch API Key from environment variable
LOCAL_TIMEZONE = 1
LOCAL_TZINFO = timezone(timedelta(hours=LOCAL_TIMEZONE)) # For correcting local time to UTC
ES_USERNAME = os.getenv("ES_USERNAME")
ES_PASSWORD = os.getenv("ES_PASSWORD")

# ====================

# Data Type Class for Elastic Query
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

# State Class
class AppState(MessagesState):
    # Optional dictionary to store structured attack analysis data
    attack_analysis: Optional[dict] 

# ====================

# Initialize MCP Server
mcp = FastMCP("mcp_server")

# Initialize Elastic Client
@asynccontextmanager
async def get_elastic_client(state: AppState):
    elastic_client = AsyncElasticsearch([ES_HOST], api_key=ES_API_KEY)
    try:
        yield elastic_client
    finally:
        await elastic_client.close()

# ====================

async def execute_elastic_query(state: AppState, index: str = ES_ALERTS_INDEX) -> dict[str, Any] | None:

    # 1. Retrieve parameters from State (from the last LLM message)
    last_message = state["messages"][-1]
    
    try:
        content = last_message.content
        raw_params = json.loads(content)
        params = QueryAlertParams(**raw_params)
        
    except (json.JSONDecodeError, ValidationError):
        # Return error if parameters cannot be parsed
        return {"messages": [AIMessage(content="Error: Could not parse query parameters.")]}

    DESIRED_OUTPUT_FIELDS = [
        "kibana.alert.rule.execution.timestamp",
        "kibana.alert.rule.parameters.severity",
        "kibana.alert.rule.name",
        "kibana.alert.rule.parameters.description",
        "kibana.alert.rule.parameters.threat",
        "host.ip"
    ]
    
    query = {"query": {"bool": {"must": []}}}
    filters = query["query"]["bool"]["must"]
    
    # Dates
    if params.start_date or params.end_date:
        date_range = {}
        if params.start_date: date_range["gte"] = params.start_date
        if params.end_date: date_range["lte"] = params.end_date
        filters.append({"range": {"kibana.alert.rule.execution.timestamp": date_range}})
    
    # Description
    if params.description:
        filters.append({"match": {"kibana.alert.rule.parameters.description": params.description}})
    
    # Severity
    if params.severity:
        severity_val = params.severity if isinstance(params.severity, list) else [params.severity]
        filters.append({"terms": {"kibana.alert.rule.parameters.severity": severity_val}})
    
    # Rule name
    if params.rule_name:
        filters.append({"match": {"kibana.alert.rule.name": params.rule_name}})

    if params.host_ip:
        filters.append({"match": {"host.ip": params.host_ip}})

    if params.mitre_attack_info:
        mitre_val = params.mitre_attack_info if isinstance(params.mitre_attack_info, list) else [params.mitre_attack_info]
        filters.append({
            "terms": {
                "kibana.alert.rule.parameters.threat" : mitre_val
            }
        })

    # Aggregations logic
    if params.aggregation:
        interval_mapping = {"hourly": "1h", "daily": "1d", "weekly": "1w", "monthly": "1M"}
        es_interval = interval_mapping.get(params.aggregation, "1d")
        query["aggs"] = {
            "time_series": {
                "date_histogram": {"field": "kibana.alert.rule.execution.timestamp", 
                                   "calendar_interval": es_interval, 
                                   "min_doc_count": 1},
            }
        }
        query["size"] = 0
    else:
        query["sort"] = [{"kibana.alert.rule.execution.timestamp": "desc"}]
        query["size"] = 3
        query["_source"] = DESIRED_OUTPUT_FIELDS

    print(f"ES QUERY on {index}: {json.dumps(query)}")

    response = None
    
    async with get_elastic_client(state) as client:
        try:
            response = await client.search(index=index, body=query)
        except Exception as e:
            return {"messages": [AIMessage(content=f"Error querying Elasticsearch: {str(e)}")]}

    # Process and return results
    processed_data = {}

    if params.aggregation:
        processed_data['aggregations'] = response.get('aggregations', {})
        processed_data['total_hits'] = response.get('hits', {}).get('total', {}).get('value', 0)
    
    else:
        hits = response.get('hits', {}).get('hits', [])
        clean_alerts = [hit.get('_source') for hit in hits if hit.get('_source')]
        
        processed_data['total_hits_found'] = response.get('hits', {}).get('total', {}).get('value', 0)
        processed_data['hits_returned'] = len(clean_alerts)
        processed_data['alerts'] = clean_alerts

    structured_response = {
        "query_parameters": params.model_dump(exclude_none=True),
        "data": processed_data 
    }

    return {
        "messages": [
            AIMessage(   
                content= "Elastic Query Result:\n" + json.dumps(structured_response, indent=2, default=str)
            )
        ]
    }

async def query_analyzer(state: AppState):
    query_result = state["messages"][-1].content

    sys_msg = f"""
    Important Rules to Follow:
        1. You are a data analyst assistant with a focus on cybersecurity. Make answers based ONLY on the following context.
        2. The context contains several generated alert logs from cybersecurity rules.
        3. Make comments about the results you got in a cybersecurity perspective.
        4. Make relevant correlations (MITRE ATT&CK, Timestamps, Host info).
        5. Warn the user for upcoming steps and recommend security measures.
    """

    # Optimize token usage: only use recent context + query result
    llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0)
    response = await llm.ainvoke(sys_msg + f"\n{query_result}")
    
    response_content = response.content

    return {"messages": [AIMessage(content=response_content)]}


async def generate_elastic_query(state: AppState):
    user_prompt = "Show me the latest security alerts from the last 24 hours"

    for msg in reversed(state["messages"]):
        if isinstance(msg, HumanMessage):
            user_prompt = msg.content
            break

    data_schema_json = QueryAlertParams.model_json_schema()
    current_date = datetime.now().strftime("%Y-%m-%d")

    correct_examples = """
    Correct Examples:
        1) User Question: "Can you check all the alerts genereated within 3 weeks prior to see if there is a potential ransomware attack?"
        1) Generated Query: {
        "start_date": "2025-10-19T23:00:00Z",
        "severity": [
            "low",
            "medium",
            "high"
        ]
        }

        2) User Question : "Okay, what about logs that have 'TA0002' MITRE tactic ID? Do they correlate between each other? And what is this tactic ID means? What kind of attacks can I expect in the future?"
        2) Generated Query: {
        "mitre_tactic_id": [
            "TA0002"
        ]
        }

        3) User Question: "Can you investigate different logs that has 'medium' severity and tell me possible threats?"
        3) Generated Query:{
        "severity": [
            "medium"
        ]
        }
        """

    sys_msg = f"""
    You are an expert at extracting structured information. 
    Analyze the user's question and generate a JSON object with parameters for the `execute_elastic_query` tool.

    Tool Parameters Schema:
    {json.dumps(data_schema_json, indent=2)}

    Important Rules to Follow:
        1. Current date is ({current_date}). If the user asks for "last week", "yesterday", etc., calculate the time and date range based on today's date.
        2. If a parameter is not mentioned, omit it from the JSON.
        3. If the user asks for multiple severities (e.g., "medium or high"), provide them as a JSON list. Example: ["medium", "high"]
        4. The response MUST be a FLAT JSON object that ONLY contains the VALUE of the parameters.
        5. DO NOT include schema keywords like 'type', 'title', 'anyOf', or 'default' in the final JSON output.
        6. If the question cannot be answered using the tool (e.g., general knowledge), return an empty JSON object.
        7. Respond ONLY with the JSON object.
    
    {correct_examples}
    """

    human_msg = HumanMessage(content=f"User Question: '{user_prompt}'")

    llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0)
    
    response = await llm.ainvoke([sys_msg, human_msg])
    response_content = response.content

    try:
        params_dict = json.loads(response_content)
        
        validated_obj = QueryAlertParams(**params_dict)
        final_json_str = json.dumps(validated_obj.model_dump(exclude_none=True))
        
        return {"messages": [AIMessage(content=final_json_str)]}
    
    except (json.JSONDecodeError, ValidationError) as e:
        return {"messages": [AIMessage(content=f"Error parsing parameters: {str(e)} | Raw Output: {response_content}")]}


# ====================
# MODE HANDLERS
# ====================

def chat_mode(state: AppState):
    messages = []
    last_message = state["messages"][-1]
    
    initial_request = None

    # Handle Tool Call Logic
    if isinstance(last_message, AIMessage) and last_message.tool_calls:
        for tool_call in last_message.tool_calls:
            if tool_call["name"] == "chat_mode":
                messages.append(
                    ToolMessage(
                        tool_call_id=tool_call["id"],
                        content="Successfully switched to Chat Mode."
                    )
                )
                initial_request = tool_call["args"].get("request")

    messages.append(AIMessage(content="Switched to Chat Mode."))

    # Inject the user's intent into the conversation stream
    if initial_request and initial_request != "switch":
        messages.append(HumanMessage(content=initial_request))
    
    return {"messages": messages}


def custom_query_mode(state: AppState):
    messages = []
    last_message = state["messages"][-1]
    initial_request = None

    if isinstance(last_message, AIMessage) and last_message.tool_calls:
        for tool_call in last_message.tool_calls:
            if tool_call["name"] == "custom_query_mode":
                messages.append(
                    ToolMessage(
                        tool_call_id=tool_call["id"],
                        content="Successfully switched to Custom Query Mode."
                    )
                )
                initial_request = tool_call["args"].get("request")
    
    messages.append(AIMessage(content="Switched to Custom Query Mode."))

    if initial_request and initial_request != "switch":
        messages.append(HumanMessage(content=initial_request))
    
    return {"messages": messages}


def standby_mode(state: AppState):
    messages = []
    last_message = state["messages"][-1]
    
    if isinstance(last_message, AIMessage) and last_message.tool_calls:
        for tool_call in last_message.tool_calls:
            if tool_call["name"] == "standby_mode":
                messages.append(
                    ToolMessage(
                        tool_call_id=tool_call["id"],
                        content="Successfully switched to Standby Mode."
                    )
                )
    
    messages.append(AIMessage(content="Welcome to Standby Mode. Waiting for security alerts..."))
    
    return {"messages": messages}

def analyze_attack(state: AppState):
    """
    Analyzes security alerts using a specialized persona.
    """
    messages = []
    last_message = state["messages"][-1]

    # Close Tool Call
    if isinstance(last_message, AIMessage) and last_message.tool_calls:
        for tool_call in last_message.tool_calls:
            if tool_call["name"] == "analyze_attack_mode":
                messages.append(ToolMessage(tool_call_id=tool_call["id"], content="Analyzing attack patterns..."))

    # Token Optimization: Use only the last 10 messages
    recent_messages = state["messages"][-10:] if len(state["messages"]) > 10 else state["messages"]
    
    llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0)
    
    analysis_prompt = SystemMessage(content="""You are a Senior Incident Response Analyst.
    Analyze the available security alert data and provide:
    
    ## ATTACK CLASSIFICATION
    - Attack type/technique (MITRE ATT&CK IDs)
    - Severity assessment
    
    ## ATTACK WORKFLOW
    - Kill chain stages involved
    - Attacker objectives
    
    ## RECOMMENDATIONS
    1. Immediate containment
    2. Remediation
    """)
    
    response = llm.invoke([analysis_prompt] + recent_messages)
    
    messages.append(response)
    
    # Store structured analysis in State
    return {
        "messages": messages,
        "attack_analysis": {
            "raw_analysis": response.content,
            "timestamp": datetime.now().isoformat()
        }
    }

def counter_recon(state: AppState):
    """
    Performs active reconnaissance (Nmap, Whois, Dig).
    """
    messages = []
    target = None

    # 1. Extract target from Tool Call
    last_message = state["messages"][-1]
    if isinstance(last_message, AIMessage) and last_message.tool_calls:
        for tool_call in last_message.tool_calls:
            if tool_call["name"] == "counter_recon_mode":
                messages.append(ToolMessage(tool_call_id=tool_call["id"], content="Starting active reconnaissance..."))
                target = tool_call["args"].get("target")

    # 2. Fallback: Find IP in recent messages using Regex
    if not target or target == "unknown":
        recent_text = " ".join([m.content for m in state["messages"][-5:] if isinstance(m, HumanMessage)])
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, recent_text)
        if ips:
            target = ips[0]
        else:
            return {"messages": messages + [AIMessage(content="I need a target IP or Domain to scan. Please specify one.")]}

    # Helper function to run shell commands
    def run_tool(cmd, timeout=30):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
        except Exception as e:
            return f"Failed: {str(e)}"

    # Perform scans
    scan_results = f"## RECON REPORT FOR: {target}\n\n"
    
    # DIG
    dig_res = run_tool(["dig", target, "+short"], timeout=5)
    scan_results += f"### DNS (Dig)\n{dig_res}\n"
    
    # WHOIS (Truncated)
    whois_res = run_tool(["whois", target], timeout=10)
    scan_results += f"### WHOIS\n{whois_res[:500]}...\n"
    
    # Analyze results with LLM
    llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0)
    analysis = llm.invoke([
        SystemMessage(content="Analyze these reconnaissance results and identify risks."),
        HumanMessage(content=scan_results)
    ])

    messages.append(AIMessage(content=f"{scan_results}\n\n### ANALYSIS\n{analysis.content}"))
    return {"messages": messages}


# ====================

def user_prompt(state: AppState):
    """We get user input here."""
    prompt = interrupt("Your prompt:")
    return {"messages": [HumanMessage(content=prompt)]}

# ====================

def call_llm(state: AppState):
    """
    We call the LLM and pass the system prompt and user prompt in it to get an answer.
    """
    llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0)
    
    sys_msg = SystemMessage(
        content = f"""
            ROLE & OBJECTIVE
                You are an expert Cybersecurity Data Analyst Assistant. 

                RULES
                1. Data Priority: Base all analysis strictly on the logs provided.
                2. Missing Data: Ask the user to run a query if data is missing.
                3. Tone: Professional, concise, alert-oriented.
            """
    )
    
    # Optimization: Only send last 10 messages
    recent_messages = state["messages"][-10:] if len(state["messages"]) > 10 else state["messages"]
    response = llm.invoke([sys_msg] + recent_messages)

    return {"messages": [response]}

# ====================

async def last_alert(state: AppState, alert_index: str= ES_ALERTS_INDEX):
    """Returns the latest alert using the shared client configuration"""

    latest_alert_query = {
        "size": 1,
        "sort": [{"kibana.alert.rule.execution.timestamp": "desc"}],
        "_source": ["kibana.alert.rule.execution.timestamp", "kibana.alert.rule.name"]
    }

    try:
        async with get_elastic_client(state) as client:
            last_data = await client.search(index=alert_index, body=latest_alert_query)
            last_hits = last_data.get('hits', {}).get('hits', [])

            if not last_hits:
                return False
            
            last_alert = last_hits[0].get('_source', {})
            return last_alert
    
    except Exception as e:
        print(f"Error checking last alert: {e}")
        return False

async def wait_alerts(state: AppState):
    """
    Waits for security alerts in Standby Mode.
    Loops indefinitely until a new alert is found.
    """    
    while True:
        last_alert_1 = await last_alert(state)
        await asyncio.sleep(5)
        last_alert_2 = await last_alert(state)

        if last_alert_1 != last_alert_2:
            return {"messages": [SystemMessage(content="new_alerts"), AIMessage(content= "{}")]}
        else:
            continue

# ====================

llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0)
llm_with_tools = llm.bind_tools(tools)
sys_msg = SystemMessage(
    content=(
        "You are an intelligent orchestration assistant. "
        "Your task is to analyze the conversation history and route the user to the correct tool.\n\n"
        
        "DECISION LOGIC:\n"
        "1. NEW DATA (custom_query_mode): Fetch/Search NEW data from DB (e.g., 'Check IP 1.1.1.1', 'Show last 5 alerts').\n"
        "2. ANALYSIS (chat_mode): Explain/Interpret ALREADY RETRIEVED data or general chat.\n"
        "3. DEEP THREAT ANALYSIS (analyze_attack_mode): Structured MITRE ATT&CK analysis and Kill Chain assessment.\n"
        "4. ACTIVE RECON (counter_recon_mode): Use active tools (Nmap/Whois/Dig) on an external Target IP/Domain.\n"
        "5. MONITORING (standby_mode): Explicit waiting/monitoring/standby requests.\n\n"
        
        "You MUST call one of the tools. Do not reply with text."
    )
)

# ====================

def assistant(state: AppState):

    prompt_text = interrupt("Main Menu - Your command:")
    new_message = HumanMessage(content=prompt_text)
    
    # Optimization: Use sys_msg + last few messages + new message
    recent_messages = state["messages"][-10:] if len(state["messages"]) > 10 else state["messages"]
    all_messages = [sys_msg] + recent_messages + [new_message]
        
    response = llm_with_tools.invoke(all_messages)
        
    return {"messages": [new_message, response]}

# ====================

def route_mechanism(state: AppState):
    last_message = state["messages"][-1]
    
    # If there is a tool call
    if hasattr(last_message, "tool_calls") and len(last_message.tool_calls) > 0:
        tool_name = last_message.tool_calls[0]["name"]
        return tool_name

    return END

# ====================
# GRAPH CONSTRUCTION
# ====================

builder = StateGraph(AppState)

# Add Nodes
builder.add_node("assistant", assistant)
builder.add_node("chat_mode", chat_mode)
builder.add_node("standby_mode", standby_mode)
builder.add_node("custom_query_mode", custom_query_mode)
builder.add_node("analyze_attack_mode", analyze_attack) # New Node
builder.add_node("counter_recon_mode", counter_recon)   # New Node
builder.add_node("user_prompt_chat", user_prompt)
builder.add_node("call_llm", call_llm)
builder.add_node("generate_elastic_query", generate_elastic_query)
builder.add_node("execute_elastic_query_C", execute_elastic_query)
builder.add_node("execute_elastic_query_S", execute_elastic_query)
builder.add_node("query_analyzer_C", query_analyzer)
builder.add_node("query_analyzer_S", query_analyzer)
builder.add_node("wait_alerts", wait_alerts)

# Add Edges
builder.add_edge(START, "assistant")

# Router Logic
builder.add_conditional_edges(
    "assistant",
    route_mechanism,
    {
        "chat_mode": "chat_mode",
        "standby_mode": "standby_mode",
        "custom_query_mode": "custom_query_mode",
        "analyze_attack_mode": "analyze_attack_mode",
        "counter_recon_mode": "counter_recon_mode",
        END : END
    }
)

# 1. Chat Flow (One-Shot: Return to Assistant)
builder.add_edge("chat_mode", "call_llm")
builder.add_edge("call_llm", "assistant")

# 2. Query Flow (One-Shot: Return to Assistant)
builder.add_edge("custom_query_mode", "generate_elastic_query")
builder.add_edge("generate_elastic_query", "execute_elastic_query_C")
builder.add_edge("execute_elastic_query_C", "query_analyzer_C")
builder.add_edge("query_analyzer_C", "assistant")

# 3. Standby Flow (Wait -> Alert -> Analyze -> Return to Assistant)
builder.add_edge("standby_mode", "wait_alerts")
builder.add_edge("wait_alerts", "execute_elastic_query_S")
builder.add_edge("execute_elastic_query_S", "query_analyzer_S")
builder.add_edge("query_analyzer_S", "assistant")

# 4. New Tool Flows (One-Shot: Return to Assistant)
builder.add_edge("analyze_attack_mode", "assistant")
builder.add_edge("counter_recon_mode", "assistant")

graph = builder.compile()