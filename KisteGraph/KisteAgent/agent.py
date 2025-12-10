# ===== Import libraries =====
import json
import asyncio
import os, getpass
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

class chat_mode(BaseModel):
    """Switches to Chat Mode."""
    request: str = Field(description="The user's command that triggered this mode.", default="switch")

class standby_mode(BaseModel):
    """Switches to Standby Mode."""
    request: str = Field(description="The user's command that triggered this mode.", default="switch")

class custom_query_mode(BaseModel):
    """Switches to Custom Query Mode."""
    request: str = Field(description="The user's command that triggered this mode.", default="switch")

tools = [chat_mode, standby_mode, custom_query_mode]
# ====================


# OpenAI API Key
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

# State Class
class AppState(MessagesState):
    pass

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


# Function for querying Elastic
# Query function
# Gerekli importlar (Eksikse ekleyin)
# from elasticsearch import AsyncElasticsearch
# from langchain_core.messages import AIMessage

async def execute_elastic_query(state: AppState, index: str = ES_ALERTS_INDEX) -> dict[str, Any] | None:

    # 1. PARAMETRELERİ STATE'DEN ÇEKME (LLM'in ürettiği son mesajdan)
    # Fonksiyon argümanı olarak değil, state'den almalıyız.
    last_message = state["messages"][-1]
    
    try:
        content = last_message.content
        raw_params = json.loads(content)

        params = QueryAlertParams(**raw_params)
        
    except (json.JSONDecodeError, ValidationError):
        # Eğer parametre parse edilemezse varsayılan boş parametre kullan veya hata dön
        # Şimdilik hata durumunda boş obje ile devam edelim veya hata mesajı dönelim:
        return {"messages": [AIMessage(content="Error: Could not parse query parameters.")]}

    # 2. SORGULAMA MANTIĞI (Sizin yazdığınız kod)
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
        # Alan adı genellikle @timestamp'tir ama sizin mapping'de bu ise böyle kalsın:
        filters.append({"range": {"kibana.alert.rule.execution.timestamp": date_range}})
    
    # Description
    if params.description:
        filters.append({"match": {"kibana.alert.rule.parameters.description": params.description}})
    
    # Severity
    if params.severity:
        # Terms expects a list/array
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

    print(f"ES QUERY on {index}: {json.dumps(query)}") # Debug için güzel

    response = None
    
    async with get_elastic_client(state) as client:
        try:
            response = await client.search(index=index, body=query)
        except Exception as e:
            return {"messages": [AIMessage(content=f"Error querying Elasticsearch: {str(e)}")]}

    # 4. SONUCU İŞLEME VE DÖNDÜRME
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

        2. The context contains several generated alert logs from 
        cybersecurity rules and possibly got triggered by a suspicious activity.
 
        3. Make comments about the results you got in a cybersecurity perspective.

        4. If possible, make relevant correlations between different 
        types of context you have. Because it might be a chained attack. 
        Possible fields for founding correlations:
            - MITRE ATT&CK information in each log to predict an attack chain.

            - Timestamps are important to see how attacks evolve over 
            time, and what the attacker is going to do after. They give you the 
            timeline of the attack.

            - You can check host and network information to see if the same attacker is targeting multiple hosts or services.
            
            - Rule name and rule description might give you clues about the attack type, but don't trust it fully.
        
        5. It is recommended to make comments about connected MITRE tactics, techniques, and subtechniques you found.

        6. You can warn the user for upcoming steps with looking at 
        previous steps. You can list future attack steps based on MITRE 
        information in the log data.
        
        7. You can also give recommendations about how to proceed from now on about securing the environment.
    """

    llm = ChatGroq(model="llama-3.1-8b-instant", temperature=0)
    response = await llm.ainvoke(sys_msg + f"\n{query_result}")
    
    response_content = response.content

    return {"messages": [AIMessage(content=response_content)]}


async def generate_elastic_query(state: AppState):

    user_prompt = state["messages"][-1].content
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

    Now here is the real user question:\n
    User Question: "{user_prompt}"
    """

    llm = ChatGroq(model="llama-3.1-8b-instant", temperature=0)
    response = await llm.ainvoke(sys_msg + f"\n{user_prompt}")
    
    response_content = response.content

    try:
        # 3. String'i Python Sözlüğüne (Dict) çevir
        params_dict = json.loads(response_content)
        
        # 4. Pydantic ile Doğrula (Validation burada yapılıyor!)
        # Hata aldığınız yer burasıydı, artık 'params_dict' bir sözlük olduğu için çalışacak.
        validated_obj = QueryAlertParams(**params_dict)
        
        # 5. Doğrulanmış veriyi tekrar temiz bir JSON string'e çevir
        # exclude_none=True ile boş alanları atıyoruz.
        final_json_str = json.dumps(validated_obj.model_dump(exclude_none=True))
        
        # 6. Sonucu bir AIMessage olarak döndür
        # Not: LangGraph akışında mesaj listesine obje değil, Message tipi eklemek en güvenlisidir.
        return {"messages": [AIMessage(content=final_json_str)]}
    
    except (json.JSONDecodeError, ValidationError) as e:
        # JSON bozuksa veya Pydantic validasyonundan geçmezse hata mesajı döndür
        return {"messages": [AIMessage(content=f"Error parsing parameters: {str(e)}")]}


def chat_mode(state: AppState):
    """
    Switches to Chat Mode. 
    1. Closes the tool call with a ToolMessage (Must have tool_call_id).
    2. Sends a welcome AIMessage.
    """
    messages = []
    last_message = state["messages"][-1]
    
    # Tool Call ID'sini bulup kapatıyoruz
    if isinstance(last_message, AIMessage) and last_message.tool_calls:
        for tool_call in last_message.tool_calls:
            if tool_call["name"] == "chat_mode":
                messages.append(
                    ToolMessage(
                        tool_call_id=tool_call["id"],
                        content="Successfully switched to Chat Mode."
                    )
                )
    
    # HATA ÇÖZÜMÜ: Buraya ID'siz ToolMessage yerine AIMessage koyuyoruz.
    # Böylece zincir: AIMessage(Call) -> ToolMessage(Result) -> AIMessage(New Info) oluyor.
    messages.append(AIMessage(content="Switched to Chat Mode. How can I help you?"))
    
    return {"messages": messages}


# ====================


def user_prompt(state: AppState):
    """We get user input here."""

    prompt = interrupt("Your prompt:")

    return {"messages": [HumanMessage(content=prompt)]}


# ====================


def route_user_input_C(state: AppState):
    last_message = state["messages"][-1]

    # Check content
    if isinstance(last_message, HumanMessage) and last_message.content.strip().lower() == "exit":
        # Exit back to assistant
        return "assistant"
    
    # Exit not requested, continue normal flow (to LLM)
    return "call_llm"


def route_user_input_Q(state: AppState):
    last_message = state["messages"][-1]

    # Check content
    if isinstance(last_message, HumanMessage) and last_message.content.strip().lower() == "exit":
        # Exit back to assistant
        return "assistant"
    
    # Exit not requested, continue normal flow (to LLM)
    return "generate_elastic_query"


# ====================


def call_llm(state: AppState):
    """
    We call the LLM and pass the system prompt and user prompt in it to get an answer.
    """

    llm = ChatGroq(model="llama-3.1-8b-instant", temperature=0)
    
    sys_msg = SystemMessage(
        content = f"""
            ROLE & OBJECTIVE
                You are an expert Cybersecurity Data Analyst Assistant. You interpret database logs, detect anomalies, and answer user questions using the conversation history and tool outputs. You may also answer general cybersecurity questions.

                INPUT STRUCTURE
                The conversation may include:
                1. User messages
                2. Tool/system outputs (database logs, JSON, etc.)
                3. Your previous answers

                RULES
                1. Data Priority: Base all analysis strictly on the logs provided. Do not invent IPs, timestamps, or events.
                2. Missing Data: If a question cannot be answered from the current logs, reply:
                "The current data does not contain information about that. Would you like to run a new query?"
                3. General Knowledge: Use general cybersecurity knowledge only for conceptual explanations, never to infer specific events.
                4. Tone: Be professional, concise, and alert-oriented.
                5. Continuity: Treat the dialogue as continuous. References like "that IP" refer to the most recent relevant data.
            """
    )

    response = llm.invoke([sys_msg] + state["messages"])

    return {"messages": [response]}


# ====================


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
    
    # Burası zaten AIMessage idi ama ToolMessage ile birlikte döndürmek daha sağlıklı
    messages.append(AIMessage(content="Welcome to Standby Mode. Waiting for security alerts..."))
    
    return {"messages": messages}

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
                # print("No alerts found in the initial query.") 
                return False
            
            last_alert = last_hits[0].get('_source', {})
            return last_alert
    
    except Exception as e:
        print(f"Error checking last alert: {e}")
        return False

async def wait_alerts(state: AppState):
    """
    Waits for security alerts in Standby Mode.
    """    
    while True:
        last_alert_1 = await last_alert(state)
        await asyncio.sleep(5)
        last_alert_2 = await last_alert(state)

        if last_alert_1 != last_alert_2:
            return {"messages": [SystemMessage(content="new_alerts"), AIMessage(content= "{}")]}
        else:
            continue
    # Fix!!!!
# ====================


def custom_query_mode(state: AppState):
    messages = []
    last_message = state["messages"][-1]
    
    if isinstance(last_message, AIMessage) and last_message.tool_calls:
        for tool_call in last_message.tool_calls:
            if tool_call["name"] == "custom_query_mode":
                messages.append(
                    ToolMessage(
                        tool_call_id=tool_call["id"],
                        content="Successfully switched to Custom Query Mode."
                    )
                )
    
    messages.append(AIMessage(content="Welcome to Custom Query Mode. Please specify your query parameters."))
    
    return {"messages": messages}


# ====================

llm = ChatGroq(model="llama-3.1-8b-instant", temperature=0)
llm_with_tools = llm.bind_tools(tools)
sys_msg = SystemMessage(
    content=(
        "You are a routing assistant. Your ONLY job is to route the user to the correct mode based on their input. "
        "You MUST call one of the provided tools (chat_mode, standby_mode, custom_query_mode)."
        "Do not reply with text. Just call the tool."
    )
)

# ====================


def assistant(state: AppState):

    # Interrupt ile input al
    prompt_text = interrupt("Main Menu - Your command:")
        
    # HumanMessage oluştur
    new_message = HumanMessage(content=prompt_text)
        
    # LLM'e gönderirken sys_msg + geçmiş + yeni mesaj
    # Not: new_message'ı burada listeye koyuyoruz ama invoke'dan sonra 
    # return ederken de state'e eklemeliyiz.
    all_messages = [sys_msg] + state["messages"] + [new_message]
        
    response = llm_with_tools.invoke(all_messages)
        
    # State'e eklenecekler: Kullanıcının yeni mesajı VE LLM'in cevabı
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

builder.add_node("user_prompt_chat", user_prompt)
builder.add_node("user_prompt_query", user_prompt)

builder.add_node("call_llm", call_llm)
builder.add_node("generate_elastic_query", generate_elastic_query)
builder.add_node("execute_elastic_query_C", execute_elastic_query)
builder.add_node("execute_elastic_query_S", execute_elastic_query)

builder.add_node("query_analyzer_C", query_analyzer)
builder.add_node("query_analyzer_S", query_analyzer)

builder.add_node("wait_alerts", wait_alerts)

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

builder.add_edge("chat_mode", "user_prompt_chat")
builder.add_conditional_edges(
    "user_prompt_chat",       
    route_user_input_C,    
    {
        "assistant": "assistant",  # If 'assistant' returned, go here
        "call_llm": "call_llm"     # If 'call_llm' returned, go there
    }
)
builder.add_edge("call_llm", "chat_mode")

builder.add_edge("custom_query_mode", "user_prompt_query")
builder.add_edge("generate_elastic_query", "execute_elastic_query_C")
builder.add_edge("execute_elastic_query_C", "query_analyzer_C")
builder.add_edge("query_analyzer_C", "user_prompt_query")

builder.add_conditional_edges(
    "user_prompt_query",       
    route_user_input_Q,    
    {
        "assistant": "assistant",  # If 'assistant' returned, go here
        "generate_elastic_query": "generate_elastic_query"     # If 'call_llm' returned, go there
    }
)
builder.add_edge("standby_mode", "wait_alerts")
builder.add_edge("wait_alerts", "execute_elastic_query_S")
builder.add_edge("execute_elastic_query_S", "query_analyzer_S")
builder.add_edge("query_analyzer_S", "assistant")

graph = builder.compile()