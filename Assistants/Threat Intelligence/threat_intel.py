"""
An MCP server for querying threat data
"""

# Import libraries
import os
from dotenv import load_dotenv
from typing import List, Any, Optional
import json
from datetime import datetime
from pydantic import BaseModel, field_validator
from mcp.server.fastmcp import FastMCP
from elasticsearch import AsyncElasticsearch
from contextlib import asynccontextmanager


# Initialize MCP Server
mcp = FastMCP("threat-intelligence-server")



# Constants
load_dotenv()
ES_INDEX = "otx_pulses_minimal"
ES_HOST = "http://localhost:9200"
ES_API_KEY = os.getenv("ES_API_KEY")


# Pydantic Model for Indicators
class IndicatorParams(BaseModel):
    indicator: Optional[str] = None      # e.g., "1.2.3.4"
    type: Optional[str] = None           # e.g., "IPv4"
    role: Optional[str] = None           # e.g., "C2"
    is_active: Optional[bool] = None     # true or false
    title: Optional[str] = None          # e.g., "SSH intrusion attempt"
    description: Optional[str] = None    # A keyword to search in the description
# ----- end-IndicatorParams -----


# Pydantic Model for Threat Data
class QueryThreatDataParams(BaseModel):
    """
    Parameters for filtering threat intelligence data.
    """

    # In case a user includes a date in its prompt, LLM can use these
    start_date: Optional[str] = None
    end_date: Optional[str] = None

    # Pulse information
    pulse_id: Optional[str] = None          # ID of the pulse in OTX Database
    pulse_name: Optional[str] = None        # Title of threat intel
    pulse_description: Optional[str] = None # Description of intel

    # Classification of pulse
    adversary_name: Optional[str] = None # Specifies the name of the threat actor or cyber attack group. Means enemy.

    # Threat details and tags
    threat_tags: Optional[List[str]] = None # Tags for the attack type. For example [phishing, malware, etc.]
    target_countries: Optional[List[str]] = None
    industries: Optional[List[str]] = None
    malware_families: Optional[List[str]] = None
    attack_ids: Optional[List[str]] = None # Attack identities according to MITRE ATT&CK
    references: Optional[List[str]] = None # Some outer resources regarding this attack (news, articles etc.)

    # Nested Pydantic Model for indicators field
    indicators: Optional[List[IndicatorParams]] = None

    # Fill empty strings with None
    @field_validator("*", mode='before')
    def empty_str_to_none(cls, val):
        if val == "": return None
        return val
    
    @field_validator('start_date', 'end_date')
    def validate_date_format(cls, val):
        if val is None: return val
        try:
            datetime.fromisoformat(val)
            return val
        except ValueError:
            raise ValueError(f"--- Invalid date format: '{val}' ---")
# ----- end-QueryThreatDataParams class -----
    


# Elasticsearch Connection
@asynccontextmanager
async def get_es_client():
    client = AsyncElasticsearch([ES_HOST], api_key=ES_API_KEY)
    try:
        yield client
        print("--- Client yielded successfuly ---")
    finally:
        await client.close()
        print("--- Client connection closed securely ---")

async def query_elasticsearch(query: dict) -> dict[str, Any] | None:
    print(f"---> [ES QUERY]: {json.dumps(query)}")
    async with get_es_client() as client:
        try:
            response = await client.search(index=ES_INDEX, body=query)
            return response
        except Exception as e:
            print(f"Error querying Elasticsearch: {e}")
            return None
# ----- end-Elasticsearch Connection -----


# Tool for Querying Threat Data
@mcp.tool()
async def query_threat_data(params: QueryThreatDataParams) -> str:
    """
    Queries threat intelligence data (OTX Pulses)
    """

    # Initial query scheme
    query = {"query": {"bool": {"must": []}}}
    filters = query["query"]["bool"]["must"]
    
    # Date filter
    if params.start_date or params.end_date:
        date_range = {}
        if params.start_date: date_range["gte"] = params.start_date
        if params.end_date: date_range["lte"] = params.end_date # Add '||/d' if there is a problem with dates. 
        filters.append({"range": {"created": date_range}})

    # Basic text and keyword filters
    if params.pulse_id:
        filters.append({"term": {"id": params.pulse_id}}) # Using 'term' for exact matching
    if params.pulse_name:
        filters.append({"match": {"name": params.pulse_name}}) # Using 'match' for flexible matching
    if params.pulse_description:
        filters.append({"match": {"description": params.pulse_description}})
    if params.adversary_name:
        filters.append({"term": {"adversary": params.adversary_name}})
    
    # List-based filters
    if params.threat_tags:
        filters.append({"terms": {"tags": params.threat_tags}})
    if params.target_countries:
        filters.append({"terms": {"targeted_countries": params.target_countries}})
    if params.industries:
        filters.append({"terms": {"industries": params.industries}})
    if params.malware_families:
        filters.append({"terms": {"malware_families": params.malware_families}})
    if params.attack_ids:
        filters.append({"terms": {"attack_ids": params.attack_ids}})
    if params.references:
        filters.append({"terms": {"references": params.references}})
    
    # Nested filter for 'indicators'
    if params.indicators:
        for indicator_filter in params.indicators:
            nested_filters = []
            if indicator_filter.indicator:
                nested_filters.append({"term": {"indicators.indicator": indicator_filter.indicator}})
            if indicator_filter.type:
                nested_filters.append({"term": {"indicators.type": indicator_filter.type}})
            if indicator_filter.role:
                nested_filters.append({"term": {"indicators.role": indicator_filter.role}})
            if indicator_filter.is_active is not None:
                nested_filters.append({"term": {"indicators.is_active": indicator_filter.is_active}})
            if indicator_filter.title:
                nested_filters.append({"match": {"indicators.title": indicator_filter.title}})
            if indicator_filter.description:
                nested_filters.append({"match": {"indicators.description": indicator_filter.description}})

            if nested_filters:
                filters.append({
                    "nested": {
                        "path": "indicators",
                        "query": {"bool": {"must": nested_filters}}
                    }
                })

    # Default state
    if not filters:
        query["query"] = {"match_all": {}}
    
    # Sort and control the size
    query["sort"] = [{"created": "desc"}]
    query["size"] = 10 

    query["_source"] = [
        "name", 
        "description", 
        "author_name", 
        "tags", 
        "indicators"
    ]

    # Run the query
    data = await query_elasticsearch(query)
    if not data:
        return json.dumps({"error": "Unable to query Elasticsearch"}, indent=2)
    
    # Format the result and return
    structured_response = {
        "query_parameters": params.model_dump(exclude_none=True),
        "data": dict(data)

    }
    return json.dumps(structured_response, indent=2)
# ---- end-Tool -----


if __name__ == "__main__":
    mcp.run()