# Changed the model to llama3.1:latest

import asyncio
import json
import aiohttp
from datetime import datetime

# Import from your new MCP server file
from security_alerts import query_alert_data, QueryAlertDataParams

async def get_tool_parameters_from_llm(user_question: str) -> dict:
    tool_description = """
    Tool Name: query_alert_data
    Parameters:
    - start_date (string, format: YYYY-MM-DD)
    - end_date (string, format: YYYY-MM-DD)
    - rule_name (string, e.g., "Potential Internal Linux SSH Brute Force Detected")
    - source_ip (string, the IP where the attack came from, e.g., "192.168.0.180")
    - host_name (string, the name of the targeted machine, e.g., "ercodex")
    - event_outcome (string, the result of the event, e.g., "failure" or "success")

    - sort_by (string): Field to sort the results by (default: '@timestamp').
    - sort_order (string): 'asc' for ascending, 'desc' for descending (default: 'desc').
    - limit (integer): The number of results to return (default: 5).
    """
    

    prompt = f"""
    You are an expert at extracting structured information from a user's question to call a tool.
    Tool Description: {tool_description}
    Dates and times in logs are very important. Pay attention to their correctness.

    RULES:
    1. If the user asks for "latest", "newest", "most recent", or a specific number of alerts (e.g., "top 5"),
       use the 'sort_by', 'sort_order', and 'limit' parameters. DO NOT generate a date range in this case.

    2. If the user asks about a specific day or date range (e.g., "today", "yesterday", "last week"),
       use the 'start_date' and 'end_date' parameters.

    3. If a parameter is not mentioned, DO NOT include its key in the JSON.
    
    User Question: "{user_question}"
    Respond ONLY with the JSON object.
    """
    
    payload = {"model": "llama3.1:latest", "prompt": prompt, "stream": False, "format": "json"}
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post("http://localhost:11434/api/generate", json=payload) as resp:
                resp.raise_for_status()
                ollama_response_str = await resp.text()
                ollama_response_obj = json.loads(ollama_response_str)
                params_str = ollama_response_obj.get('response', '{}')
                return json.loads(params_str)
        except Exception as e:
            print(f"Error getting parameters from LLM: {type(e).__name__} - {e}")
            return {}

def format_context_as_alert_report(context: dict) -> str:
    """
    Transforms the raw JSON from Elasticsearch into a detailed Security Alert Report for the LLM.
    This version is corrected to read data from the 'fields' object, where each value is a list.
    """
    if "data" not in context or "hits" not in context["data"]["hits"]:
        return "No alerts found for the given criteria."

    hits = context["data"]["hits"]["hits"]
    if not hits:
        params = context.get("query_parameters", {})
        return f"No alerts found matching the criteria: {json.dumps(params)}"
    
    report = "--- Security Alert Summary ---\n"
    report += f"Found {len(hits)} relevant alerts.\n"
    
    for i, hit in enumerate(hits):

        fields = hit.get("fields", {})
        
        def get_field(field_name):
            """Safely gets the first item from a field's list."""
            return fields.get(field_name, ['N/A'])[0]

        report += f"\n--- Alert #{i+1} ---\n"
        report += f"Timestamp: {get_field('@timestamp')}\n"
        report += f"Rule Name: {get_field('kibana.alert.rule.name')}\n"
        report += f"Severity: {get_field('kibana.alert.severity')}\n"
        report += f"Outcome: {get_field('event.outcome')}\n"
        report += f"Source IP: {get_field('source.ip')}\n"
        report += f"Target Host Name: {get_field('host.name')}\n"
        
        target_ips = fields.get('host.ip', ['N/A'])
        report += f"Target Host IPs: {', '.join(target_ips)}\n" # It might contain more than one IP, so we join it.
        
        report += f"Reason: {get_field('kibana.alert.reason')}\n"
    
    return report

async def get_final_answer_from_llm(context_report: str, question: str):
    """Generates a final answer based on the formatted alert report."""
    prompt = f"""
    You are a helpful security analyst. Your task is to interpret the provided security alerts
    and answer the user's question. Be concise and clear. Make sure the numbers are correct in some data (i.e. ip addresses)

    --- SECURITY ALERT SUMMARY ---
    {context_report}

    --- QUESTION ---
    {question}

    --- ANALYSIS & ANSWER ---
    """
    payload = {"model": "llama3.1:latest", "prompt": prompt, "stream": True}
    print("\n--- Assistant ---")
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post("http://localhost:11434/api/generate", json=payload) as resp:
                resp.raise_for_status()
                async for line in resp.content:
                    if line:
                        chunk = json.loads(line.decode('utf-8'))
                        token = chunk.get('response', '')
                        print(token, end="", flush=True)
                        if chunk.get('done'):
                            print()
        except Exception as e:
            print(f"\nAn error occurred while getting the final answer: {e}")

async def main():
    print("Security Alert Assistant is ready. Type 'exit' to quit.")
    while True:
        user_question = input("\n> ")
        if user_question.lower() == 'exit':
            break

        print("\n[Step 1: Analyzing your question...]")
        tool_params_dict = await get_tool_parameters_from_llm(user_question)

        if not tool_params_dict:
            print("--> Could not determine parameters. Please ask a question about security alerts.")
            continue

        try:
            print(f"--> LLM generated parameters: {json.dumps(tool_params_dict, indent=2)}")
            params = QueryAlertDataParams(**tool_params_dict)
            
            print("\n[Step 2: Querying security alerts...]")
            result_json_str = await query_alert_data(params)
            retrieved_context = json.loads(result_json_str)
            
            print("\n[Step 3: Formatting alerts into a report...]")
            report_context = format_context_as_alert_report(retrieved_context)
            print(report_context)

            print("\n[Step 4: Generating final analysis...]")
            await get_final_answer_from_llm(report_context, user_question)
        except Exception as e:
            print(f"\n--- Assistant ---\nAn error occurred: {e}")

if __name__ == "__main__":
    asyncio.run(main())