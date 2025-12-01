"""
Main file for the Ultimate Assistant
Author: Eren Cil
"""
# +++++++++++++++++++++ Libraries +++++++++++++++++++++
import os                       # For 'save_conversation' function
import asyncio                  # For async main loop
import json                     # For JSON handling
import aiohttp                  # For async HTTP requests
from datetime import datetime  # For timestamping conversations
import time                     # For measuring time intervals
from elasticsearch import AsyncElasticsearch
import logging
logging.getLogger("elastic_transport").setLevel(logging.WARNING)
logging.getLogger("elasticsearch").setLevel(logging.WARNING)
from final_assistant import query_alerts, QueryAlertParams
# +++++++++++++++++++++++++++++++++++++++++++++++++++++


ES_USERNAME = os.getenv("ES_USERNAME")
ES_PASSWORD = os.getenv("ES_PASSWORD")
ES_HOSTS = ["http://localhost:9200"]
ES_ALERTS_INDEX = ".internal.alerts-security.alerts-default*"
ANSWER_LLM = "qwen2.5:3b"


# +++++++++++ LLM Interaction Functions +++++++++++++++
async def ask_LLM(user_prompt: str, history: dict, system_prompt: str = None, model_name: str = ANSWER_LLM) -> str:
    """
    Generates a final, human-readable answer based on the provided context and question.
    """
    try:
        # All functions use this ask_LLM function. So you don't have to convert history into JSON format everytime.
        history_json = json.dumps(history, indent=2)

        full_prompt = ""

        if system_prompt:
            full_prompt += f"SYSTEM INSTRUCTIONS:\n{system_prompt}\n\n"

        full_prompt += f"CONVERSATION HISTORY:\n{history_json}\n\n"
        full_prompt += f"USER INPUT:\n{user_prompt}"

        payload = {
            "model": model_name,
            "prompt": full_prompt,
            "stream": False,
            "temperature": 0.05
        }

        # Start session
        async with aiohttp.ClientSession() as session:
            async with session.post("http://localhost:11434/api/generate", json=payload) as resp:
                resp.raise_for_status()
                response_text = await resp.text()
                data = json.loads(response_text)
                return data.get('response', 'Could not get a valid response.').strip()
    except Exception as e:
        return f"LLM Error: {e}"

async def generate_query_LLM(user_question: str, model_name : str = ANSWER_LLM) -> dict:
    """
    Asks the LLM to act as a router. It analyzes the user's question and extracts the correct parameters for the query_log_data tool.
    """

    # Define the tool schema that contains the parameters for Alert Querying
    tool_schema = QueryAlertParams.model_json_schema()

    # Give today's date to LLM for relative date calculations
    today_str = datetime.now().strftime("%Y-%m-%d")

    # Build the prompt
    prompt = f"""
    You are an expert at extracting structured information. Analyze the user's question and generate a JSON object with parameters for the `query_alert_data` tool.

    Tool Parameters Schema:
    {json.dumps(tool_schema, indent=2)}

    Important Rules to Follow:
        1. Current date is ({today_str}). If the user asks for "last week", "yesterday", etc., calculate the time and date range based on today's date.
        2. If a parameter is not mentioned, omit it from the JSON.
        3. If the user asks for multiple severities (e.g., "medium or high"), provide them as a JSON list. Example: ["medium", "high"]
        4. The response MUST be a FLAT JSON object that ONLY contains the VALUE of the parameters.
        5. DO NOT include schema keywords like 'type', 'title', 'anyOf', or 'default' in the final JSON output.
        6. If the question cannot be answered using the tool (e.g., general knowledge), return an empty JSON object.
        7. Respond ONLY with the JSON object.
    
    User Question: "{user_question}"
    """
    
    # Define the payload for the Ollama API
    payload = {"model": model_name, 
               "prompt": prompt, 
               "stream": False, 
               "format": "json", 
               "temperature": 0}

    # Start an aiohttp session
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post("http://localhost:11434/api/generate", json=payload) as resp:
                resp.raise_for_status()
                ollama_response_str = await resp.text()
                print("Response created. Converting results...")
                ollama_response_obj = json.loads(ollama_response_str)
                params_str = ollama_response_obj.get('response', '{}')
                params_dict = json.loads(params_str)
                return params_dict
        except Exception as e:
            print(f"Error getting parameters from LLM: {e}")
            return {}

# +++++++++++ Other Functions +++++++++++++++
# ALERT: You might need to update this function when you add new fields to the alert data.
def reduce_alert_data(raw_data: dict) -> dict:
    """
    Cleans the incoming JSON data from the alert query and reduces its size.
    Only holds one of the similar logs.
    """
    try:
        # Take log list
        alerts = raw_data.get("data", {}).get("alerts", [])
        if not alerts:
            return raw_data  # If there is nothing to process, return as is

        unique_alerts = []
        seen_signatures = set()
        original_count = len(alerts)

        for alert in alerts:
            # Only take first IP row
            host_data = alert.get("host", {})
            ip_list = host_data.get("ip", [])
            if ip_list:
                # Keep the first IP in a list to preserve original structure
                host_data["ip"] = [ip_list[0]]

            # Create signature
            # We consider important fields except for the timestamp.
            # Rule name, rule parameters, and host information (with cleaned IP)
            signature = (
                alert.get("kibana.alert.rule.name"),
                json.dumps(alert.get("kibana.alert.rule.parameters"), sort_keys=True),
                json.dumps(host_data, sort_keys=True)
            )

            # If we haven't seen this signature before, add it to the list
            if signature not in seen_signatures:
                unique_alerts.append(alert)
                seen_signatures.add(signature)

        # Update the cleaned alert list and the returned hit count
        raw_data["data"]["alerts"] = unique_alerts
        raw_data["data"]["hits_returned"] = len(unique_alerts)

        print(f"Data reduced. Original hits: {original_count}, Cleaned hits: {len(unique_alerts)}")
        return raw_data

    except Exception as e:
        print(f"Error during alert reduction: {e}")
        return raw_data  # If there is an error, return the original data


async def last_alert(alert_index: str = ES_ALERTS_INDEX): # Learn what type of data it returns and specify it here.
    """Returns the latest alert"""

    latest_alert_query = {
        "size": 1,
        "sort": [{"kibana.alert.rule.execution.timestamp": "desc"}],
        "_source": ["kibana.alert.rule.execution.timestamp", "kibana.alert.rule.name"]
    }

    try:
        async with AsyncElasticsearch(ES_HOSTS, basic_auth=(ES_USERNAME, ES_PASSWORD)) as client:

            # İlk sorgu
            last_data = await client.search(index=alert_index, body=latest_alert_query)
            last_hits = last_data.get('hits', {}).get('hits', [])

            if not last_hits:
                print("No alerts found in the initial query.")
                return False
            last_alert = last_hits[0].get('_source', {})
            return last_alert
    
    except Exception as e:
        print(f"Error during Elasticsearch query: {e}")
        return False

async def process_alerts(history: dict):
    print("Security Assistant is generating response...")
    mode_status = "STANDBY"

    response_time_start = time.perf_counter()  # Start time for response time measurement

    # Take parameters from Pydantic model and query according to them
    # Params dictionary
    params_instance = QueryAlertParams()

    query_result_json_str = await query_alerts(params_instance)
    response_time_end = time.perf_counter()  # End time for response time measurement
    query_time = response_time_end - response_time_start
    print(f"Querying alert data took {query_time:.2f} seconds.")

    raw_query_result_reduced = reduce_alert_data(json.loads(query_result_json_str))

    print("\n### Raw Alert Data Retrieved ###")
    print(json.dumps(raw_query_result_reduced, indent=2))
    print("#########################################\n")

    # Generate final answer
    print("Generating answer...")

    prompt = "--- ANALYSIS RESULT ---"
    system_prompt = """
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
    answer_start_time = time.perf_counter()  # Start time for final answer generation
    answer = await ask_LLM(
        prompt,
        history,
        system_prompt,
        model_name=ANSWER_LLM
    )
    answer_end_time = time.perf_counter()  # End time for final answer generation
    response_time = answer_end_time - answer_start_time

    print(f"Generating final answer took {response_time:.2f} seconds.")

    print("\n### Assistant Answer ###")
    print(answer)

    # Save conversation
    print("\nSaving conversation...")
    date_and_time = datetime.now().isoformat()

    new_entry = {
        "timestamp": date_and_time,
        "mode": mode_status,
        "LLM": ANSWER_LLM,
        "response_time": f"{response_time} seconds",
        "user_prompt": None,
        "data_context": json.dumps(raw_query_result_reduced, indent=2),
        "answer": answer
    }

    history["messages"].append(new_entry)


async def chat_mode(history: dict, user_prompt: str):
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    mode_status = "CHAT"

    system_prompt = f"""
    ROLE & OBJECTIVE

    You are an expert Cybersecurity Data Analyst Assistant. Your goal 
is to interpret database logs, detect anomalies, and answer user 
questions based on the provided conversation history and data tools.

    CURRENT CONTEXT
    - Current Time: {current_time}
    - Current Mode: {mode_status}

    INPUT STRUCTURE
    The input you receive is a conversation history. It contains:
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

    answer_start_time = time.perf_counter()  # Start time for final answer generation
    answer = await ask_LLM(
        user_prompt,
        history,
        system_prompt,
        model_name=ANSWER_LLM
    )
    answer_end_time = time.perf_counter()    # End time for final answer generation
    response_time = answer_end_time - answer_start_time

    print(answer)

    date_and_time = datetime.now().isoformat()

    new_entry = {
        "timestamp": date_and_time,
        "mode": mode_status,
        "LLM": ANSWER_LLM,
        "response_time_seconds": response_time,
        "user_prompt": user_prompt,
        "data_context": None,
        "answer": answer
    }

    history["messages"].append(new_entry)

async def standby_mode(history: dict):

    while True:
        print("\n[Standby] Checking for new alerts...", end="", flush=True)

        last_alert_1 = await last_alert()
        time.sleep(5)
        last_alert_2 = await last_alert()

        if last_alert_1 != last_alert_2:
            print("[!] New alerts detected!")
            user_selection = input("Do you want to check these alerts?")

            if user_selection.strip().lower() == 'yes':
                await process_alerts(history)
            elif user_selection.strip().lower() == 'no':
                print("Continuing to monitor...")
        else:
            print(" No new alerts.")
    
async def custom_query_mode(history : dict):
    """Main loop to run the assistant."""
    mode_status = "CUSTOM_QUERY"

    while True:
        user_question = input("\n> ")
        if user_question.lower() == 'exit':
            break

        # Extract parameters
        print("\nExtracting tool parameters from user question...")
    
        query_start_time = time.perf_counter() # Mark the start of generation of query
    
        tool_params_dict = await generate_query_LLM(user_question)
    
        query_end_time = time.perf_counter()   # Mark the end of generation of query
        query_time = query_end_time - query_start_time
        print(f"Creating query took {query_time:.2f} seconds.")

        # If parameters are empty, skip tool call
        if not tool_params_dict:
            print("No tool required. Forwarding question directly to LLM.")
            final_answer = await ask_LLM({"info": "No tool was called."}, user_question)
        
        # Parameters are generated, call the tool
        else:
            try:
                print(f"Parameters received from LLM: {tool_params_dict}") # Debug print

                try:
                    # Validate and convert parameters using the Pydantic model
                    params = QueryAlertParams(**tool_params_dict)

                except Exception as pydantic_error: # Parameters doesn't match with the Pydantic model
                    print(f"Pydantic Validation Error: {pydantic_error}")        
                    final_answer = f"Error Detail: {pydantic_error}"
                    print(final_answer)
                    
                    continue
                
                # Execute the Data Tool
                print("\nExecuting the data tool (query_alert_data)...")
                result_json_str = await query_alerts(params)

                # First take raw data
                raw_retrieved_context = json.loads(result_json_str)

                # Clean and reduce the data
                print("\nReducing and cleaning alert data...")
                retrieved_context = reduce_alert_data(raw_retrieved_context)

                # Display the raw data returned from the tool
                print("\n===== Cleaned Data =====")
                print(json.dumps(retrieved_context, indent=2))
                print("-----------------------------------\n")

                # Generate Final Answer
                print("Sending data to LLM for interpretation...")

                prompt = f"""
                    Important Rules to Follow:
                        1. You are a data analyst assistant with a focus on cybersecurity. Answer the user's question based ONLY on the following context. 
                        2. Make comments about the results you got in a cybersecurity perspective. 
                        3. Make relevant correlations between different types of context you have. For example, you can check the MITRE ATT&CK information in each log to predict an attack chain. 
                        4. It is recommended to make comments about connected MITRE tactics, techniques, and subtechniques.
                        5. You can warn the user for upcoming steps with getting inspiration from possible future MITRE techniques and subtechniques of the attacker based on the log data.

                    --- CONTEXT ---
                    {json.dumps(retrieved_context, indent=2)}

                    --- QUESTION ---
                    {user_question}

                    --- ANSWER ---
                    """

                final_answer_start_time = time.perf_counter() # Start time for final answer generation
                final_answer = await ask_LLM(user_question, history, prompt)
                final_answer_end_time = time.perf_counter() # End time for final answer generation
                response_time = final_answer_end_time - final_answer_start_time
                
                print(f"Generating final answer took {response_time:.2f} seconds.")

            except Exception as e:
                final_answer = f"An error occurred during tool execution: {e}"

        print("\n===== Cybersecurity Assistant Answer =====")
        print(final_answer)

        date_and_time = datetime.now().isoformat()
        
        new_entry = {
        "timestamp": date_and_time,
        "mode": mode_status,
        "LLM": ANSWER_LLM,
        "response_time_seconds": response_time,
        "user_prompt": user_question,
        "data_context": retrieved_context,
        "answer": final_answer
        }

        history["messages"].append(new_entry)


# +++++++++++++++++++++++++++++++++++++++++++++++++++++
# ++++++++++++++++++++ Main Execution +++++++++++++++++

async def main():
    """Main loop to run the assistant."""

    # Initialize chat history
    history = {
        "session_start": datetime.now().isoformat(),
        "messages": []
    }

    os.system('clear')
    
    print("\nWelcome to the Security Assistant CLI\n")
    while True:
        print("===== Main Menu =====\n")
        print("0. Chat Mode")
        print("1. Standby Mode")
        print("2. Custom Query Mode")
        print("\nq. Quit\n")

        try:
            # Main menu input doesn't need to be async since we aren't running tasks yet
            user_choice = input("Enter your choice: ").strip()

            if user_choice == '0':
                os.system('clear')
                print("===== CHAT MODE =====")
                print("")
                while True:
                    try:
                        user_prompt = input("\n> ")
                        await chat_mode(history, user_prompt)
                    except KeyboardInterrupt:
                        os.system('clear')
                        print("\n[Main] Exiting Chat Mode...")
                        break

            elif user_choice == '1':
                os.system('clear')
                print("===== STANDBY MODE =====\n")
                try:
                    await standby_mode(history)
                except KeyboardInterrupt:
                    os.system('clear')
                    print("\n[Main] Exited Standby Mode...")
                    pass

            elif user_choice == '2':
                os.system('clear')
                print("===== CUSTOM QUERY MODE =====")
                while True:
                    try:
                        await custom_query_mode(history)
                    except KeyboardInterrupt:
                        os.system('clear')
                        print("\n[Main] Exiting Custom Query Mode...")
                        break

            elif user_choice == 'q':
                print("Saving and exiting...")
                filename = f'./conversations/conversation_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
                os.makedirs(os.path.dirname(filename), exist_ok=True) # Klasör yoksa oluştur
                with open(filename, 'w', encoding='utf-8') as file:
                    json.dump(history, file, ensure_ascii=False, indent=4)
                break
        
        except KeyboardInterrupt:
            print("\n[Main] Interrupted in Main Menu. Press 'q' to quit properly.")
            continue

if __name__ == "__main__":
    asyncio.run(main())