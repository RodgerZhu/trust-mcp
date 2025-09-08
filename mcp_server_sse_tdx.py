# server.py
## Server Definition (webpage fetch + bing search)
import sys
import os
# First add lib directory to sys.path
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))

import anyio
import asyncio
import base64
import click
import datetime
import hashlib
import httpx
import json
import logging
import requests
import subprocess
import time
from io import StringIO
from typing import Any, List
from urllib.parse import parse_qs, urlparse
from concurrent.futures import ThreadPoolExecutor

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.routing import Mount, Route

# Attempt to import the quote_generator module
try:
    import quote_generator
    print("Successfully imported quote_generator module")
except ImportError as e:
    print(f"Failed to import quote_generator module: {str(e)}")
    raise

# Import TDX-related modules
from tdxmeasure.cli import TDXEventLogsCmd
from cctrusted_base.api import CCTrustedApi
from cctrusted_base.eventlog import TcgEventLog
from cctrusted_base.tcgcel import TcgTpmsCelEvent
from cctrusted_vm.cvm import ConfidentialVM
from cctrusted_vm.sdk import CCTrustedVmSdk

# Global configuration
LOG = logging.getLogger(__name__)
ATTEST_SERVICE_ENDPOINT = "http://47.76.235.246:8080/attestation"


async def fetch_quote():
    """Generate TDX quote data"""
    try:
        quote_data, parse_result = quote_generator.generate_quote()
        # Convert byte data to Base64 encoded string for JSON transmission
        quote_base64 = base64.b64encode(quote_data).decode('utf-8')
        
        # Return response containing both data types
        result = {'status': 200, 'quote_data': quote_base64, 'parse_result': parse_result}
        return [types.TextContent(type="text", text=json.dumps(result))]
    except Exception as e:
        error_result = {'status': 500, 'error': str(e)}
        return [types.TextContent(type="text", text=json.dumps(error_result))]


async def attest_quote(url):
    """Perform TDX quote generation and attestation"""
    try:
        # 1. Call quote_generator.generate_quote() to obtain quote
        quote_data, quote_ret = quote_generator.generate_quote()
        # Print hex format of quote_data and data length
        print(f"quote_data hex: {quote_data.hex()}")
        print(f"quote_data length: {len(quote_data)}")
        
        # 2. Convert byte data to Base64 encoded string
        quote_base64 = base64.b64encode(quote_data).decode('utf-8')
        
        # 3. Package according to evidence data structure
        evidence = {
            "quote": quote_base64,
            "aa_eventlog": None,
            "cc_eventlog": None
        }
        
        # 4. Transcode evidence (URL safe Base64 without padding)
        evidence_json = json.dumps(evidence)
        evidencebase64 = base64.b64encode(evidence_json.encode()).decode()
        evidencebase64 = evidencebase64.replace('+', '-').replace('/', '_').replace('=', '')
        
        # 5. Package req structure
        req = {
            "verification_requests": [
                {
                    "tee": "tdx",
                    "evidence": evidencebase64
                }],
            "policy_ids": []
        }
        
        # 6. Send request to the specified attestation service URL
        print(f"Starting attestation request to {url} at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        # Timeout set to 5 seconds
        response_attest = requests.post(url, json=req, timeout=5)
        dec_response_att = response_attest.text.split('.')[1]
        dec_response_att = base64.b64decode(dec_response_att).decode('utf-8')

        print(f"Response attest raw: {dec_response_att}")
        result = {'status': 200, 'attest_result': dec_response_att}
        return [types.TextContent(type="text", text=json.dumps(result))]
    except requests.exceptions.Timeout:
        error_msg = 'Attestation service request timed out'
        print(error_msg)
        response = {'error': error_msg}
    except requests.exceptions.ConnectionError:
        error_msg = 'Failed to connect to attestation service: Connection refused'
        print(error_msg)
        response = {'error': error_msg}
    except Exception as e:
        error_msg = f'Failed to connect to attestation service: {str(e)}'
        print(error_msg)
        response = {'error': error_msg}
    
    return response


async def get_tee_status():
    """Check if TEE is enabled on the OS where MCP Server is running
    Check for the string 'tdx: Guest detected' by executing the command dmesg | grep -i tdx
    """
    try:
        # Execute shell command
        process = await asyncio.create_subprocess_shell(
            'dmesg | grep -i tdx',
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Get command output
        stdout, stderr = await process.communicate()
        output = stdout.decode('utf-8')
        print(f"dmesg | grep -i tdx output: {output}")
        
        # Check if specific string is contained
        if 'tdx: Guest detected' in output:
            result = {'status': 200, 'message': 'Current MCP Server is running in a TD Guest'}
        else:
            result = {'status': 200, 'message': 'Current MCP Server is running in a normal environment'}

        return [types.TextContent(type="text", text=json.dumps(result, ensure_ascii=False))]
    except Exception as e:
        error_result = {'status': 500, 'error': f'Command execution failed: {str(e)}'}
        return [types.TextContent(type="text", text=json.dumps(error_result, ensure_ascii=False))]


async def fetch_td_eventlog():
    """Retrieve TD Eventlog
    Directly call APIs from CCTrustedVmSdk and CCTrustedApi to obtain event logs
    """
    try:
        # Redirect standard output and standard error to in-memory buffer
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        result = StringIO()
        sys.stdout = result
        sys.stderr = result
        
        # Save original logging configuration and reconfigure logging to output to result
        old_log_handlers = logging.root.handlers[:]
        for handler in old_log_handlers:
            logging.root.removeHandler(handler)
        log_handler = logging.StreamHandler(result)
        logging.root.addHandler(log_handler)
        logging.root.setLevel(logging.INFO)
        
        try:
            print("Starting to retrieve TD Eventlog")

            # Check if running in a confidential VM
            if ConfidentialVM.detect_cc_type() == CCTrustedApi.TYPE_CC_NONE:
                print("This is not a confidential VM!")
                output = "Current environment is not a confidential VM, cannot retrieve TD Eventlog"
            elif os.geteuid() != 0:
                print("Please run as root which is required for this example!")
                output = "Root privileges required to retrieve TD Eventlog"
            else:
                # Simulate parameters from decod.py
                class Args:
                    def __init__(self):
                        self.start = None
                        self.count = None
                        self.cel_format = False

                args = Args()

                # Retrieve event logs
                event_logs = CCTrustedVmSdk.inst().get_cc_eventlog(args.start, args.count)
                if event_logs is None:
                    print("No event log fetched. Check debug log for issues.")
                    output = "No TD Eventlog data retrieved"
                else:
                    print(f"Total {len(event_logs)} of event logs fetched.")

                    # Replay event logs
                    res = CCTrustedApi.replay_cc_eventlog(event_logs)
                    print("Replayed result of collected event logs:")
                    for key in res.keys():
                        print(f"RTMR[{key}]: ")
                        print(f"     {res.get(key).get(12).hex()}")

                    print("Dump collected event logs:")
                    for event in event_logs:
                        if isinstance(event, TcgTpmsCelEvent):
                            print("TcgTpmsCelEvent")
                            if args.cel_format:
                                TcgTpmsCelEvent.encode(event, TcgEventLog.TCG_FORMAT_CEL_TLV).dump()
                            else:
                                event.to_pcclient_format().dump()
                        else:
                            event.dump()

        finally:
            # Get all output content
            output = result.getvalue()
            # Restore standard output and standard error
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            # Restore original logging configuration
            logging.root.handlers.clear()
            for handler in old_log_handlers:
                logging.root.addHandler(handler)
        
        with open('tdeventlog.txt', 'w') as f:
            f.write(output)
            
        # Return result
        response = {
            'status': 200,
            'message': 'TD Eventlog retrieval successful',
            'td_eventlog': output
        }
        print(f"TD Eventlog: {response}")
        return [types.TextContent(type="text", text=json.dumps(response))]
    except Exception as e:
        error_result = {'status': 500, 'error': f'TD Eventlog retrieval failed: {str(e)}'}
        return [types.TextContent(type="text", text=json.dumps(error_result))]


# Create SSE Server
sse = SseServerTransport("/messages/")  # Create SSE server transport instance with path "/messages/"
app = Server("mcp-website-fetcher")  # Create MCP server instance with name "mcp-website-fetcher"


@app.call_tool()
async def fetch_tool(
  name: str, arguments: dict
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Define asynchronous function fetch_tool as MCP tool call processor
    Parameters: name - tool name, arguments - tool parameter dictionary
    Returns: List containing text, image, or embedded resources
    """
    if name == "getRawTDXQuote":
        # If "getRawTDXQuote" tool is called
        return await fetch_quote()  # Call fetch_quote function to generate TDX quote data

    elif name == "attestTDXQuote":
        # If "attestTDXQuote" tool is called
        print(f"attestTDXQuote arguments: {arguments}")
        print(f"attestTDXQuote arguments url: {arguments.get('url')}")

        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")  # Check if required url parameter is provided
        return await attest_quote(arguments["url"])  # Call attest_quote function for TDX quote attestation

    elif name == "getTEEStatus":
        # If "getTEEStatus" tool is called
        return await get_tee_status()  # Call get_tee_status function to check TEE status

    elif name == "fetchTDEventlog":
        # If "fetchTDEventlog" tool is called
        return await fetch_td_eventlog()  # Call fetch_td_eventlog function to retrieve TD Eventlog


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    """Define asynchronous function list_tools to list available tools
    Returns: List of Tool objects describing available tools
    """
    return [
        types.Tool(
            name="getRawTDXQuote",
            description="Retrieve raw TDX Quote data only, without attestation. Returns Base64 encoded quote data and parsing results.",
            inputSchema={
                "type": "object",
                "required": [],
                "properties": {},
            },
        ),
        types.Tool(
            name="attestTDXQuote",
            description="Attest TDX Quote. Requires attestation service URL, then sends TDX Evidence to the specified service for attestation.",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Attestation Service URL",
                    }
                },
            },
        ),
        types.Tool(
            name="getTEEStatus",
            description="Check if TEE is enabled on the OS where MCP Server is running",
            inputSchema={
                "type": "object",
                "required": [],
                "properties": {},
            },
        ),
        types.Tool(
            name="fetchTDEventlog",
            description="Retrieve TD Eventlog",
            inputSchema={
                "type": "object",
                "required": [],
                "properties": {},
            },
        ),
    ]


async def handle_sse(request):
    """Define asynchronous function handle_sse to process SSE requests
    Parameters: request - HTTP request object
    """
    async with sse.connect_sse(
        request.scope, request.receive, request._send
    ) as streams:
        # Establish SSE connection and obtain input/output streams
        await app.run(
            streams[0], streams[1], app.create_initialization_options()
        )  # Run MCP application to handle SSE connection


# Create Starlette application instance and configure routes
starlette_app = Starlette(
    debug=True,
    routes=[
        Route("/sse", endpoint=handle_sse),  # Set /sse route with handle_sse function
        Mount("/messages/", app=sse.handle_post_message),  # Mount /messages/ path to handle POST messages
    ],
)


if __name__ == "__main__":
    import uvicorn  # Import uvicorn ASGI server
    uvicorn.run(starlette_app, host="0.0.0.0", port=8800)  # Run Starlette application, listening on all interfaces and specified port
