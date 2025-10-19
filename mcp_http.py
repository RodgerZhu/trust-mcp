# server.py
## Server Definition (HTTP API for TDX tools)
import sys
import os
# First add lib directory to sys.path
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))

import asyncio
import base64
import datetime
import json
import logging
import requests
import subprocess
import time
from io import StringIO
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.applications import Starlette
from starlette.requests import Request as StarletteRequest
from starlette.responses import JSONResponse as StarletteJSONResponse
from starlette.routing import Route

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

# Mock types module for compatibility with existing functions
class MockTypes:
    class TextContent:
        def __init__(self, type=None, text=None):
            self.type = type
            self.text = text

types = MockTypes()

# Global configuration
LOG = logging.getLogger(__name__)
ATTEST_SERVICE_ENDPOINT = "http://47.76.235.246:8080/attestation"

# Create FastAPI application
app = FastAPI(title="TDX Tools HTTP API", description="HTTP API for accessing TDX-related tools")


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


# Removed session_id validation function as it's no longer required

# HTTP endpoint for getRawTDXQuote
@app.post("/api/getRawTDXQuote")
async def http_get_raw_tdx_quote():
    """HTTP endpoint to retrieve raw TDX Quote data"""
    try:
        # Call the existing fetch_quote function
        result = await fetch_quote()
        # Extract JSON data from TextContent
        if result and isinstance(result[0], dict):
            return result[0]
        elif result and hasattr(result[0], 'text'):
            return json.loads(result[0].text)
        else:
            return {"status": 500, "error": "Invalid response format"}
    except Exception as e:
        print(f"Error in getRawTDXQuote: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# HTTP endpoint for attestTDXQuote
@app.post("/api/attestTDXQuote")
async def http_attest_tdx_quote(request: Request):
    """HTTP endpoint to attest TDX Quote"""
    try:
        # Parse request body
        body = await request.json()
        url = body.get("url")
        
        if not url:
            raise HTTPException(status_code=400, detail="Missing required parameter 'url'")
        
        # Call the existing attest_quote function
        result = await attest_quote(url)
        # Extract JSON data from TextContent
        if result and isinstance(result[0], dict):
            return result[0]
        elif result and hasattr(result[0], 'text'):
            return json.loads(result[0].text)
        else:
            return result  # Return directly if it's already a dictionary (error case)
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in attestTDXQuote: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# HTTP endpoint for getTEEStatus
@app.post("/api/getTEEStatus")
async def http_get_tee_status():
    """HTTP endpoint to check TEE status"""
    try:
        # Call the existing get_tee_status function
        result = await get_tee_status()
        # Extract JSON data from TextContent
        if result and isinstance(result[0], dict):
            return result[0]
        elif result and hasattr(result[0], 'text'):
            return json.loads(result[0].text)
        else:
            return {"status": 500, "error": "Invalid response format"}
    except Exception as e:
        print(f"Error in getTEEStatus: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# HTTP endpoint for fetchTDEventlog
@app.post("/api/fetchTDEventlog")
async def http_fetch_td_eventlog():
    """HTTP endpoint to retrieve TD Eventlog"""
    try:
        # Call the existing fetch_td_eventlog function
        result = await fetch_td_eventlog()
        # Extract JSON data from TextContent
        if result and isinstance(result[0], dict):
            return result[0]
        elif result and hasattr(result[0], 'text'):
            return json.loads(result[0].text)
        else:
            return {"status": 500, "error": "Invalid response format"}
    except Exception as e:
        print(f"Error in fetchTDEventlog: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# HTTP endpoint to list all available tools
@app.get("/api/tools")
async def list_available_tools():
    """List all available tools with their descriptions and input schemas"""
    return [
        {
            "name": "getRawTDXQuote",
            "description": "Retrieve raw TDX Quote data only, without attestation. Returns Base64 encoded quote data and parsing results.",
            "endpoint": "/api/getRawTDXQuote",
            "method": "POST",
            "required_params": [],
            "example_request": {}
        },
        {
            "name": "attestTDXQuote",
            "description": "Attest TDX Quote. Requires attestation service URL, then sends TDX Evidence to the specified service for attestation.",
            "endpoint": "/api/attestTDXQuote",
            "method": "POST",
            "required_params": ["url"],
            "example_request": {"url": "http://example.com/attestation"}
        },
        {
            "name": "getTEEStatus",
            "description": "Check if TEE is enabled on the OS where MCP Server is running",
            "endpoint": "/api/getTEEStatus",
            "method": "POST",
            "required_params": [],
            "example_request": {}
        },
        {
            "name": "fetchTDEventlog",
            "description": "Retrieve TD Eventlog",
            "endpoint": "/api/fetchTDEventlog",
            "method": "POST",
            "required_params": [],
            "example_request": {}
        }
    ]

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.datetime.now().isoformat()}


# Root endpoint with basic information
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "name": "TDX Tools HTTP API",
        "version": "1.0.0",
        "description": "HTTP API for accessing TDX-related tools",
        "endpoints": {
            "tools": "/api/tools",
            "health": "/health",
            "getRawTDXQuote": "/api/getRawTDXQuote",
            "attestTDXQuote": "/api/attestTDXQuote",
            "getTEEStatus": "/api/getTEEStatus",
            "fetchTDEventlog": "/api/fetchTDEventlog"
        }
    }


if __name__ == "__main__":
    import uvicorn  # Import uvicorn ASGI server
    print("Starting TDX Tools HTTP API server...")
    print("Available endpoints:")
    print("  GET  /                    - API information")
    print("  GET  /health              - Health check")
    print("  GET  /api/tools           - List available tools")
    print("  POST /api/getRawTDXQuote  - Get raw TDX Quote")
    print("  POST /api/attestTDXQuote  - Attest TDX Quote")
    print("  POST /api/getTEEStatus    - Check TEE status")
    print("  POST /api/fetchTDEventlog - Retrieve TD Eventlog")
    print("\nServer starting on http://0.0.0.0:8800")
    uvicorn.run(app, host="0.0.0.0", port=8800)  # Run FastAPI application, listening on all interfaces and specified port
