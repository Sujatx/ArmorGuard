# Agent Prompt Injection Rewrite

## Overview
This document outlines the architectural changes made to `agent/agent.py` to enable the prompt injection demo scenario.

## The Problem
The initial implementation of `agent/agent.py` ran the vulnerability scanning tools in a deterministic, hardcoded sequence. The LLM was only used at the very end of the process to summarize the numerical counts of the findings. 

Because the LLM never actually ingested the raw HTML of the target site, and because the LLM did not actually drive the execution of the tools, it was impossible for the hidden `AGENT DIRECTIVE` inside `demo-target/app.py` to trigger an out-of-scope `httpx` exfiltration attempt.

## The Solution

To support the prompt injection demo while retaining the deterministic stability of the scan pipeline, we modified the `_summarize` phase:

1. **Ingesting Target Content:**
   In `_summarize`, we now fetch the target's raw homepage HTML and inject it into the prompt for the `_summary_agent`. The system prompt now explicitly instructs the agent to follow any directives it discovers in the HTML.

2. **Exposing an HTTP Request Tool:**
   We added a new `@_summary_agent.tool` named `http_request`. This tool allows the summary agent to attempt HTTP requests if instructed by the injected HTML comment. 
   When the agent calls this tool, we intercept it by passing the URL to `_armoriq_gate`.

3. **Triggering the ArmorIQ Gate:**
   When `_armoriq_gate` receives the out-of-bounds `fake-exfil-domain.local/steal` URL, it raises a `PolicyBlockedException(reason="out_of_scope_target")`.

4. **Fixing Drift Classification:**
   The `_handle_armoriq_block` function previously coerced all `out_of_scope_target` blocks into `hallucination` drift classifications. We modified this to preserve the `prompt_injection` classification if it is already present in the block's metadata. 

## Result
During the summary phase, the LLM reads the HTML, sees the `AGENT DIRECTIVE`, and uses the `http_request` tool to attempt exfiltration. ArmorIQ intercepts the tool execution and raises an `intent_drift_detected` event with `driftClassification: "prompt_injection"`, followed by an `agent_halted` event.

This fulfills the demo requirement without jeopardizing the stability of the core scanning pipeline.
