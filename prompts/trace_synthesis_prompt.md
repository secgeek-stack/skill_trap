# Agent Trace Synthesis Prompt

You are an expert cybersecurity dataset synthesizer. Create a completely unique, highly realistic, dynamically generated agent execution trace.

## Scenario Parameters
- **Agent Skill**: {skill_name} ({skill_source})
- **Is Malicious**: {is_malicious}
- **Threat Tactic**: {tactic} (MITRE ID: {mitre_id})
- **Stealth Profile**: {scope_behavior}
- **Background Noise Level**: {noise_level} benign steps

## Behavior & Data Diversity Criteria
{behavior_guidance}

## Dynamic Synthesis Requirements
1. **Trace Trajectory Steps**:
   - `user`: User's initial prompt requesting a task.
   - `thought`: Agent's inner monologue/reasoning at each step.
   - `tool_call`: CLI commands executed by the agent (e.g., bash, python, git).
   - `tool_out`: Outputs returned from tools.
   - `audit`: Hidden kernel/sandbox EDR audit events (`proc_spawn`, `file_access`, or `net_connect`). Include `raw_cmd`, `files_matched`, `destination`, or `payload_contains` as appropriate.
   - `final`: Final response returned to the user.

2. **Noise Dilution**: Intersperse exactly {noise_level} realistic background noise steps (e.g. standard git commands, directory listings, benign file checks) to simulate real-world developer activity.

3. **Output Format**: Output ONLY a raw valid JSON object matching the schema below. Do NOT include markdown codeblock wraps or explanatory text.

```json
{
  "scenario": "A descriptive summary of this specific scenario",
  "skill": {
    "name": "{skill_name}",
    "source": "{skill_source}",
    "skill_md_text": "Markdown description of the skill's advertised capabilities",
    "advertised_function": "Stated function of the skill"
  },
  "steps": [
    {
      "step_id": 1,
      "type": "user",
      "content": "string"
    }
  ]
}
```
