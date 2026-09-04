# WebMCP Evals Dataset

Test dataset for [Chrome's experimental WebMCP evals](https://developer.chrome.com/docs/ai/webmcp/evals)
([evals-cli](https://github.com/GoogleChromeLabs/webmcp-tools/tree/main/evals-cli)).

`guardstudio-tools.json` covers tool selection for all five Guard Studio WebMCP
tools: one natural-language prompt per tool, with the expected tool call and
arguments. Use it with the evals-cli to check that an agent picks the right
Guard Studio tool for import, analysis, text scanning, guarded codegen, and
call simulation.
