# @git-agentic/sentinel-mcp

`sentinel-mcp`: a stdio [Model Context Protocol](https://modelcontextprotocol.io/)
server exposing Sentinel's pre-install audit tools to agent hosts. It is a
thin client to a running Sentinel proxy — it audits nothing itself, and the
only write tool *requests* approval; it can never grant one.

> **Alpha.** This is a pre-1.0 preview (`0.1.0-alpha.1`). APIs may change
> without notice. Not production-ready.

```bash
npm install -g @git-agentic/sentinel-mcp@alpha
```

MCP client configuration:

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "sentinel-mcp",
      "env": { "SENTINEL_PROXY": "http://localhost:4873" }
    }
  }
}
```

Tools: `sentinel_audit`, `sentinel_audit_tree`, `sentinel_capabilities`,
`sentinel_check_provenance`, `sentinel_list_violations`, `sentinel_explain`,
and `sentinel_request_approval` (request-only, never a grant). See the
[Sentinel repository](https://github.com/git-agentic/pkg-registry) for the
full documentation.

## License

Apache-2.0
