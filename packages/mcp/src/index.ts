#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ProxyClient, ProxyError } from "./client.js";
import { TOOLS } from "./tools.js";

/** Build an McpServer with every Sentinel tool registered against `client`. */
export function createMcpServer(client: ProxyClient): McpServer {
  const server = new McpServer({ name: "sentinel", version: "0.1.0-alpha.2" });
  for (const tool of TOOLS) {
    server.registerTool(
      tool.name,
      { description: tool.description, inputSchema: tool.inputSchema },
      async (args: Record<string, unknown>) => {
        try {
          const { text, structured } = await tool.handler(args, client);
          return { content: [{ type: "text" as const, text }], structuredContent: structured as Record<string, unknown> };
        } catch (e) {
          const msg = e instanceof ProxyError ? e.message : `tool ${tool.name} failed: ${(e as Error).message}`;
          return { content: [{ type: "text" as const, text: msg }], isError: true };
        }
      },
    );
  }
  return server;
}

async function main(): Promise<void> {
  const client = new ProxyClient(process.env.SENTINEL_PROXY ?? "http://localhost:4873");
  const server = createMcpServer(client);
  await server.connect(new StdioServerTransport());
}

// Run only when invoked as the entrypoint (not when imported by a test).
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
function isMain(): boolean {
  const a = process.argv[1];
  if (!a) return false;
  try { return import.meta.url === pathToFileURL(realpathSync(a)).href; } catch { return false; }
}
if (isMain()) main().catch((e) => { console.error(`sentinel-mcp: ${(e as Error).message}`); process.exit(1); });
