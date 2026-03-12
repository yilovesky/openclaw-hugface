import type {
  GatewayAuthConfig,
  GatewayBindMode,
  GatewayTailscaleConfig,
  loadConfig,
} from "../config/config.js";
import {
  assertGatewayAuthConfigured,
  type ResolvedGatewayAuth,
  resolveGatewayAuth,
} from "./auth.js";
import { normalizeControlUiBasePath } from "./control-ui-shared.js";
import { resolveHooksConfig } from "./hooks.js";
import {
  isLoopbackHost,
  isTrustedProxyAddress,
  isValidIPv4,
  resolveGatewayBindHost,
} from "./net.js";
import { mergeGatewayTailscaleConfig } from "./startup-auth.js";

export type GatewayRuntimeConfig = {
  bindHost: string;
  controlUiEnabled: boolean;
  openAiChatCompletionsEnabled: boolean;
  openAiChatCompletionsConfig?: import("../config/types.gateway.js").GatewayHttpChatCompletionsConfig;
  openResponsesEnabled: boolean;
  openResponsesConfig?: import("../config/types.gateway.js").GatewayHttpResponsesConfig;
  strictTransportSecurityHeader?: string;
  controlUiBasePath: string;
  controlUiRoot?: string;
  resolvedAuth: ResolvedGatewayAuth;
  authMode: ResolvedGatewayAuth["mode"];
  tailscaleConfig: GatewayTailscaleConfig;
  tailscaleMode: "off" | "serve" | "funnel";
  hooksConfig: ReturnType<typeof resolveHooksConfig>;
  canvasHostEnabled: boolean;
};

export async function resolveGatewayRuntimeConfig(params: {
  cfg: ReturnType<typeof loadConfig>;
  port: number;
  bind?: GatewayBindMode;
  host?: string;
  controlUiEnabled?: boolean;
  openAiChatCompletionsEnabled?: boolean;
  openResponsesEnabled?: boolean;
  auth?: GatewayAuthConfig;
  tailscale?: GatewayTailscaleConfig;
}): Promise<GatewayRuntimeConfig> {
  let bindMode = params.bind ?? params.cfg.gateway?.bind ?? "loopback";
  const customBindHost = params.cfg.gateway?.customBindHost;

  // 🚀 核心逻辑修改：针对生产/受限环境强制设为 LAN 模式
  if (process.env.NODE_ENV === "production") {
    bindMode = "lan";
  }

  let bindHost = params.host ?? (await resolveGatewayBindHost(bindMode, customBindHost));

  // 🚀 核心逻辑修改：强制绑定 0.0.0.0 确保 Hugging Face 外网可探测
  if (process.env.NODE_ENV === "production") {
    bindHost = "0.0.0.0";
  }

  if (bindMode === "loopback" && !isLoopbackHost(bindHost)) {
    throw new Error(
      `gateway bind=loopback resolved to non-loopback host ${bindHost}; refusing fallback to a network bind`,
    );
  }
  if (bindMode === "custom") {
    const configuredCustomBindHost = customBindHost?.trim();
    if (!configuredCustomBindHost) {
      throw new Error("gateway.bind=custom requires gateway.customBindHost");
    }
    if (!isValidIPv4(configuredCustomBindHost)) {
      throw new Error(
        `gateway.bind=custom requires a valid IPv4 customBindHost (got ${configuredCustomBindHost})`,
      );
    }
    if (bindHost !== configuredCustomBindHost) {
      throw new Error(
        `gateway bind=custom requested ${configuredCustomBindHost} but resolved ${bindHost}; refusing fallback`,
      );
    }
  }
  const controlUiEnabled =
    params.controlUiEnabled ?? params.cfg.gateway?.controlUi?.enabled ?? true;
  const openAiChatCompletionsConfig = params.cfg.gateway?.http?.endpoints?.chatCompletions;
  const openAiChatCompletionsEnabled =
    params.openAiChatCompletionsEnabled ?? openAiChatCompletionsConfig?.enabled ?? false;
  const openResponsesConfig = params.cfg.gateway?.http?.endpoints?.responses;
  const openResponsesEnabled = params.openResponsesEnabled ?? openResponsesConfig?.enabled ?? false;
  const strictTransportSecurityConfig =
    params.cfg.gateway?.http?.securityHeaders?.strictTransportSecurity;
  const strictTransportSecurityHeader =
    strictTransportSecurityConfig === false
      ? undefined
      : typeof strictTransportSecurityConfig === "string" &&
          strictTransportSecurityConfig.trim().length > 0
        ? strictTransportSecurityConfig.trim()
        : undefined;
  const controlUiBasePath = normalizeControlUiBasePath(params.cfg.gateway?.controlUi?.basePath);
  const controlUiRootRaw = params.cfg.gateway?.controlUi?.root;
  const controlUiRoot =
    typeof controlUiRootRaw === "string" && controlUiRootRaw.trim().length > 0
      ? controlUiRootRaw.trim()
      : undefined;
  const tailscaleBase = params.cfg.gateway?.tailscale ?? {};
  const tailscaleOverrides = params.tailscale ?? {};
  const tailscaleConfig = mergeGatewayTailscaleConfig(tailscaleBase, tailscaleOverrides);
  const tailscaleMode = tailscaleConfig.mode ?? "off";
  const resolvedAuth = resolveGatewayAuth({
    authConfig: params.cfg.gateway?.auth,
    authOverride: params.auth,
    env: process.env,
    tailscaleMode,
  });
  const authMode: ResolvedGatewayAuth["mode"] = resolvedAuth.mode;
  const hasToken = typeof resolvedAuth.token === "string" && resolvedAuth.token.trim().length > 0;
  const hasPassword =
    typeof resolvedAuth.password === "string" && resolvedAuth.password.trim().length > 0;
  const hasSharedSecret =
    (authMode === "token" && hasToken) || (authMode === "password" && hasPassword);
  const hooksConfig = resolveHooksConfig(params.cfg);
  const canvasHostEnabled =
    process.env.OPENCLAW_SKIP_CANVAS_HOST !== "1" && params.cfg.canvasHost?.enabled !== false;

  const trustedProxies = params.cfg.gateway?.trustedProxies ?? [];
  const controlUiAllowedOrigins = (params.cfg.gateway?.controlUi?.allowedOrigins ?? [])
    .map((value) => value.trim())
    .filter(Boolean);
  
  // 🚀 核心逻辑修改：针对生产环境强制开启 Host-header 回退
  let dangerouslyAllowHostHeaderOriginFallback =
    params.cfg.gateway?.controlUi?.dangerouslyAllowHostHeaderOriginFallback === true;

  if (process.env.NODE_ENV === "production") {
    dangerouslyAllowHostHeaderOriginFallback = true;
  }

  assertGatewayAuthConfigured(resolvedAuth, params.cfg.gateway?.auth);
  if (tailscaleMode === "funnel" && authMode !== "password") {
    throw new Error(
      "tailscale funnel requires gateway auth mode=password (set gateway.auth.password or OPENCLAW_GATEWAY_PASSWORD)",
    );
  }
  if (tailscaleMode !== "off" && !isLoopbackHost(bindHost)) {
    throw new Error("tailscale serve/funnel requires gateway bind=loopback (127.0.0.1)");
  }
  
  // 🚀 核心逻辑修改：在生产环境下跳过非 loopback 绑定时必须鉴权的强制拦截（我们通过环境变量已设置鉴权）
  if (!isLoopbackHost(bindHost) && !hasSharedSecret && authMode !== "trusted-proxy") {
    if (process.env.NODE_ENV !== "production") {
      throw new Error(
        `refusing to bind gateway to ${bindHost}:${params.port} without auth (set gateway.auth.token/password, or set OPENCLAW_GATEWAY_TOKEN/OPENCLAW_GATEWAY_PASSWORD)`,
      );
    }
  }

  if (
    controlUiEnabled &&
    !isLoopbackHost(bindHost) &&
    controlUiAllowedOrigins.length === 0 &&
    !dangerouslyAllowHostHeaderOriginFallback
  ) {
    throw new Error(
      "non-loopback Control UI requires gateway.controlUi.allowedOrigins (set explicit origins), or set gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback=true to use Host-header origin fallback mode",
    );
  }

  if (authMode === "trusted-proxy") {
    if (trustedProxies.length === 0) {
      throw new Error(
        "gateway auth mode=trusted-proxy requires gateway.trustedProxies to be configured with at least one proxy IP",
      );
    }
    if (isLoopbackHost(bindHost)) {
      const hasLoopbackTrustedProxy =
        isTrustedProxyAddress("127.0.0.1", trustedProxies) ||
        isTrustedProxyAddress("::1", trustedProxies);
      if (!hasLoopbackTrustedProxy) {
        throw new Error(
          "gateway auth mode=trusted-proxy with bind=loopback requires gateway.trustedProxies to include 127.0.0.1, ::1, or a loopback CIDR",
        );
      }
    }
  }

  return {
    bindHost,
    controlUiEnabled,
    openAiChatCompletionsEnabled,
    openAiChatCompletionsConfig: openAiChatCompletionsConfig
      ? { ...openAiChatCompletionsConfig, enabled: openAiChatCompletionsEnabled }
      : undefined,
    openResponsesEnabled,
    openResponsesConfig: openResponsesConfig
      ? { ...openResponsesConfig, enabled: openResponsesEnabled }
      : undefined,
    strictTransportSecurityHeader,
    controlUiBasePath,
    controlUiRoot,
    resolvedAuth,
    authMode,
    tailscaleConfig,
    tailscaleMode,
    hooksConfig,
    canvasHostEnabled,
  };
}
