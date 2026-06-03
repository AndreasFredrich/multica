"use client";

import { Suspense, useEffect } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { useAuthStore } from "@multica/core/auth";
import { useWorkspaceStore } from "@multica/core/workspace";
import { setLoggedInCookie } from "@/features/auth/auth-cookie";
import { LoginPage, validateCliCallback } from "@multica/views/auth";

const oidcAuthorizeUrl = process.env.NEXT_PUBLIC_OIDC_AUTHORIZE_URL;
const oidcClientId = process.env.NEXT_PUBLIC_OIDC_CLIENT_ID;
const oidcScope = process.env.NEXT_PUBLIC_OIDC_SCOPE || "openid email profile";
const oidcLabel = process.env.NEXT_PUBLIC_OIDC_LABEL || "Continue with Agentic360";

function LoginPageContent() {
  const router = useRouter();
  const user = useAuthStore((s) => s.user);
  const isLoading = useAuthStore((s) => s.isLoading);
  const searchParams = useSearchParams();

  const cliCallbackRaw = searchParams.get("cli_callback");
  const cliState = searchParams.get("cli_state") || "";
  const nextUrl = searchParams.get("next") || "/issues";

  // Already authenticated — redirect to dashboard (skip if CLI callback)
  useEffect(() => {
    if (!isLoading && user && !cliCallbackRaw) {
      router.replace(nextUrl);
    }
  }, [isLoading, user, router, nextUrl, cliCallbackRaw]);

  const lastWorkspaceId =
    typeof window !== "undefined"
      ? localStorage.getItem("multica_workspace_id")
      : null;

  const handleSuccess = () => {
    const ws = useWorkspaceStore.getState().workspace;
    router.push(ws ? nextUrl : "/onboarding");
  };

  // OIDC (Agentic360 IAM) state carries the provider marker so the callback can
  // route the response to the OIDC exchange.
  const oidcState = ["provider:agentic360", nextUrl !== "/issues" ? `next:${nextUrl}` : ""]
    .filter(Boolean)
    .join(",");

  const oidcConfigured = Boolean(oidcAuthorizeUrl && oidcClientId);

  return (
    <div className="relative min-h-svh">
      {/* Brain background (same motif as the dashboard), with an overlay so the
          login card keeps its contrast. */}
      <div
        aria-hidden
        className="pointer-events-none fixed inset-0 -z-10 bg-cover bg-center"
        style={{ backgroundImage: "url(/ai-brain-bg.jpg)" }}
      />
      <div aria-hidden className="pointer-events-none fixed inset-0 -z-10 bg-background/75" />
      <LoginPage
        onSuccess={handleSuccess}
        oidc={
          oidcConfigured
            ? {
                authorizeUrl: oidcAuthorizeUrl!,
                clientId: oidcClientId!,
                redirectUri: `${window.location.origin}/auth/callback`,
                scope: oidcScope,
                state: oidcState,
                label: oidcLabel,
              }
            : undefined
        }
        // Hosted Multica gates sign-in behind Agentic360 IAM only. Falls back to
        // the full form if OIDC isn't configured, so a build without the env vars
        // can never lock everyone out.
        oidcOnly={oidcConfigured}
        cliCallback={
          cliCallbackRaw && validateCliCallback(cliCallbackRaw)
            ? { url: cliCallbackRaw, state: cliState }
            : undefined
        }
        lastWorkspaceId={lastWorkspaceId}
        onTokenObtained={setLoggedInCookie}
      />
    </div>
  );
}

export default function Page() {
  return (
    <Suspense fallback={null}>
      <LoginPageContent />
    </Suspense>
  );
}
