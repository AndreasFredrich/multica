import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// Hosted Multica sends the root straight to sign-in. Done here (edge) so it's a
// real HTTP 307 before any render — a redirect() inside the async (landing)
// layout only surfaces mid-stream as a 200. Marketing stays reachable at
// /homepage; remove this redirect to restore the landing page at /.
export function proxy(request: NextRequest) {
  return NextResponse.redirect(new URL("/login", request.url));
}

export const config = {
  matcher: ["/"],
};
