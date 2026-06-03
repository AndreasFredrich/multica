import { redirect } from "next/navigation";

// Hosted Multica goes straight to sign-in; the marketing landing stays available
// at /homepage (and /about, /changelog) so this is fully reversible.
export default function LandingPage() {
  redirect("/login");
}
