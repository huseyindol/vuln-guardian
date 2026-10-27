import GuardianDashboard from "@/components/GuardianDashboard";
import { getGuardianState } from "@/lib/store";

export const dynamic = "force-dynamic";

export default function HomePage() {
  const initialState = getGuardianState();
  return <GuardianDashboard initialState={initialState} />;
}
