import GuardianDashboard from "@/components/GuardianDashboard";
import { getGuardianStateAsync } from "@/lib/store";

export const dynamic = "force-dynamic";

export default async function HomePage() {
  const initialState = await getGuardianStateAsync();
  return <GuardianDashboard initialState={initialState} />;
}
