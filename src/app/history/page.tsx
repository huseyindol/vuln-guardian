import ScanHistoryView from "@/components/ScanHistoryView";
import { getGuardianStateAsync } from "@/lib/store";

export const dynamic = "force-dynamic";

export default async function ScanHistoryPage() {
  const initialState = await getGuardianStateAsync();
  return <ScanHistoryView initialState={initialState} />;
}
