import ScanHistoryView from "@/components/ScanHistoryView";
import { getGuardianState } from "@/lib/store";

export const dynamic = "force-dynamic";

export default function ScanHistoryPage() {
  const initialState = getGuardianState();
  return <ScanHistoryView initialState={initialState} />;
}
