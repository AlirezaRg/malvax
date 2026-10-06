import { api } from "@/lib/api";
import { ErrorBox } from "@/components/Table";

export const dynamic = "force-dynamic";

export default async function Dashboard() {
  try {
    const [health, samples, analyses] = await Promise.all([
      api.health(),
      api.samples(),
      api.analyses(),
    ]);
    const completed = analyses.filter((a) => a.state === "COMPLETED").length;
    const running = analyses.filter((a) => a.state === "QUEUED" || a.state.endsWith("ANALYSIS")).length;
    const failed = analyses.filter((a) => a.state === "FAILED").length;
    const stats: [string, string | number][] = [
      ["Total samples", samples.length],
      ["Completed analyses", completed],
      ["Queued or running", running],
      ["Failed analyses", failed],
      ["Database", health.database ? "ok" : "down"],
      ["Queue", health.queue ? "ok" : "down"],
      ["Suspicious / high-risk", "NOT YET MEASURED"],
      ["Analysis duration", "NOT YET MEASURED"],
    ];
    return (
      <div className="space-y-6">
        <h1 className="text-lg text-zinc-100">Dashboard</h1>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {stats.map(([label, value]) => (
            <div key={label} className="border border-zinc-800 p-3">
              <div className="text-zinc-500 text-xs">{label}</div>
              <div className="text-zinc-100 text-base mt-1">{value}</div>
            </div>
          ))}
        </div>
      </div>
    );
  } catch (error) {
    return <ErrorBox error={error} />;
  }
}
