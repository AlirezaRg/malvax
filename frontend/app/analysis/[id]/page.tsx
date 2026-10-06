import Link from "next/link";
import { api } from "@/lib/api";
import { Empty, ErrorBox, Table } from "@/components/Table";

export const dynamic = "force-dynamic";

export default async function AnalysisDetail({ params }: { params: { id: string } }) {
  try {
    const job = await api.analysis(params.id);
    let findings: Awaited<ReturnType<typeof api.findings>> | null = null;
    if (job.state === "COMPLETED") {
      findings = await api.findings(job.id);
    }
    return (
      <div className="space-y-6">
        <h1 className="text-lg text-zinc-100">Analysis {job.id}</h1>
        <p>
          State: <span className="text-zinc-100">{job.state}</span> · Sample:{" "}
          <Link className="text-sky-400 hover:underline" href={`/samples/${job.sample_id}`}>
            {job.sample_id.slice(0, 8)}
          </Link>
        </p>
        <p className="text-amber-400 text-xs">
          Static analysis only. Dynamic (sandbox) results are not connected yet.
        </p>
        {findings === null ? (
          <Empty text="Findings appear when the analysis is COMPLETED." />
        ) : (
          <>
            <section className="space-y-2">
              <h2 className="text-zinc-300">Risk contributions</h2>
              {findings.risk_contributions.length === 0 ? (
                <Empty text="No risk contributions were recorded for this sample." />
              ) : (
                <Table headers={["Points", "Reason", "Evidence"]}>
                  {findings.risk_contributions.map((c, i) => (
                    <tr key={i}>
                      <td className="px-3 py-2">+{c.points}</td>
                      <td className="px-3 py-2">{c.reason}</td>
                      <td className="px-3 py-2 text-zinc-500">{c.evidence.join(", ") || "—"}</td>
                    </tr>
                  ))}
                </Table>
              )}
            </section>
            <section className="space-y-2">
              <h2 className="text-zinc-300">YARA matches</h2>
              {findings.yara_matches.length === 0 ? (
                <Empty text="No YARA rule matched." />
              ) : (
                <Table headers={["Rule", "Severity", "Description"]}>
                  {findings.yara_matches.map((m) => (
                    <tr key={m.rule_id}>
                      <td className="px-3 py-2">{m.rule_id}</td>
                      <td className="px-3 py-2">{m.severity}</td>
                      <td className="px-3 py-2">{m.description}</td>
                    </tr>
                  ))}
                </Table>
              )}
            </section>
            <Link
              className="text-sky-400 hover:underline"
              href={`/reports/${findings.report_id}`}
            >
              Open full report #{findings.report_id}
            </Link>
          </>
        )}
      </div>
    );
  } catch (error) {
    return <ErrorBox error={error} />;
  }
}
