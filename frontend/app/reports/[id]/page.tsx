import { api } from "@/lib/api";
import { ErrorBox } from "@/components/Table";

export const dynamic = "force-dynamic";

export default async function ReportPage({ params }: { params: { id: string } }) {
  const id = Number(params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return <ErrorBox error={new Error("report id must be a positive integer")} />;
  }
  try {
    const report = await api.report(id);
    return (
      <div className="space-y-6">
        <h1 className="text-lg text-zinc-100">Report #{id}</h1>
        <p className="text-zinc-500">
          Schema {report.schema_version} · generated {report.generated_at}
        </p>
        <section>
          <h2 className="text-zinc-300 mb-2">Risk</h2>
          {typeof report.risk === "string" ? (
            <p className="text-zinc-500">{report.risk}</p>
          ) : (
            <>
              <p className="text-zinc-100">Score {report.risk.total} / 100</p>
              <ul className="list-disc pl-6 text-zinc-300">
                {report.risk.contributions.map((c, i) => (
                  <li key={i}>
                    +{c.points} {c.reason}
                  </li>
                ))}
              </ul>
            </>
          )}
        </section>
        <section>
          <h2 className="text-zinc-300 mb-2">Sample</h2>
          <pre className="border border-zinc-800 p-3 overflow-x-auto whitespace-pre-wrap break-all">
            {JSON.stringify(report.sample, null, 2)}
          </pre>
        </section>
        <section>
          <h2 className="text-zinc-300 mb-2">Static analysis</h2>
          <pre className="border border-zinc-800 p-3 overflow-x-auto whitespace-pre-wrap break-all">
            {JSON.stringify(report.static, null, 2)}
          </pre>
        </section>
        <section>
          <h2 className="text-zinc-300 mb-2">Limitations</h2>
          <ul className="list-disc pl-6 text-zinc-400">
            {report.limitations.map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
        </section>
      </div>
    );
  } catch (error) {
    return <ErrorBox error={error} />;
  }
}
