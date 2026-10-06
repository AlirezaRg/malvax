import Link from "next/link";
import { api } from "@/lib/api";
import { Empty, ErrorBox, Table } from "@/components/Table";

export const dynamic = "force-dynamic";

export default async function Samples() {
  try {
    const samples = await api.samples();
    return (
      <div className="space-y-4">
        <h1 className="text-lg text-zinc-100">Samples</h1>
        {samples.length === 0 ? (
          <Empty text="No samples yet. Upload one through the API." />
        ) : (
          <Table headers={["Filename", "Type", "Size", "SHA-256", "Status"]}>
            {samples.map((s) => (
              <tr key={s.id} className="hover:bg-zinc-900">
                <td className="px-3 py-2">
                  <Link href={`/samples/${s.id}`} className="text-sky-400 hover:underline">
                    {s.filename}
                  </Link>
                </td>
                <td className="px-3 py-2">{s.file_type}</td>
                <td className="px-3 py-2">{s.size} B</td>
                <td className="px-3 py-2 text-zinc-500">{s.sha256.slice(0, 16)}…</td>
                <td className="px-3 py-2">{s.analysis_status}</td>
              </tr>
            ))}
          </Table>
        )}
      </div>
    );
  } catch (error) {
    return <ErrorBox error={error} />;
  }
}
