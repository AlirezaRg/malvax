import Link from "next/link";
import { api } from "@/lib/api";
import { Empty, ErrorBox, Table } from "@/components/Table";

export const dynamic = "force-dynamic";

export default async function Analyses() {
  try {
    const jobs = await api.analyses();
    return (
      <div className="space-y-4">
        <h1 className="text-lg text-zinc-100">Analyses</h1>
        {jobs.length === 0 ? (
          <Empty text="No analyses yet." />
        ) : (
          <Table headers={["Analysis", "Sample", "State", "Created"]}>
            {jobs.map((j) => (
              <tr key={j.id} className="hover:bg-zinc-900">
                <td className="px-3 py-2">
                  <Link href={`/analysis/${j.id}`} className="text-sky-400 hover:underline">
                    {j.id.slice(0, 8)}
                  </Link>
                </td>
                <td className="px-3 py-2 text-zinc-500">{j.sample_id.slice(0, 8)}</td>
                <td className="px-3 py-2">{j.state}</td>
                <td className="px-3 py-2 text-zinc-500">{j.created_at}</td>
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
