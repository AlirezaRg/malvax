import { api } from "@/lib/api";
import { ErrorBox } from "@/components/Table";

export const dynamic = "force-dynamic";

export default async function SampleDetail({ params }: { params: { id: string } }) {
  try {
    const s = await api.sample(params.id);
    const rows: [string, string | number][] = [
      ["Sample ID", s.id],
      ["Filename", s.filename],
      ["File type", s.file_type],
      ["Size", `${s.size} bytes`],
      ["SHA-256", s.sha256],
      ["SHA-1", s.sha1],
      ["MD5", s.md5],
      ["Uploaded", s.uploaded_at],
      ["Status", s.analysis_status],
    ];
    return (
      <div className="space-y-4">
        <h1 className="text-lg text-zinc-100">Sample {s.filename}</h1>
        <table className="w-full border border-zinc-800">
          <tbody className="divide-y divide-zinc-800">
            {rows.map(([k, v]) => (
              <tr key={k}>
                <th className="px-3 py-2 text-left text-zinc-500 w-40 font-normal">{k}</th>
                <td className="px-3 py-2 break-all">{v}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="text-zinc-500 text-xs">
          Analyses for this sample are listed under{" "}
          <a className="text-sky-400 hover:underline" href="/analyses">
            Analyses
          </a>
          .
        </p>
      </div>
    );
  } catch (error) {
    return <ErrorBox error={error} />;
  }
}
