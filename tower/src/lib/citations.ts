export interface Citation {
  kind: string;
  id: string;
  exists: boolean;
}

/** Splits an answer into text and citation links ([agent:…], [finding:…], [run:…]). */
export function linkify(text: string, citations: Citation[]) {
  const out: (string | Citation)[] = [];
  const re = /\[(agent|finding|run):([^\]]+)\]/g;
  let last = 0;
  for (const m of text.matchAll(re)) {
    out.push(text.slice(last, m.index));
    const kind = m[1]!;
    const id = m[2]!;
    out.push({ kind, id, exists: citations.find((c) => c.kind === kind && c.id === id)?.exists ?? false });
    last = m.index! + m[0].length;
  }
  out.push(text.slice(last));
  return out;
}

