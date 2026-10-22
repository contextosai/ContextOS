import { Fragment, useState } from "react";
import { Link } from "react-router";
import { useMutation } from "@tanstack/react-query";
import { api, useMe } from "../lib/api";
import { Badge, Card, ErrorNote, PageHead } from "../components/ui";
import { errorText } from "../components/actions";
import { linkify } from "../lib/citations";

interface Answer {
  answer: string;
  citations: { kind: string; id: string; exists: boolean }[];
  steps: { tool: string; input: unknown }[];
  model: string;
  usage: { input_tokens?: number; output_tokens?: number };
}

interface Turn {
  question: string;
  answer?: Answer;
  error?: string;
}

const SUGGESTIONS = [
  "Which agents can move money, and are they all behind a human approval?",
  "What should I tell the board about our agent risk this quarter?",
  "Which production agents have never been reviewed?",
  "What changed in how we govern agents this week?",
  "Which agents are behaving unusually right now, and why might that be?",
];

function href(kind: string, id: string) {
  if (kind === "agent") return `/agents/${encodeURIComponent(id)}`;
  if (kind === "finding") return `/agents/${encodeURIComponent(id.split(":").slice(1).join(":"))}`;
  return "/activity";
}

export function Ask() {
  const me = useMe().data;
  const [question, setQuestion] = useState("");
  const [turns, setTurns] = useState<Turn[]>([]);
  const ask = useMutation({
    mutationFn: (q: string) => api<Answer>("/api/ask", { body: { question: q } }),
    onMutate: (q) => setTurns((t) => [...t, { question: q }]),
    onSuccess: (answer) => setTurns((t) => t.map((x, i) => (i === t.length - 1 ? { ...x, answer } : x))),
    onError: (e) => setTurns((t) => t.map((x, i) => (i === t.length - 1 ? { ...x, error: errorText(e)[0] } : x))),
  });
  const send = (q: string) => {
    if (!q.trim() || ask.isPending) return;
    setQuestion("");
    ask.mutate(q.trim());
  };

  return (
    <div className="stack" style={{ maxWidth: 920 }}>
      <PageHead
        title="Ask Tower"
        sub="Ask about your agents in plain language. Claude answers from Tower's read-only tools, cites the agents, findings and runs it relies on, and Tower checks every citation. It can recommend, never act."
      />
      {!me?.intelligence && <div className="banner info">Intelligence is off for this Tower. Set [intelligence] provider = "anthropic" to enable it; everything else works without it.</div>}
      {turns.length === 0 && (
        <div className="row wrap">
          {SUGGESTIONS.map((s) => (
            <button key={s} className="small" onClick={() => send(s)} disabled={!me?.intelligence}>
              {s}
            </button>
          ))}
        </div>
      )}
      {turns.map((t, i) => (
        <div key={i} className="stack tight">
          <div className="ask-q">{t.question}</div>
          {!t.answer && !t.error && <Card><span className="muted">Looking into it…</span></Card>}
          {t.error && <ErrorNote error={{ message: t.error, code: "intelligence" }} />}
          {t.answer && (
            <Card>
              <div className="prose-out">
                {linkify(t.answer.answer, t.answer.citations).map((part, j) =>
                  typeof part === "string" ? (
                    <Fragment key={j}>{part}</Fragment>
                  ) : part.exists ? (
                    <Link key={j} to={href(part.kind, part.id)} className="cite">
                      {part.id}
                    </Link>
                  ) : (
                    <span key={j} className="cite bad" title="Tower could not find this id: do not rely on it">
                      {part.id} ⚠
                    </span>
                  ),
                )}
              </div>
              <div className="row wrap small faint" style={{ marginTop: 10 }}>
                <Badge tone="primary">AI · {t.answer.model}</Badge>
                {t.answer.steps.map((s, k) => (
                  <span key={k} className="chip" title={JSON.stringify(s.input)}>
                    {s.tool}
                  </span>
                ))}
                {t.answer.citations.some((c) => !c.exists) && <Badge tone="bad">unverified citation</Badge>}
                <span className="right">{(t.answer.usage.input_tokens ?? 0) + (t.answer.usage.output_tokens ?? 0)} tokens · journalled</span>
              </div>
            </Card>
          )}
        </div>
      ))}
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          send(question);
        }}
      >
        <input className="grow" value={question} onChange={(e) => setQuestion(e.target.value)} placeholder="Ask about agents, risk, findings, changes…" disabled={!me?.intelligence} />
        <button className="primary" disabled={!me?.intelligence || ask.isPending || !question.trim()}>
          {ask.isPending ? "Thinking…" : "Ask"}
        </button>
      </form>
    </div>
  );
}
