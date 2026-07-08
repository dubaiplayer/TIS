// Classifier keyword visualization.
//
// We show BOTH, because they answer different questions, but INLINE HIGHLIGHTING
// is the primary/clearer view: it shows each flagged term IN CONTEXT (a weighted
// tag cloud strips the words out of the sentence, losing meaning). The tag cloud
// is a compact secondary summary. Intensity (0..1) drives highlight opacity / chip
// size. Only phishing-direction terms are highlighted; legit-pushing terms are
// listed small for transparency.

function mergeSpans(keywords) {
  // Flatten phishing-direction spans, tagging each with its keyword intensity.
  const spans = [];
  keywords
    .filter((k) => k.direction === "phishing")
    .forEach((k) => k.spans.forEach((s) => spans.push({ ...s, intensity: k.intensity })));
  spans.sort((a, b) => a.start - b.start);
  // Drop overlaps (keep the first / highest already sorted by position).
  const out = [];
  let lastEnd = -1;
  for (const s of spans) {
    if (s.start >= lastEnd) { out.push(s); lastEnd = s.end; }
  }
  return out;
}

function Highlighted({ text, keywords }) {
  if (!text) return null;
  const spans = mergeSpans(keywords);
  const parts = [];
  let cur = 0;
  spans.forEach((s, i) => {
    if (s.start > cur) parts.push(<span key={`t${i}`}>{text.slice(cur, s.start)}</span>);
    parts.push(
      <mark key={`m${i}`} className="kw-mark"
            style={{ background: `rgba(239,68,68,${0.25 + 0.55 * s.intensity})` }}
            title={`contribution intensity ${s.intensity.toFixed(2)}`}>
        {text.slice(s.start, s.end)}
      </mark>
    );
    cur = s.end;
  });
  if (cur < text.length) parts.push(<span key="tail">{text.slice(cur)}</span>);
  return <pre className="highlight-text">{parts}</pre>;
}

function Cloud({ keywords }) {
  const phishing = keywords.filter((k) => k.direction === "phishing").slice(0, 20);
  const legit = keywords.filter((k) => k.direction === "legitimate").slice(0, 6);
  return (
    <div className="cloud">
      {phishing.map((k) => (
        <span key={`p${k.term}`} className="chip chip-phish"
              style={{ fontSize: `${12 + 12 * k.intensity}px`,
                       opacity: 0.55 + 0.45 * k.intensity }}
              title={`+${k.weight.toFixed(3)} toward phishing`}>
          {k.term}
        </span>
      ))}
      {legit.map((k) => (
        <span key={`l${k.term}`} className="chip chip-legit"
              title={`${k.weight.toFixed(3)} toward legitimate`}>
          {k.term}
        </span>
      ))}
    </div>
  );
}

export default function KeywordHighlight({ report }) {
  const kws = report.classifier.keyword_attributions || [];
  if (!kws.length) {
    return (
      <div className="card">
        <h3>Classifier keywords</h3>
        <p className="muted">No classifier attributions (model unavailable or empty text).</p>
      </div>
    );
  }
  return (
    <div className="card">
      <h3>Classifier keywords <span className="muted">(coef × tf-idf, this email)</span></h3>
      <Cloud keywords={kws} />
      <div className="divider" />
      <Highlighted text={report.analyzed_text} keywords={kws} />
      {report.classifier.char_ngram_contribution != null && (
        <p className="muted small">
          Note: character n-gram patterns also contributed{" "}
          {report.classifier.char_ngram_contribution.toFixed(2)} to the logit
          (not shown as words). The keywords above explain the readable portion of
          the model's reasoning, not the whole score.
        </p>
      )}
    </div>
  );
}
