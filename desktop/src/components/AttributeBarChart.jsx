// Horizontal bar chart of all 12 attribute scores (Recharts).
//
// Why horizontal bars (not a radar/spider): we compare 12 named 0..1 scores and
// want to read EXACT values and long labels ("generic_greeting", "sender_domain")
// easily. Horizontal bars give each attribute a readable row and a directly
// comparable length. A radar shows overall "shape" but makes exact values and
// 12 axis labels hard to read, and implies a cyclic relationship the attributes
// don't have. Bars win for this data.
import {
  Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";

function color(score) {
  if (score >= 0.66) return "#ef4444";
  if (score >= 0.33) return "#f59e0b";
  if (score > 0) return "#eab308";
  return "#3f4956";
}

export default function AttributeBarChart({ attributes }) {
  const data = attributes
    .map((a) => ({ name: a.name, score: Number(a.score.toFixed(3)), label: a.label }))
    .sort((x, y) => y.score - x.score);

  return (
    <div className="card">
      <h3>Attribute scores</h3>
      <ResponsiveContainer width="100%" height={Math.max(260, data.length * 26)}>
        <BarChart layout="vertical" data={data} margin={{ left: 8, right: 24 }}>
          <XAxis type="number" domain={[0, 1]} tick={{ fill: "#8b98a8", fontSize: 11 }} />
          <YAxis type="category" dataKey="name" width={120}
                 tick={{ fill: "#c3ccd8", fontSize: 11 }} />
          <Tooltip
            cursor={{ fill: "rgba(255,255,255,0.04)" }}
            contentStyle={{ background: "#1a2230", border: "1px solid #2b3648",
                            borderRadius: 8, color: "#e5e9f0" }}
            formatter={(v, _n, p) => [`${v}  (${p.payload.label})`, "score"]}
          />
          <Bar dataKey="score" radius={[0, 4, 4, 0]} isAnimationActive={false}>
            {data.map((d) => <Cell key={d.name} fill={color(d.score)} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
