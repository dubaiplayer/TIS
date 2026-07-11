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
  if (score >= 0.66) return "#ff453a";
  if (score >= 0.33) return "#ff9f0a";
  if (score > 0) return "#ffd60a";
  return "#3a3a3c";
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
          <XAxis type="number" domain={[0, 1]} tick={{ fill: "#98989d", fontSize: 11 }} />
          <YAxis type="category" dataKey="name" width={120}
                 tick={{ fill: "#c7c7cc", fontSize: 11 }} />
          <Tooltip
            cursor={{ fill: "rgba(255,255,255,0.05)" }}
            contentStyle={{ background: "#2c2c2e", border: "1px solid rgba(255,255,255,0.12)",
                            borderRadius: 10, color: "#f5f5f7" }}
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
