import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

const colors: Record<string, string> = {
  critical: "#dc2626",
  high: "#d97706",
  medium: "#2563eb",
  low: "#059669",
  info: "#64748b"
};

export function SeverityChart({ data }: { data: Record<string, number> }) {
  const rows = Object.entries(data).map(([name, value]) => ({
    name,
    value,
    color: colors[name.toLowerCase()] ?? "#64748b"
  }));

  if (!rows.length) {
    return <div className="flex h-64 items-center justify-center text-sm text-muted-foreground">No severity data</div>;
  }

  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie data={rows} dataKey="value" nameKey="name" innerRadius={62} outerRadius={92} paddingAngle={3}>
            {rows.map((entry) => (
              <Cell key={entry.name} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              borderRadius: 8,
              border: "1px solid hsl(var(--border))",
              background: "hsl(var(--card))",
              color: "hsl(var(--foreground))"
            }}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

