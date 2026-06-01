import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";

interface ScoreTrendChartProps {
  complianceScore: number;
  securityScore: number;
}

export function ScoreTrendChart({ complianceScore, securityScore }: ScoreTrendChartProps) {
  const data = [
    { name: "T-5", compliance: Math.max(0, complianceScore - 12), security: Math.max(0, securityScore - 10) },
    { name: "T-4", compliance: Math.max(0, complianceScore - 8), security: Math.max(0, securityScore - 9) },
    { name: "T-3", compliance: Math.max(0, complianceScore - 5), security: Math.max(0, securityScore - 5) },
    { name: "T-2", compliance: Math.max(0, complianceScore - 4), security: Math.max(0, securityScore - 3) },
    { name: "T-1", compliance: Math.max(0, complianceScore - 2), security: Math.max(0, securityScore - 1) },
    { name: "Now", compliance: complianceScore, security: securityScore }
  ];

  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 10, right: 16, left: -20, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
          <XAxis dataKey="name" tickLine={false} axisLine={false} fontSize={12} />
          <YAxis domain={[0, 100]} tickLine={false} axisLine={false} fontSize={12} />
          <Tooltip
            contentStyle={{
              borderRadius: 8,
              border: "1px solid hsl(var(--border))",
              background: "hsl(var(--card))",
              color: "hsl(var(--foreground))"
            }}
          />
          <Line type="monotone" dataKey="compliance" stroke="#0f766e" strokeWidth={2} dot={false} />
          <Line type="monotone" dataKey="security" stroke="#2563eb" strokeWidth={2} dot={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

