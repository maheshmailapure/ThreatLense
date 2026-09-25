import React from 'react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  AreaChart,
  Area,
} from 'recharts';

const glassTooltipStyle = {
  backgroundColor: 'rgba(255, 255, 255, 0.92)',
  backdropFilter: 'blur(16px)',
  WebkitBackdropFilter: 'blur(16px)',
  borderColor: 'rgba(255, 255, 255, 0.9)',
  borderRadius: '14px',
  color: '#0f172a',
  boxShadow: '0 8px 30px rgba(15, 23, 42, 0.08), inset 0 1px 1px rgba(255, 255, 255, 0.9)',
  fontSize: '11px',
  fontWeight: 600,
  padding: '8px 12px',
};

export function NormalVsAttackChart({ data = [] }) {
  const COLORS = ['#10b981', '#f43f5e'];

  return (
    <div className="w-full h-60">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={55}
            outerRadius={80}
            paddingAngle={4}
            dataKey="value"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip contentStyle={glassTooltipStyle} />
          <Legend
            verticalAlign="bottom"
            height={32}
            formatter={(value) => <span className="text-xs font-medium text-slate-700">{value}</span>}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

export function AttackCategoryBarChart({ data = [] }) {
  return (
    <div className="w-full h-60">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 10, right: 10, left: -10, bottom: 20 }}>
          <XAxis dataKey="name" stroke="#94a3b8" tick={{ fill: '#475569', fontSize: 10, fontWeight: 500 }} />
          <YAxis stroke="#94a3b8" tick={{ fill: '#475569', fontSize: 10, fontWeight: 500 }} />
          <Tooltip contentStyle={glassTooltipStyle} />
          <Bar dataKey="count" fill="#6366f1" radius={[6, 6, 0, 0]} name="Count" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function TimelineAreaChart({ data = [] }) {
  return (
    <div className="w-full h-60">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
          <defs>
            <linearGradient id="colorNormal" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#10b981" stopOpacity={0.35}/>
              <stop offset="95%" stopColor="#10b981" stopOpacity={0.0}/>
            </linearGradient>
            <linearGradient id="colorAttack" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.35}/>
              <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0}/>
            </linearGradient>
          </defs>
          <XAxis dataKey="time" stroke="#94a3b8" tick={{ fill: '#475569', fontSize: 10, fontWeight: 500 }} />
          <YAxis stroke="#94a3b8" tick={{ fill: '#475569', fontSize: 10, fontWeight: 500 }} />
          <Tooltip contentStyle={glassTooltipStyle} />
          <Area type="monotone" dataKey="normal" stroke="#10b981" strokeWidth={2} fillOpacity={1} fill="url(#colorNormal)" name="Normal Traffic" />
          <Area type="monotone" dataKey="attack" stroke="#f43f5e" strokeWidth={2} fillOpacity={1} fill="url(#colorAttack)" name="Attacks" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
