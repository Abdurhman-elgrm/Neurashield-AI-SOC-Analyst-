import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
} from "recharts";
import { CHART_COLORS, CHART_TOOLTIP_STYLE, CHART_PALETTE } from "./ChartTheme";
import { Skeleton } from "@/components/ui/Skeleton";

export interface DonutSegment {
  name: string;
  value: number;
  color?: string;
}

export interface DonutChartProps {
  data: DonutSegment[];
  height?: number;
  innerRadius?: number;
  outerRadius?: number;
  isLoading?: boolean;
  showLegend?: boolean;
  centerLabel?: string;
  centerValue?: string | number;
  valueFormatter?: (value: number) => string;
}

export function DonutChart({
  data,
  height = 200,
  innerRadius = 55,
  outerRadius = 80,
  isLoading = false,
  showLegend = true,
  centerLabel,
  centerValue,
  valueFormatter,
}: DonutChartProps) {
  if (isLoading) {
    return <Skeleton className="w-full rounded-full" style={{ height }} />;
  }

  const isEmpty = data.every((d) => d.value === 0);

  const displayData = isEmpty
    ? [{ name: "Empty", value: 1, color: CHART_COLORS.border }]
    : data;

  return (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart>
        <Pie
          data={displayData}
          cx="50%"
          cy="50%"
          innerRadius={innerRadius}
          outerRadius={outerRadius}
          paddingAngle={isEmpty ? 0 : 2}
          dataKey="value"
          strokeWidth={0}
          isAnimationActive={false}
        >
          {displayData.map((entry, index) => (
            <Cell
              key={`cell-${index}`}
              fill={entry.color ?? CHART_PALETTE[index % CHART_PALETTE.length]}
            />
          ))}
        </Pie>

        {!isEmpty && (
          <Tooltip
            {...CHART_TOOLTIP_STYLE}
            formatter={valueFormatter ? (val: number) => [valueFormatter(val)] : undefined}
          />
        )}

        {showLegend && !isEmpty && (
          <Legend
            iconType="circle"
            iconSize={8}
            wrapperStyle={{ fontSize: 11, color: CHART_COLORS.muted }}
          />
        )}

        {/* Center label via SVG text — rendered using foreignObject workaround */}
        {centerValue !== undefined && (
          <text x="50%" y="50%" textAnchor="middle" dominantBaseline="middle">
            <tspan
              x="50%"
              dy="-0.3em"
              style={{ fontSize: 20, fontWeight: 700, fill: "#e2e8f0", fontFamily: "inherit" }}
            >
              {centerValue}
            </tspan>
            {centerLabel && (
              <tspan
                x="50%"
                dy="1.4em"
                style={{ fontSize: 11, fill: CHART_COLORS.muted, fontFamily: "inherit" }}
              >
                {centerLabel}
              </tspan>
            )}
          </text>
        )}
      </PieChart>
    </ResponsiveContainer>
  );
}
