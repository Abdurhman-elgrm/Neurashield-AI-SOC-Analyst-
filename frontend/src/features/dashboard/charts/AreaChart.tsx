import {
  ResponsiveContainer,
  AreaChart as RechartsArea,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  type TooltipProps,
} from "recharts";
import { CHART_AXIS_STYLE, CHART_COLORS, CHART_TOOLTIP_STYLE } from "./ChartTheme";
import { Skeleton } from "@/components/ui/Skeleton";

export interface AreaSeries {
  key: string;
  label: string;
  color?: string;
  fillOpacity?: number;
}

export interface AreaChartProps {
  data: Record<string, unknown>[];
  series: AreaSeries[];
  xKey: string;
  xFormatter?: (value: string) => string;
  yFormatter?: (value: number) => string;
  height?: number;
  isLoading?: boolean;
  showLegend?: boolean;
  showGrid?: boolean;
  CustomTooltip?: React.ComponentType<TooltipProps<number, string>>;
}

export function AreaChart({
  data,
  series,
  xKey,
  xFormatter,
  yFormatter,
  height = 200,
  isLoading = false,
  showLegend = false,
  showGrid = true,
  CustomTooltip,
}: AreaChartProps) {
  if (isLoading) {
    return <Skeleton className="w-full" style={{ height }} />;
  }

  return (
    <ResponsiveContainer width="100%" height={height}>
      <RechartsArea data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
        <defs>
          {series.map((s) => (
            <linearGradient key={s.key} id={`grad-${s.key}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={s.color ?? CHART_COLORS.accent} stopOpacity={0.25} />
              <stop offset="100%" stopColor={s.color ?? CHART_COLORS.accent} stopOpacity={0} />
            </linearGradient>
          ))}
        </defs>

        {showGrid && (
          <CartesianGrid strokeDasharray="3 3" stroke={CHART_COLORS.gridLine} vertical={false} />
        )}

        <XAxis
          dataKey={xKey}
          tickFormatter={xFormatter}
          tick={CHART_AXIS_STYLE.tick}
          axisLine={CHART_AXIS_STYLE.line}
          tickLine={false}
          interval="preserveStartEnd"
        />
        <YAxis
          tickFormatter={yFormatter}
          tick={CHART_AXIS_STYLE.tick}
          axisLine={false}
          tickLine={false}
          width={40}
        />

        <Tooltip
          {...CHART_TOOLTIP_STYLE}
          content={CustomTooltip ? <CustomTooltip /> : undefined}
          formatter={yFormatter ? (val: number) => [yFormatter(val)] : undefined}
          labelFormatter={xFormatter}
        />

        {showLegend && <Legend wrapperStyle={{ fontSize: 11, color: CHART_COLORS.muted }} />}

        {series.map((s) => (
          <Area
            key={s.key}
            type="monotone"
            dataKey={s.key}
            name={s.label}
            stroke={s.color ?? CHART_COLORS.accent}
            strokeWidth={1.5}
            fill={`url(#grad-${s.key})`}
            fillOpacity={s.fillOpacity ?? 1}
            dot={false}
            activeDot={{ r: 3, strokeWidth: 0 }}
            isAnimationActive={false}
          />
        ))}
      </RechartsArea>
    </ResponsiveContainer>
  );
}
