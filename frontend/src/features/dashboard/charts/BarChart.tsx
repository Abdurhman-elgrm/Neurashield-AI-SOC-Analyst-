import {
  ResponsiveContainer,
  BarChart as RechartsBar,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
} from "recharts";
import { CHART_AXIS_STYLE, CHART_COLORS, CHART_TOOLTIP_STYLE } from "./ChartTheme";
import { Skeleton } from "@/components/ui/Skeleton";

export interface BarChartProps {
  data: Record<string, unknown>[];
  xKey: string;
  yKey: string;
  color?: string | ((entry: Record<string, unknown>, index: number) => string);
  xFormatter?: (value: string) => string;
  yFormatter?: (value: number) => string;
  height?: number;
  isLoading?: boolean;
  showGrid?: boolean;
  layout?: "horizontal" | "vertical";
  barSize?: number;
}

export function BarChart({
  data,
  xKey,
  yKey,
  color = CHART_COLORS.accent,
  xFormatter,
  yFormatter,
  height = 200,
  isLoading = false,
  showGrid = true,
  layout = "horizontal",
  barSize = 12,
}: BarChartProps) {
  if (isLoading) {
    return <Skeleton className="w-full" style={{ height }} />;
  }

  const isVertical = layout === "vertical";

  return (
    <ResponsiveContainer width="100%" height={height}>
      <RechartsBar
        data={data}
        layout={layout}
        margin={{ top: 4, right: 4, left: isVertical ? -20 : -20, bottom: 0 }}
      >
        {showGrid && (
          <CartesianGrid
            strokeDasharray="3 3"
            stroke={CHART_COLORS.gridLine}
            vertical={!isVertical}
            horizontal={isVertical}
          />
        )}

        {isVertical ? (
          <>
            <XAxis
              type="number"
              tickFormatter={yFormatter}
              tick={CHART_AXIS_STYLE.tick}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              dataKey={xKey}
              type="category"
              tickFormatter={xFormatter}
              tick={{ ...CHART_AXIS_STYLE.tick, width: 80 }}
              axisLine={false}
              tickLine={false}
              width={80}
            />
          </>
        ) : (
          <>
            <XAxis
              dataKey={xKey}
              tickFormatter={xFormatter}
              tick={CHART_AXIS_STYLE.tick}
              axisLine={CHART_AXIS_STYLE.line}
              tickLine={false}
            />
            <YAxis
              tickFormatter={yFormatter}
              tick={CHART_AXIS_STYLE.tick}
              axisLine={false}
              tickLine={false}
              width={40}
            />
          </>
        )}

        <Tooltip
          {...CHART_TOOLTIP_STYLE}
          formatter={yFormatter ? (val: number) => [yFormatter(val)] : undefined}
          labelFormatter={xFormatter}
        />

        <Bar
          dataKey={yKey}
          radius={[3, 3, 0, 0]}
          maxBarSize={barSize}
          isAnimationActive={false}
        >
          {data.map((entry, index) => (
            <Cell
              key={`cell-${index}`}
              fill={typeof color === "function" ? color(entry, index) : color}
            />
          ))}
        </Bar>
      </RechartsBar>
    </ResponsiveContainer>
  );
}
