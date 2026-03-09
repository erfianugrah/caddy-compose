import type { SummaryParams, EventsParams, EventType, FilterOp, GeneralLogsParams } from "@/lib/api";
import type { FilterField, LogFilterField, DashboardFilter } from "./types";
import { FIELD_OPERATORS, LOG_FIELD_OPERATORS, FILTER_FIELDS, LOG_FILTER_FIELDS, OP_META } from "./constants";

// ─── Pure logic functions (exported for testing) ────────────────────

/**
 * Parse filter state from URL search params.
 * Recognized params: service, client (also ip), event_type (also type),
 * method, rule_name. Each can have a companion _op param.
 */
export function parseFiltersFromURL(search: string): DashboardFilter[] {
  const params = new URLSearchParams(search);
  const filters: DashboardFilter[] = [];

  const fieldMap: { key: string; alias?: string; field: FilterField }[] = [
    { key: "service", field: "service" },
    { key: "client", alias: "ip", field: "client" },
    { key: "event_type", alias: "type", field: "event_type" },
    { key: "method", field: "method" },
    { key: "rule_name", field: "rule_name" },
    { key: "uri", alias: "path", field: "uri" },
    { key: "status_code", alias: "status", field: "status_code" },
    { key: "country", field: "country" },
    { key: "event_id", field: "event_id" },
    { key: "request_id", field: "request_id" },
    { key: "tag", field: "tag" },
  ];

  for (const { key, alias, field } of fieldMap) {
    const value = params.get(key) || (alias ? params.get(alias) : null);
    if (value) {
      const op = (params.get(`${key}_op`) || "eq") as FilterOp;
      const validOps = FIELD_OPERATORS[field];
      filters.push({
        field,
        operator: validOps.includes(op) ? op : validOps[0],
        value,
      });
    }
  }

  return filters;
}

/** Convert filter array to SummaryParams (excluding time range). */
export function filtersToSummaryParams(filters: DashboardFilter[]): Partial<SummaryParams> {
  const params: Partial<SummaryParams> = {};
  for (const f of filters) {
    switch (f.field) {
      case "service":     params.service = f.value;     params.service_op = f.operator;     break;
      case "client":      params.client = f.value;      params.client_op = f.operator;      break;
      case "event_type":  params.event_type = f.value;  params.event_type_op = f.operator;  break;
      case "method":      params.method = f.value;      params.method_op = f.operator;      break;
      case "rule_name":   params.rule_name = f.value;   params.rule_name_op = f.operator;   break;
      case "uri":         params.uri = f.value;         params.uri_op = f.operator;         break;
      case "status_code": params.status_code = f.value; params.status_code_op = f.operator; break;
      case "country":     params.country = f.value;     params.country_op = f.operator;     break;
      case "request_id":  params.request_id = f.value;  params.request_id_op = f.operator;  break;
      case "tag":         params.tag = f.value;         params.tag_op = f.operator;         break;
    }
  }
  return params;
}

/** Convert filter array to EventsParams (excluding pagination and time range). */
export function filtersToEventsParams(filters: DashboardFilter[]): Partial<EventsParams> {
  const params: Partial<EventsParams> = {};
  for (const f of filters) {
    switch (f.field) {
      case "service":     params.service = f.value;                          params.service_op = f.operator;     break;
      case "client":      params.client = f.value;                          params.client_op = f.operator;      break;
      case "event_type":  params.event_type = f.value as EventType;         params.event_type_op = f.operator;  break;
      case "method":      params.method = f.value;                          params.method_op = f.operator;      break;
      case "rule_name":   params.rule_name = f.value;                       params.rule_name_op = f.operator;   break;
      case "uri":         params.uri = f.value;                             params.uri_op = f.operator;         break;
      case "status_code": params.status_code = f.value;                     params.status_code_op = f.operator; break;
      case "country":     params.country = f.value;                         params.country_op = f.operator;     break;
      case "event_id":    params.id = f.value;                                                                  break;
      case "request_id":  params.request_id = f.value;                                                            break;
      case "tag":         params.tag = f.value;                             params.tag_op = f.operator;         break;
    }
  }
  return params;
}

/** Get a display label for a filter value. */
export function filterDisplayValue(field: FilterField, value: string): string {
  const meta = FILTER_FIELDS[field];
  if (meta.options) {
    // For "in" operator, resolve each comma-separated value
    if (value.includes(",")) {
      return value.split(",").map((v) => {
        const opt = meta.options!.find((o) => o.value === v.trim());
        return opt ? opt.label : v.trim();
      }).join(", ");
    }
    const opt = meta.options.find((o) => o.value === value);
    if (opt) return opt.label;
  }
  return value;
}

/** Get the operator chip label. */
export function operatorChip(op: FilterOp): string {
  return OP_META[op]?.chip ?? "=";
}

// ─── General Logs filter helpers ────────────────────────────────────

/** Parse log filter state from URL search params. */
export function parseLogFiltersFromURL(search: string): DashboardFilter<LogFilterField>[] {
  const params = new URLSearchParams(search);
  const filters: DashboardFilter<LogFilterField>[] = [];

  const fieldMap: { key: string; alias?: string; field: LogFilterField }[] = [
    { key: "service", field: "service" },
    { key: "method", field: "method" },
    { key: "status", field: "status" },
    { key: "client", alias: "ip", field: "client" },
    { key: "uri", field: "uri" },
    { key: "level", field: "level" },
    { key: "country", field: "country" },
    { key: "user_agent", field: "user_agent" },
    { key: "missing_header", field: "missing_header" },
  ];

  for (const { key, alias, field } of fieldMap) {
    const value = params.get(key) || (alias ? params.get(alias) : null);
    if (value) {
      const op = (params.get(`${key}_op`) || "eq") as FilterOp;
      const validOps = LOG_FIELD_OPERATORS[field];
      filters.push({
        field,
        operator: validOps.includes(op) ? op : validOps[0],
        value,
      });
    }
  }

  return filters;
}

/** Convert log filter array to GeneralLogsParams (excluding time range / pagination). */
export function filtersToGeneralLogsParams(filters: DashboardFilter<LogFilterField>[]): Partial<GeneralLogsParams> {
  const params: Partial<GeneralLogsParams> = {};
  for (const f of filters) {
    switch (f.field) {
      case "service":        params.service = f.value;        params.service_op = f.operator;     break;
      case "method":         params.method = f.value;         params.method_op = f.operator;      break;
      case "status":         params.status = f.value;         params.status_op = f.operator;      break;
      case "client":         params.client = f.value;         params.client_op = f.operator;      break;
      case "uri":            params.uri = f.value;            params.uri_op = f.operator;         break;
      case "level":          params.level = f.value;          params.level_op = f.operator;       break;
      case "country":        params.country = f.value;        params.country_op = f.operator;     break;
      case "user_agent":     params.user_agent = f.value;     params.user_agent_op = f.operator;  break;
      case "missing_header": params.missing_header = f.value;                                     break;
    }
  }
  return params;
}

/** Display label for a log filter value. */
export function logFilterDisplayValue(field: LogFilterField, value: string): string {
  const meta = LOG_FILTER_FIELDS[field];
  if (meta.options) {
    if (value.includes(",")) {
      return value.split(",").map((v) => {
        const opt = meta.options!.find((o) => o.value === v.trim());
        return opt ? opt.label : v.trim();
      }).join(", ");
    }
    const opt = meta.options.find((o) => o.value === value);
    if (opt) return opt.label;
  }
  return value;
}
