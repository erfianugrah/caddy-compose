import { countryFlag } from "@/lib/format";

/** Country code + optional flag. */
export function CountryLabel({ code }: { code: string }) {
  if (!code || code === "XX") return <span className="text-muted-foreground">Unknown</span>;
  return (
    <span className="inline-flex items-center gap-1.5">
      <span>{countryFlag(code)}</span>
      <span className="font-data text-xs">{code}</span>
    </span>
  );
}
