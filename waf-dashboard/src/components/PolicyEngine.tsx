import { useState, useEffect, useCallback, useMemo } from "react";
import {
  Shield,
  FileCode,
  Plus,
  Trash2,
  Pencil,
  Copy,
  Check,
  GripVertical,
  AlertTriangle,
  ToggleLeft,
  Code2,
  Wand2,
  Rocket,
  Download,
  Upload,
  X,
  Power,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  CardFooter,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  getExclusions,
  createExclusion,
  updateExclusion,
  deleteExclusion,
  generateConfig,
  fetchServices,
  exportExclusions,
  importExclusions,
  type Exclusion,
  type ExclusionType,
  type ExclusionCreateData,
  type GeneratedConfig,
  type ServiceDetail,
} from "@/lib/api";

// ─── Constants ──────────────────────────────────────────────────────

const EXCLUSION_TYPES: { value: ExclusionType; label: string; description: string }[] = [
  { value: "SecRuleRemoveById", label: "Remove entire rule", description: "SecRuleRemoveById — removes a rule globally" },
  { value: "SecRuleRemoveByTag", label: "Remove rule category", description: "SecRuleRemoveByTag — removes all rules in a tag category" },
  { value: "SecRuleUpdateTargetById", label: "Exclude variable from rule", description: "SecRuleUpdateTargetById — excludes a specific variable from a rule" },
  { value: "SecRuleUpdateTargetByTag", label: "Exclude variable from category", description: "SecRuleUpdateTargetByTag — excludes a variable from all rules in a tag" },
  { value: "ctl:ruleRemoveById", label: "Remove rule for URI", description: "Runtime ctl:ruleRemoveById — removes a rule only for matching URIs" },
  { value: "ctl:ruleRemoveByTag", label: "Remove category for URI", description: "Runtime ctl:ruleRemoveByTag — removes a tag category for matching URIs" },
  { value: "ctl:ruleRemoveTargetById", label: "Exclude variable for URI", description: "Runtime ctl:ruleRemoveTargetById — excludes a variable for matching URIs" },
];

const RULE_TAGS = [
  "attack-sqli",
  "attack-xss",
  "attack-rce",
  "attack-lfi",
  "attack-rfi",
  "attack-protocol",
  "attack-injection-php",
  "attack-injection-generic",
  "attack-reputation-ip",
  "attack-disclosure",
  "attack-fixation",
  "paranoia-level/1",
  "paranoia-level/2",
  "paranoia-level/3",
  "paranoia-level/4",
];

function isById(type: ExclusionType): boolean {
  return type.includes("ById");
}

function isByTag(type: ExclusionType): boolean {
  return type.includes("ByTag");
}

function isTargetType(type: ExclusionType): boolean {
  return type.includes("Target") || type.includes("UpdateTarget");
}

function isRuntimeType(type: ExclusionType): boolean {
  return type.startsWith("ctl:");
}

// ─── Copy Button ────────────────────────────────────────────────────

function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Button variant="ghost" size="sm" onClick={handleCopy}>
      {copied ? (
        <Check className="h-3.5 w-3.5 text-neon-green" />
      ) : (
        <Copy className="h-3.5 w-3.5" />
      )}
      <span className="text-xs">{copied ? "Copied" : label ?? "Copy"}</span>
    </Button>
  );
}

// ─── Condition Chip ─────────────────────────────────────────────────

function ConditionChip({
  label,
  value,
  onRemove,
}: {
  label: string;
  value: string;
  onRemove?: () => void;
}) {
  return (
    <div className="inline-flex items-center gap-1.5 rounded-full border border-border bg-navy-950 px-2.5 py-1 text-xs">
      <span className="text-muted-foreground">{label}:</span>
      <span className="font-medium text-neon-cyan">{value}</span>
      {onRemove && (
        <button
          onClick={onRemove}
          className="ml-0.5 rounded-full p-0.5 hover:bg-accent"
        >
          <X className="h-3 w-3 text-muted-foreground hover:text-neon-pink" />
        </button>
      )}
    </div>
  );
}

// ─── Guided Builder Form ────────────────────────────────────────────

interface BuilderFormState {
  name: string;
  description: string;
  type: ExclusionType;
  rule_id: string;
  rule_tag: string;
  variable: string;
  uri: string;
  service: string;
  enabled: boolean;
}

const emptyForm: BuilderFormState = {
  name: "",
  description: "",
  type: "SecRuleRemoveById",
  rule_id: "",
  rule_tag: "",
  variable: "",
  uri: "",
  service: "",
  enabled: true,
};

function GuidedBuilderForm({
  initial,
  services,
  onSubmit,
  onCancel,
  submitLabel,
}: {
  initial?: BuilderFormState;
  services: ServiceDetail[];
  onSubmit: (data: ExclusionCreateData) => void;
  onCancel?: () => void;
  submitLabel: string;
}) {
  const [form, setForm] = useState<BuilderFormState>(initial ?? emptyForm);

  const update = (field: keyof BuilderFormState, value: string | boolean) => {
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  const selectedType = EXCLUSION_TYPES.find((t) => t.value === form.type);
  const needsRuleId = isById(form.type);
  const needsRuleTag = isByTag(form.type);
  const needsVariable = isTargetType(form.type);
  const needsUri = isRuntimeType(form.type);

  const chips = useMemo(() => {
    const result: { label: string; value: string; field: keyof BuilderFormState }[] = [];
    if (form.type) result.push({ label: "Type", value: form.type, field: "type" });
    if (form.rule_id) result.push({ label: "Rule", value: form.rule_id, field: "rule_id" });
    if (form.rule_tag) result.push({ label: "Tag", value: form.rule_tag, field: "rule_tag" });
    if (form.variable) result.push({ label: "Variable", value: form.variable, field: "variable" });
    if (form.uri) result.push({ label: "URI", value: form.uri, field: "uri" });
    if (form.service) result.push({ label: "Service", value: form.service, field: "service" });
    return result;
  }, [form]);

  const handleSubmit = () => {
    const data: ExclusionCreateData = {
      name: form.name || `${form.type} exclusion`,
      description: form.description,
      type: form.type,
      enabled: form.enabled,
    };
    if (needsRuleId && form.rule_id) data.rule_id = form.rule_id;
    if (needsRuleTag && form.rule_tag) data.rule_tag = form.rule_tag;
    if (needsVariable && form.variable) data.variable = form.variable;
    if (needsUri && form.uri) data.uri = form.uri;
    if (form.service) data.service = form.service;
    onSubmit(data);
  };

  const isValid =
    form.name.trim() !== "" &&
    ((needsRuleId && form.rule_id.trim() !== "") ||
      (needsRuleTag && form.rule_tag.trim() !== ""));

  return (
    <div className="space-y-4">
      {/* Name & Description */}
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label className="text-xs uppercase tracking-wider text-muted-foreground">
            Name
          </Label>
          <Input
            value={form.name}
            onChange={(e) => update("name", e.target.value)}
            placeholder="e.g., Allow WordPress admin"
          />
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs uppercase tracking-wider text-muted-foreground">
            Description
          </Label>
          <Input
            value={form.description}
            onChange={(e) => update("description", e.target.value)}
            placeholder="Optional description"
          />
        </div>
      </div>

      {/* Exclusion Type */}
      <div className="space-y-1.5">
        <Label className="text-xs uppercase tracking-wider text-muted-foreground">
          Exclusion Type
        </Label>
        <Select value={form.type} onValueChange={(v) => update("type", v)}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {EXCLUSION_TYPES.map((t) => (
              <SelectItem key={t.value} value={t.value}>
                <div className="flex flex-col">
                  <span>{t.label}</span>
                  <span className="text-xs text-muted-foreground">{t.description}</span>
                </div>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Conditional fields */}
      <div className="grid gap-3 sm:grid-cols-2">
        {needsRuleId && (
          <div className="space-y-1.5">
            <Label className="text-xs uppercase tracking-wider text-muted-foreground">
              Rule ID / Range
            </Label>
            <Input
              value={form.rule_id}
              onChange={(e) => update("rule_id", e.target.value)}
              placeholder="e.g., 941100 or 941000-941999"
            />
          </div>
        )}

        {needsRuleTag && (
          <div className="space-y-1.5">
            <Label className="text-xs uppercase tracking-wider text-muted-foreground">
              Rule Tag
            </Label>
            <Select value={form.rule_tag} onValueChange={(v) => update("rule_tag", v)}>
              <SelectTrigger>
                <SelectValue placeholder="Select a tag" />
              </SelectTrigger>
              <SelectContent>
                {RULE_TAGS.map((tag) => (
                  <SelectItem key={tag} value={tag}>
                    {tag}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        )}

        {needsVariable && (
          <div className="space-y-1.5">
            <Label className="text-xs uppercase tracking-wider text-muted-foreground">
              Variable
            </Label>
            <Input
              value={form.variable}
              onChange={(e) => update("variable", e.target.value)}
              placeholder='e.g., ARGS:wp_post, REQUEST_COOKIES:/^uid_.*/'
            />
          </div>
        )}

        {needsUri && (
          <div className="space-y-1.5">
            <Label className="text-xs uppercase tracking-wider text-muted-foreground">
              URI Condition
            </Label>
            <Input
              value={form.uri}
              onChange={(e) => update("uri", e.target.value)}
              placeholder="e.g., /socket.io/, /api/v3/"
            />
          </div>
        )}
      </div>

      {/* Service filter (optional) */}
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label className="text-xs uppercase tracking-wider text-muted-foreground">
            Service (optional)
          </Label>
          <Select value={form.service} onValueChange={(v) => update("service", v)}>
            <SelectTrigger>
              <SelectValue placeholder="All services" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="">All Services</SelectItem>
              {services.map((s) => (
                <SelectItem key={s.service} value={s.service}>
                  {s.service}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="flex items-end gap-3 pb-0.5">
          <div className="flex items-center gap-2">
            <Switch
              checked={form.enabled}
              onCheckedChange={(v) => update("enabled", v)}
              id="enabled-toggle"
            />
            <Label htmlFor="enabled-toggle" className="text-sm">
              {form.enabled ? "Enabled" : "Disabled"}
            </Label>
          </div>
        </div>
      </div>

      {/* Condition chips preview */}
      {chips.length > 0 && (
        <div className="space-y-1.5">
          <Label className="text-xs uppercase tracking-wider text-muted-foreground">
            Conditions
          </Label>
          <div className="flex flex-wrap gap-2">
            {chips.map((chip) => (
              <ConditionChip
                key={chip.field}
                label={chip.label}
                value={chip.value}
                onRemove={
                  chip.field !== "type"
                    ? () => update(chip.field, "")
                    : undefined
                }
              />
            ))}
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center gap-2 pt-2">
        <Button onClick={handleSubmit} disabled={!isValid}>
          <Plus className="h-4 w-4" />
          {submitLabel}
        </Button>
        {onCancel && (
          <Button variant="outline" onClick={onCancel}>
            Cancel
          </Button>
        )}
      </div>
    </div>
  );
}

// ─── Advanced Expression Mode ───────────────────────────────────────

function AdvancedExpressionForm({
  services,
  onSubmit,
}: {
  services: ServiceDetail[];
  onSubmit: (data: ExclusionCreateData) => void;
}) {
  const [name, setName] = useState("");
  const [rawRule, setRawRule] = useState("");
  const [service, setService] = useState("");

  const handleSubmit = () => {
    if (!name.trim() || !rawRule.trim()) return;
    onSubmit({
      name,
      description: "Raw SecRule expression",
      type: "SecRuleRemoveById",
      enabled: true,
      raw_rule: rawRule,
      service: service || undefined,
    });
    setName("");
    setRawRule("");
  };

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label className="text-xs uppercase tracking-wider text-muted-foreground">
            Name
          </Label>
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Exclusion name"
          />
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs uppercase tracking-wider text-muted-foreground">
            Service (optional)
          </Label>
          <Select value={service} onValueChange={setService}>
            <SelectTrigger>
              <SelectValue placeholder="All services" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="">All Services</SelectItem>
              {services.map((s) => (
                <SelectItem key={s.service} value={s.service}>
                  {s.service}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="space-y-1.5">
        <Label className="text-xs uppercase tracking-wider text-muted-foreground">
          Raw SecRule Directive
        </Label>
        <Textarea
          value={rawRule}
          onChange={(e) => setRawRule(e.target.value)}
          placeholder={`SecRule REQUEST_URI "@streq /api/upload" \\
    "id:10001,\\
    phase:1,\\
    pass,\\
    t:none,\\
    nolog,\\
    ctl:ruleRemoveById=942100"`}
          rows={8}
          className="font-mono text-xs text-neon-green/80"
        />
      </div>

      <Button
        onClick={handleSubmit}
        disabled={!name.trim() || !rawRule.trim()}
      >
        <Plus className="h-4 w-4" />
        Add Exclusion
      </Button>
    </div>
  );
}

// ─── Config Viewer ──────────────────────────────────────────────────

function ConfigViewer({ config }: { config: GeneratedConfig }) {
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      {/* pre-crs.conf */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm">pre-crs.conf</CardTitle>
            {config.pre_crs && <CopyButton text={config.pre_crs} />}
          </div>
          <CardDescription>Loaded before CRS rules</CardDescription>
        </CardHeader>
        <Separator />
        <CardContent className="p-0">
          <div className="relative max-h-[400px] overflow-auto">
            <pre className="p-4 text-xs leading-relaxed">
              <code className="text-neon-green/80">
                {config.pre_crs || "# No pre-CRS exclusions configured"}
              </code>
            </pre>
          </div>
        </CardContent>
      </Card>

      {/* post-crs.conf */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm">post-crs.conf</CardTitle>
            {config.post_crs && <CopyButton text={config.post_crs} />}
          </div>
          <CardDescription>Loaded after CRS rules</CardDescription>
        </CardHeader>
        <Separator />
        <CardContent className="p-0">
          <div className="relative max-h-[400px] overflow-auto">
            <pre className="p-4 text-xs leading-relaxed">
              <code className="text-neon-cyan/80">
                {config.post_crs || "# No post-CRS exclusions configured"}
              </code>
            </pre>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Main Policy Engine Component ───────────────────────────────────

export default function PolicyEngine() {
  const [exclusions, setExclusions] = useState<Exclusion[]>([]);
  const [services, setServices] = useState<ServiceDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [generatedConfig, setGeneratedConfig] = useState<GeneratedConfig | null>(null);
  const [generating, setGenerating] = useState(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const loadData = useCallback(() => {
    setLoading(true);
    setError(null);
    Promise.all([getExclusions(), fetchServices()])
      .then(([excl, svcs]) => {
        setExclusions(excl);
        setServices(svcs);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const showSuccess = (msg: string) => {
    setSuccessMsg(msg);
    setTimeout(() => setSuccessMsg(null), 3000);
  };

  const handleCreate = async (data: ExclusionCreateData) => {
    try {
      const created = await createExclusion(data);
      setExclusions((prev) => [...prev, created]);
      showSuccess("Exclusion created");
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleUpdate = async (id: string, data: ExclusionCreateData) => {
    try {
      const updated = await updateExclusion(id, data);
      setExclusions((prev) => prev.map((e) => (e.id === id ? updated : e)));
      setEditingId(null);
      showSuccess("Exclusion updated");
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteExclusion(id);
      setExclusions((prev) => prev.filter((e) => e.id !== id));
      setDeleteConfirmId(null);
      showSuccess("Exclusion deleted");
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleToggleEnabled = async (id: string, enabled: boolean) => {
    try {
      const updated = await updateExclusion(id, { enabled });
      setExclusions((prev) => prev.map((e) => (e.id === id ? updated : e)));
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleGenerateConfig = async () => {
    setGenerating(true);
    try {
      const config = await generateConfig();
      setGeneratedConfig(config);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setGenerating(false);
    }
  };

  const handleExport = async () => {
    try {
      const data = await exportExclusions();
      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "waf-exclusions.json";
      a.click();
      URL.revokeObjectURL(url);
      showSuccess("Exclusions exported");
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleImport = () => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json";
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const data = JSON.parse(text);
        const result = await importExclusions(data);
        showSuccess(`Imported ${result.imported} exclusions`);
        loadData();
      } catch (err: any) {
        setError(err.message);
      }
    };
    input.click();
  };

  const exclusionToEdit = editingId
    ? exclusions.find((e) => e.id === editingId)
    : null;

  const editFormState: BuilderFormState | undefined = exclusionToEdit
    ? {
        name: exclusionToEdit.name,
        description: exclusionToEdit.description,
        type: exclusionToEdit.type,
        rule_id: exclusionToEdit.rule_id ?? "",
        rule_tag: exclusionToEdit.rule_tag ?? "",
        variable: exclusionToEdit.variable ?? "",
        uri: exclusionToEdit.uri ?? "",
        service: exclusionToEdit.service ?? "",
        enabled: exclusionToEdit.enabled,
      }
    : undefined;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-lg font-semibold">Policy Engine</h2>
          <p className="text-sm text-muted-foreground">
            Build and manage CRS rule exclusions. Create exclusions visually or write raw SecRule directives.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={handleExport}>
            <Download className="h-3.5 w-3.5" />
            Export
          </Button>
          <Button variant="outline" size="sm" onClick={handleImport}>
            <Upload className="h-3.5 w-3.5" />
            Import
          </Button>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {successMsg && (
        <Alert variant="success">
          <Check className="h-4 w-4" />
          <AlertTitle>Success</AlertTitle>
          <AlertDescription>{successMsg}</AlertDescription>
        </Alert>
      )}

      {/* Builder Section */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-neon-green" />
            <CardTitle className="text-sm">
              {editingId ? "Edit Exclusion" : "Create Exclusion"}
            </CardTitle>
          </div>
          <CardDescription>
            Use the guided builder or write raw ModSecurity directives
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="guided">
            <TabsList className="mb-4">
              <TabsTrigger value="guided" className="gap-1.5">
                <Wand2 className="h-3.5 w-3.5" />
                Guided Builder
              </TabsTrigger>
              <TabsTrigger value="advanced" className="gap-1.5">
                <Code2 className="h-3.5 w-3.5" />
                Advanced Expression
              </TabsTrigger>
            </TabsList>

            <TabsContent value="guided">
              {editingId && editFormState ? (
                <GuidedBuilderForm
                  initial={editFormState}
                  services={services}
                  onSubmit={(data) => handleUpdate(editingId, data)}
                  onCancel={() => setEditingId(null)}
                  submitLabel="Update Exclusion"
                />
              ) : (
                <GuidedBuilderForm
                  services={services}
                  onSubmit={handleCreate}
                  submitLabel="Add Exclusion"
                />
              )}
            </TabsContent>

            <TabsContent value="advanced">
              <AdvancedExpressionForm
                services={services}
                onSubmit={handleCreate}
              />
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {/* Exclusion List */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm">
                Exclusions ({exclusions.length})
              </CardTitle>
              <CardDescription>
                Manage your WAF rule exclusions
              </CardDescription>
            </div>
            <Button
              onClick={handleGenerateConfig}
              disabled={generating || exclusions.length === 0}
              size="sm"
            >
              <FileCode className="h-3.5 w-3.5" />
              {generating ? "Generating..." : "Generate Config"}
            </Button>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="space-y-2 p-6">
              {[...Array(5)].map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : exclusions.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-8" />
                  <TableHead>Name</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Rule / Tag</TableHead>
                  <TableHead>Service</TableHead>
                  <TableHead>Enabled</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {exclusions.map((excl) => (
                  <TableRow key={excl.id}>
                    <TableCell className="w-8">
                      <GripVertical className="h-4 w-4 cursor-grab text-muted-foreground/50" />
                    </TableCell>
                    <TableCell>
                      <div>
                        <p className="text-xs font-medium">{excl.name}</p>
                        {excl.description && (
                          <p className="text-xs text-muted-foreground truncate max-w-[200px]">
                            {excl.description}
                          </p>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-[10px] px-1.5 py-0 font-mono">
                        {excl.type}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs font-mono">
                      {excl.rule_id || excl.rule_tag || "-"}
                    </TableCell>
                    <TableCell className="text-xs">
                      {excl.service || (
                        <span className="text-muted-foreground">All</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={excl.enabled}
                        onCheckedChange={(v) => handleToggleEnabled(excl.id, v)}
                      />
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7"
                          onClick={() => setEditingId(excl.id)}
                        >
                          <Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-muted-foreground hover:text-neon-pink"
                          onClick={() => setDeleteConfirmId(excl.id)}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="flex flex-col items-center justify-center py-12">
              <Shield className="mb-3 h-8 w-8 text-muted-foreground/50" />
              <p className="text-sm text-muted-foreground">
                No exclusions configured yet
              </p>
              <p className="text-xs text-muted-foreground/70">
                Use the builder above to create your first exclusion
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Generated Config */}
      {generatedConfig && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold">Generated Configuration</h3>
            <Button variant="outline" size="sm" disabled>
              <Rocket className="h-3.5 w-3.5" />
              Deploy (coming soon)
            </Button>
          </div>
          <ConfigViewer config={generatedConfig} />
        </div>
      )}

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={deleteConfirmId !== null}
        onOpenChange={(open) => !open && setDeleteConfirmId(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Exclusion</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete this exclusion? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteConfirmId(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => deleteConfirmId && handleDelete(deleteConfirmId)}
            >
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
