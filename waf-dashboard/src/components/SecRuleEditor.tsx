import { useEffect, useRef, useCallback } from "react";
import { EditorState } from "@codemirror/state";
import { EditorView, keymap, lineNumbers, highlightActiveLine, highlightActiveLineGutter } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import { syntaxHighlighting, HighlightStyle, StreamLanguage } from "@codemirror/language";
import { autocompletion, type CompletionContext, type CompletionResult } from "@codemirror/autocomplete";
import { searchKeymap, highlightSelectionMatches } from "@codemirror/search";
import { linter, type Diagnostic } from "@codemirror/lint";
import { tags } from "@lezer/highlight";
import type { CRSAutocompleteResponse, CRSRule } from "@/lib/api";

// ─── ModSecurity Stream Language ────────────────────────────────────

// Custom StreamLanguage tokenizer for ModSecurity/SecRule directives.
const modsecLanguage = StreamLanguage.define({
  token(stream) {
    // Comments
    if (stream.match(/^#.*/)) return "lineComment";

    // Line continuation
    if (stream.match(/^\\\s*$/)) return "escape";

    // Directives (SecRule, SecAction, SecRuleRemoveById, etc.)
    if (stream.match(/^Sec(?:Rule|Action|RuleEngine|RuleRemoveById|RuleRemoveByTag|RuleUpdateTargetById|RuleUpdateTargetByTag|RequestBodyAccess|ResponseBodyAccess|ResponseBodyMimeType|ResponseBodyLimit|RequestBodyLimit|RequestBodyNoFilesLimit|DebugLog|DebugLogLevel|DataDir|TmpDir|AuditEngine|AuditLog|AuditLogParts|AuditLogType|AuditLogRelevantStatus|ArgumentSeparator|CookieFormat|UniqueId|CollectionTimeout)\b/)) {
      return "keyword";
    }

    // Operators (@rx, @streq, @pm, @ipMatch, etc.)
    if (stream.match(/@(?:rx|streq|pm|pmFromFile|beginsWith|endsWith|contains|within|ipMatch|ipMatchFromFile|gt|ge|lt|le|eq|detectSQLi|detectXSS|validateByteRange|validateUrlEncoding|validateUtf8Encoding|unconditionalMatch|noMatch)\b/)) {
      return "operatorKeyword";
    }

    // Variables (ARGS, REQUEST_URI, etc.) — must be preceded by start or certain chars
    if (stream.match(/^(?:ARGS|ARGS_COMBINED_SIZE|ARGS_GET|ARGS_GET_NAMES|ARGS_NAMES|ARGS_POST|ARGS_POST_NAMES|FILES|FILES_COMBINED_SIZE|FILES_NAMES|FILES_SIZES|GEO|MATCHED_VAR|MATCHED_VARS|MATCHED_VAR_NAME|MATCHED_VARS_NAMES|MULTIPART_FILENAME|MULTIPART_NAME|PATH_INFO|QUERY_STRING|REMOTE_ADDR|REMOTE_HOST|REMOTE_PORT|REQUEST_BASENAME|REQUEST_BODY|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|REQUEST_HEADERS|REQUEST_HEADERS_NAMES|REQUEST_LINE|REQUEST_METHOD|REQUEST_PROTOCOL|REQUEST_URI|REQUEST_URI_RAW|RESPONSE_BODY|RESPONSE_CONTENT_LENGTH|RESPONSE_CONTENT_TYPE|RESPONSE_HEADERS|RESPONSE_HEADERS_NAMES|RESPONSE_PROTOCOL|RESPONSE_STATUS|SERVER_ADDR|SERVER_NAME|SERVER_PORT|TX|UNIQUE_ID|XML)\b/)) {
      return "variableName";
    }

    // Actions — id:, phase:, pass, deny, etc.
    if (stream.match(/^(?:id:|phase:|pass|deny|drop|allow|redirect:|log|nolog|auditlog|noauditlog|msg:|severity:|tag:|rev:|ver:|maturity:|accuracy:|chain|skip:|skipAfter:|setvar:|expirevar:|capture|multiMatch|initcol:)\b/)) {
      return "function";
    }

    // Transformations (t:none, t:lowercase, etc.)
    if (stream.match(/^t:(?:none|lowercase|urlDecodeUni|htmlEntityDecode|removeWhitespace|compressWhitespace|removeNulls|replaceNulls|base64Decode|base64DecodeExt|hexDecode|jsDecode|cssDecode|utf8toUnicode|normalizePath|normalizePathWin|removeComments|replaceComments|sha1|md5|length|trim)\b/)) {
      return "typeName";
    }

    // ctl: actions
    if (stream.match(/^ctl:(?:ruleRemoveById|ruleRemoveByTag|ruleRemoveTargetById|ruleRemoveTargetByTag|ruleEngine|requestBodyAccess|responseBodyAccess|forceRequestBodyVariable)(?:=)?/)) {
      return "function";
    }

    // Quoted strings
    if (stream.match(/^"(?:[^"\\]|\\.)*"/)) return "string";
    if (stream.match(/^'(?:[^'\\]|\\.)*'/)) return "string";

    // Numbers (rule IDs, severity levels, etc.)
    if (stream.match(/^\d+/)) return "number";

    // Variable collection selectors (e.g., ARGS:username, REQUEST_HEADERS:User-Agent)
    if (stream.match(/^:/)) return "punctuation";

    // Regex patterns inside quotes are handled as strings already
    // Pipe separators in variable lists
    if (stream.match(/^\|/)) return "punctuation";

    // Exclamation for negation
    if (stream.match(/^!/)) return "operator";

    // Skip whitespace
    if (stream.eatSpace()) return null;

    // Advance past any other character
    stream.next();
    return null;
  },
});

// ─── Syntax Highlighting Theme ──────────────────────────────────────

const modsecHighlightStyle = HighlightStyle.define([
  { tag: tags.keyword, color: "#c792ea", fontWeight: "bold" },           // SecRule, SecAction — purple
  { tag: tags.operatorKeyword, color: "#f78c6c" },                       // @rx, @streq — orange
  { tag: tags.variableName, color: "#82aaff" },                          // ARGS, REQUEST_URI — blue
  { tag: tags.function(tags.name), color: "#c3e88d" },                   // id:, phase:, deny — green
  { tag: tags.typeName, color: "#ffcb6b" },                              // t:none, t:lowercase — yellow
  { tag: tags.string, color: "#c3e88d" },                                // "quoted strings" — green
  { tag: tags.number, color: "#f78c6c" },                                // 920420, 1 — orange
  { tag: tags.lineComment, color: "#546e7a", fontStyle: "italic" },      // # comments — gray italic
  { tag: tags.escape, color: "#546e7a" },                                // \ continuation
  { tag: tags.punctuation, color: "#89ddff" },                           // : | — cyan
  { tag: tags.operator, color: "#89ddff" },                              // ! — cyan
]);

// Dark editor theme matching the dashboard
const editorTheme = EditorView.theme({
  "&": {
    backgroundColor: "hsl(222 47% 8%)",
    color: "#a6accd",
    fontSize: "13px",
    borderRadius: "0.5rem",
    border: "1px solid hsl(215 20% 20%)",
  },
  ".cm-content": {
    fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
    padding: "12px 0",
  },
  "&.cm-focused": {
    outline: "1px solid hsl(180 100% 50% / 0.3)",
  },
  ".cm-gutters": {
    backgroundColor: "hsl(222 47% 6%)",
    color: "hsl(215 20% 35%)",
    border: "none",
    borderRight: "1px solid hsl(215 20% 15%)",
  },
  ".cm-activeLineGutter": {
    backgroundColor: "hsl(222 47% 12%)",
    color: "hsl(215 20% 55%)",
  },
  ".cm-activeLine": {
    backgroundColor: "hsl(222 47% 12% / 0.5)",
  },
  ".cm-selectionBackground": {
    backgroundColor: "hsl(220 50% 30% / 0.5) !important",
  },
  ".cm-cursor": {
    borderLeftColor: "hsl(180 100% 50%)",
  },
  ".cm-tooltip": {
    backgroundColor: "hsl(222 47% 10%)",
    border: "1px solid hsl(215 20% 20%)",
    color: "#a6accd",
  },
  ".cm-tooltip.cm-tooltip-autocomplete": {
    "& > ul > li": {
      padding: "2px 8px",
    },
    "& > ul > li[aria-selected]": {
      backgroundColor: "hsl(220 50% 25%)",
      color: "#fff",
    },
  },
  ".cm-diagnostic-error": {
    borderLeft: "3px solid hsl(350 100% 60%)",
    backgroundColor: "hsl(350 100% 60% / 0.1)",
    padding: "2px 8px",
  },
  ".cm-diagnostic-warning": {
    borderLeft: "3px solid hsl(40 100% 50%)",
    backgroundColor: "hsl(40 100% 50% / 0.1)",
    padding: "2px 8px",
  },
}, { dark: true });

// ─── Autocomplete ───────────────────────────────────────────────────

function buildCompletionSource(
  autocompleteData: CRSAutocompleteResponse | null,
  crsRules: CRSRule[],
) {
  return function completionSource(context: CompletionContext): CompletionResult | null {
    // Match word characters, @, :, ., and /
    const word = context.matchBefore(/[\w@:.\/]*/);
    if (!word || (word.from === word.to && !context.explicit)) return null;

    const text = word.text;
    const options: { label: string; type: string; detail?: string; info?: string }[] = [];

    if (!autocompleteData) return null;

    // If typing starts with @, suggest operators
    if (text.startsWith("@")) {
      for (const op of autocompleteData.operators) {
        options.push({
          label: op.name,
          type: "keyword",
          detail: op.label,
          info: op.description,
        });
      }
    }
    // If typing starts with t:, suggest transformations
    else if (text.startsWith("t:")) {
      for (const action of autocompleteData.actions) {
        if (action.startsWith("t:")) {
          options.push({ label: action, type: "function", detail: "transformation" });
        }
      }
    }
    // If typing starts with ctl:, suggest ctl actions
    else if (text.startsWith("ctl:")) {
      for (const action of autocompleteData.actions) {
        if (action.startsWith("ctl:")) {
          options.push({ label: action, type: "function", detail: "control action" });
        }
      }
    }
    // If context looks like it could be a variable (uppercase start or part of known vars)
    else if (/^[A-Z]/.test(text)) {
      for (const v of autocompleteData.variables) {
        options.push({ label: v, type: "variable", detail: "variable" });
      }
    }
    // Suggest directives
    else if (/^[Ss]ec/.test(text) || text === "" && context.explicit) {
      const directives = [
        "SecRule", "SecAction", "SecRuleEngine", "SecRuleRemoveById",
        "SecRuleRemoveByTag", "SecRuleUpdateTargetById", "SecRuleUpdateTargetByTag",
        "SecRequestBodyAccess", "SecResponseBodyAccess",
      ];
      for (const d of directives) {
        options.push({ label: d, type: "keyword", detail: "directive" });
      }
    }
    // If it looks like a number, could be a rule ID — suggest from CRS catalog
    else if (/^\d/.test(text) && crsRules.length > 0) {
      for (const rule of crsRules) {
        if (rule.id.startsWith(text)) {
          options.push({
            label: rule.id,
            type: "constant",
            detail: rule.category,
            info: rule.description,
          });
        }
      }
    }

    // Also suggest actions in general contexts
    if (!text.startsWith("@") && !text.startsWith("t:") && !text.startsWith("ctl:") && !/^[A-Z]/.test(text) && !/^\d/.test(text)) {
      for (const action of autocompleteData.actions) {
        if (!action.startsWith("t:") && !action.startsWith("ctl:")) {
          options.push({ label: action, type: "function", detail: "action" });
        }
      }
    }

    if (options.length === 0) return null;

    return {
      from: word.from,
      options,
      validFor: /^[\w@:.\/]*$/,
    };
  };
}

// ─── Linter ─────────────────────────────────────────────────────────

function buildLinter() {
  return linter((view) => {
    const diagnostics: Diagnostic[] = [];
    const doc = view.state.doc;

    for (let i = 1; i <= doc.lines; i++) {
      const line = doc.line(i);
      const text = line.text.trim();

      // Skip empty lines and comments
      if (!text || text.startsWith("#")) continue;

      // Skip line continuations
      if (text === "\\") continue;

      // Check that SecRule has proper structure: SecRule VARIABLE "OPERATOR" "ACTIONS"
      if (text.startsWith("SecRule ")) {
        const quoteCount = (text.match(/(?<!\\)"/g) || []).length;
        // A complete SecRule on one line needs at least 4 quotes (operator + actions)
        // But could be multi-line with \, so only warn if no continuation
        if (!text.endsWith("\\") && quoteCount > 0 && quoteCount < 4) {
          // Check if it has "chain" in it — chained rules can have fewer quotes
          if (!text.includes("chain") && quoteCount === 2) {
            diagnostics.push({
              from: line.from,
              to: line.to,
              severity: "warning",
              message: "SecRule appears incomplete — expected VARIABLE \"OPERATOR\" \"ACTIONS\" format",
            });
          }
        }
      }

      // Check SecAction has quotes
      if (text.startsWith("SecAction ") && !text.includes('"')) {
        diagnostics.push({
          from: line.from,
          to: line.to,
          severity: "error",
          message: "SecAction requires quoted action list",
        });
      }

      // Warn if id: is missing in SecRule/SecAction actions
      if ((text.startsWith("SecRule ") || text.startsWith("SecAction ")) && !text.endsWith("\\")) {
        const actionMatch = text.match(/"([^"]*)"$/);
        if (actionMatch && !actionMatch[1].includes("id:") && !text.includes("chain\"")) {
          diagnostics.push({
            from: line.from,
            to: line.to,
            severity: "warning",
            message: "Missing 'id:' — every SecRule/SecAction should have a unique rule ID",
          });
        }
      }
    }

    return diagnostics;
  });
}

// ─── Component ──────────────────────────────────────────────────────

interface SecRuleEditorProps {
  value: string;
  onChange: (value: string) => void;
  autocompleteData: CRSAutocompleteResponse | null;
  crsRules: CRSRule[];
  placeholder?: string;
  minHeight?: string;
}

export default function SecRuleEditor({
  value,
  onChange,
  autocompleteData,
  crsRules,
  placeholder,
  minHeight = "200px",
}: SecRuleEditorProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;

  // Stable completion source that reads latest data from refs
  const autocompleteDataRef = useRef(autocompleteData);
  const crsRulesRef = useRef(crsRules);
  autocompleteDataRef.current = autocompleteData;
  crsRulesRef.current = crsRules;

  const completionSource = useCallback((context: CompletionContext) => {
    const fn = buildCompletionSource(autocompleteDataRef.current, crsRulesRef.current);
    return fn(context);
  }, []);

  useEffect(() => {
    if (!containerRef.current) return;

    const state = EditorState.create({
      doc: value,
      extensions: [
        lineNumbers(),
        highlightActiveLine(),
        highlightActiveLineGutter(),
        history(),
        highlightSelectionMatches(),
        keymap.of([...defaultKeymap, ...historyKeymap, ...searchKeymap]),
        modsecLanguage,
        syntaxHighlighting(modsecHighlightStyle),
        editorTheme,
        autocompletion({
          override: [completionSource],
          activateOnTyping: true,
        }),
        buildLinter(),
        EditorView.updateListener.of((update) => {
          if (update.docChanged) {
            onChangeRef.current(update.state.doc.toString());
          }
        }),
        EditorView.contentAttributes.of({
          "aria-label": "SecRule editor",
        }),
        placeholder ? EditorView.domEventHandlers({}) : [],
      ].flat(),
    });

    const view = new EditorView({
      state,
      parent: containerRef.current,
    });

    viewRef.current = view;

    return () => {
      view.destroy();
      viewRef.current = null;
    };
    // Only create editor once on mount
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Sync external value changes (e.g., initial load, reset)
  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;
    const currentDoc = view.state.doc.toString();
    if (currentDoc !== value) {
      view.dispatch({
        changes: { from: 0, to: currentDoc.length, insert: value },
      });
    }
  }, [value]);

  return (
    <div
      ref={containerRef}
      className="overflow-hidden rounded-lg"
      style={{ minHeight }}
    />
  );
}
