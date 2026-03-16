// ─── Inline position editor ─────────────────────────────────────────
// Click the rule's position number to edit it; blur/Enter confirms, Escape cancels.

interface InlinePositionEditorProps {
  globalIndex: number;
  totalItems: number;
  isEditing: boolean;
  isFiltered: boolean;
  onStartEdit: () => void;
  onMove: (targetPos: number) => void;
  onCancel: () => void;
}

export function InlinePositionEditor({
  globalIndex,
  totalItems,
  isEditing,
  isFiltered,
  onStartEdit,
  onMove,
  onCancel,
}: InlinePositionEditorProps) {
  if (isEditing) {
    return (
      <input
        type="number"
        min={1}
        max={totalItems}
        defaultValue={globalIndex}
        autoFocus
        className="w-[40px] bg-transparent border border-lv-cyan/50 rounded px-1 py-0 text-xs text-center text-lv-cyan outline-none"
        onBlur={(e) => {
          onCancel();
          const v = parseInt(e.target.value, 10);
          if (!isNaN(v) && v !== globalIndex) onMove(v);
        }}
        onKeyDown={(e) => {
          if (e.key === "Enter") (e.target as HTMLInputElement).blur();
          else if (e.key === "Escape") onCancel();
        }}
      />
    );
  }

  return (
    <button
      onClick={() => !isFiltered && onStartEdit()}
      className={`${isFiltered ? "cursor-default" : "cursor-pointer hover:text-lv-cyan hover:bg-lv-cyan/10 rounded px-1"} transition-colors`}
      disabled={isFiltered}
    >
      {globalIndex}
    </button>
  );
}
