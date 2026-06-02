import { useState } from "react";
import { formatDistanceToNowStrict } from "date-fns";
import { Send, FileText } from "lucide-react";
import { SkeletonText } from "@/components/ui/Skeleton";
import { EmptyState } from "@/components/ui/EmptyState";
import { useAddNote } from "../../hooks/useInvestigation";
import type { InvestigationNote } from "../../types/investigation";

interface InvestigationNotesProps {
  investigationId: string;
  notes: InvestigationNote[];
  isLoading?: boolean;
}

export function InvestigationNotes({
  investigationId,
  notes,
  isLoading,
}: InvestigationNotesProps) {
  const [content, setContent] = useState("");
  const { mutate: addNote, isPending } = useAddNote(investigationId);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim()) return;
    addNote(content.trim(), {
      onSuccess: () => setContent(""),
    });
  };

  return (
    <div className="flex flex-col gap-3">
      {/* Note input */}
      <form onSubmit={handleSubmit} className="space-y-2">
        <textarea
          value={content}
          onChange={(e) => setContent(e.target.value)}
          placeholder="Add analyst note..."
          rows={3}
          className="w-full px-3 py-2 text-xs bg-bg-elevated border border-border rounded-md text-text-primary placeholder:text-text-muted resize-none focus:outline-none focus:ring-1 focus:ring-accent"
          onKeyDown={(e) => {
            if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
              e.preventDefault();
              handleSubmit(e);
            }
          }}
        />
        <button
          type="submit"
          disabled={!content.trim() || isPending}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-accent text-white rounded-md hover:bg-accent/90 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          <Send className="w-3 h-3" />
          {isPending ? "Adding..." : "Add Note (⌘+Enter)"}
        </button>
      </form>

      {/* Notes list */}
      {isLoading ? (
        <SkeletonText lines={4} />
      ) : !notes.length ? (
        <EmptyState
          icon={<FileText className="w-4 h-4" />}
          title="No notes yet"
          description="Add analyst notes to document your findings."
          className="py-4"
        />
      ) : (
        <div className="space-y-2">
          {notes.map((note) => (
            <div
              key={note.id}
              className="border border-border rounded-lg p-3 bg-bg-subtle"
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-xs font-medium text-text-primary">{note.authorName}</span>
                <span className="text-2xs text-text-muted">
                  {formatDistanceToNowStrict(new Date(note.createdAt), { addSuffix: true })}
                </span>
              </div>
              <p className="text-xs text-text-secondary leading-relaxed whitespace-pre-wrap">
                {note.content}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
