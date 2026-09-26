import type { LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'

interface PanelProps {
  title: string
  icon: LucideIcon
  meta?: React.ReactNode
  className?: string
  children: React.ReactNode
  labelledBy: string
}

export function Panel({ title, icon: Icon, meta, className, children, labelledBy }: PanelProps) {
  return (
    <section
      aria-labelledby={labelledBy}
      className={cn('flex flex-col rounded-xl border bg-card', className)}
    >
      <header className="flex items-center justify-between gap-3 border-b px-4 py-3">
        <h2 id={labelledBy} className="flex items-center gap-2 text-sm font-medium">
          <Icon className="size-4 text-muted-foreground" aria-hidden="true" />
          {title}
        </h2>
        {meta}
      </header>
      <div className="flex-1 p-4">{children}</div>
    </section>
  )
}

export function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <span className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
      {children}
    </span>
  )
}
