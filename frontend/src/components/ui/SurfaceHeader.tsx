import React from 'react';

import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/Badge';

interface SurfaceHeaderProps {
  eyebrow: string;
  title: string;
  description: string;
  action?: React.ReactNode;
  meta?: React.ReactNode;
  className?: string;
}

export function SurfaceHeader({
  eyebrow,
  title,
  description,
  action,
  meta,
  className,
}: SurfaceHeaderProps) {
  return (
    <div
      data-contract="Component.SurfaceHeader.v1"
      className={cn(
        'mb-8 flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between',
        className,
      )}
    >
      <div className="max-w-3xl">
        <Badge variant="info" size="sm" className="mb-3 rounded-md">
          {eyebrow}
        </Badge>
        <h1 className="text-2xl font-semibold leading-tight text-slate-950 sm:text-4xl">
          {title}
        </h1>
        <p className="mt-3 max-w-2xl text-base leading-7 text-slate-600 sm:text-lg">
          {description}
        </p>
        {meta ? <div className="mt-4">{meta}</div> : null}
      </div>
      {action ? <div className="w-full sm:w-auto">{action}</div> : null}
    </div>
  );
}
