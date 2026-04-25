import api from './api';

/**
 * Annotation client - researcher sticky notes, highlights, flags.
 * Backs the per-message note strip in ThreadsTab and (eventually) the
 * per-document pins in Library. Polymorphic target by design:
 * {@code targetKind + targetId} lets us hang a note off anything.
 */

export type AnnotationTargetKind = 'MESSAGE' | 'DOCUMENT' | 'CITATION' | 'FREEFORM';
export type AnnotationKind = 'NOTE' | 'HIGHLIGHT' | 'FLAG' | 'VERIFIED';

export interface ResearchAnnotation {
  id: string;
  bundleId: string | null;
  targetKind: AnnotationTargetKind;
  targetId: string;
  kind: AnnotationKind;
  body: string;
  tags: string | null;
  author: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CreateAnnotationRequest {
  bundleId?: string | null;
  targetKind: AnnotationTargetKind;
  targetId: string;
  kind?: AnnotationKind;
  body: string;
  tags?: string;
  author?: string;
}

export async function listAnnotationsForTarget(
  targetKind: AnnotationTargetKind,
  targetId: string
): Promise<ResearchAnnotation[]> {
  const res = await api.get<ResearchAnnotation[]>('/api/research/annotations', {
    params: { targetKind, targetId },
  });
  return res.data ?? [];
}

export async function listAnnotationsForBundle(bundleId: string): Promise<ResearchAnnotation[]> {
  const res = await api.get<ResearchAnnotation[]>('/api/research/annotations', {
    params: { bundleId },
  });
  return res.data ?? [];
}

export async function createAnnotation(req: CreateAnnotationRequest): Promise<ResearchAnnotation> {
  const res = await api.post<ResearchAnnotation>('/api/research/annotations', req);
  return res.data;
}

export async function updateAnnotation(
  id: string,
  patch: { kind?: AnnotationKind; body?: string; tags?: string }
): Promise<ResearchAnnotation> {
  const res = await api.patch<ResearchAnnotation>(`/api/research/annotations/${id}`, patch);
  return res.data;
}

export async function deleteAnnotation(id: string): Promise<void> {
  await api.delete(`/api/research/annotations/${id}`);
}

export default {
  listAnnotationsForTarget,
  listAnnotationsForBundle,
  createAnnotation,
  updateAnnotation,
  deleteAnnotation,
};
