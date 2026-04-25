import api from './api';

/**
 * Client for the OTShield Research Studio endpoints. Wraps the
 * {@code /api/research/documents} REST surface behind a small
 * hand-rolled API: {@link listDocuments}, {@link uploadDocument},
 * {@link deleteDocument}.
 *
 * <p>Uploads have to bypass axios' default JSON content-type, which is
 * why we use {@code FormData} and let the browser set the multipart
 * boundary for us. Everything else piggybacks on the shared axios
 * instance so JWT injection and 401-refresh behave consistently with
 * the rest of the app.
 */

/**
 * Document class stamped on upload (Option C #3). Drives the tiny
 * badge inside every citation pill. Matches the Java enum one-to-one.
 */
export type ResearchSourceType =
  | 'VENDOR_MANUAL'
  | 'DATASHEET'
  | 'FORUM'
  | 'ACADEMIC'
  | 'CODE'
  | 'UNKNOWN';

/** One document row as returned by {@code GET /api/research/documents}. */
export interface ResearchDocument {
  id: string;
  fileName: string;
  sizeBytes: number;
  contentType: string | null;
  productLabel: string | null;
  pageCount: number | null;
  chunkCount: number;
  status: 'UPLOADED' | 'PROCESSING' | 'READY' | 'FAILED';
  errorMessage: string | null;
  uploadedAt: string;
  ingestedAt: string | null;
  /**
   * Document class. Backend stamps a heuristic guess on upload and
   * refines it after extract; the user can override from the Library
   * row via {@link setDocumentSourceType}.
   */
  sourceType?: ResearchSourceType | null;
}

/** Library listing, newest first. Drives the Research Studio table. */
export async function listDocuments(): Promise<ResearchDocument[]> {
  const res = await api.get<ResearchDocument[]>('/api/research/documents');
  return res.data;
}

/**
 * Upload one file. Returns the newly-created document row; status will
 * be {@code UPLOADED} initially, then flip to {@code PROCESSING} and
 * finally {@code READY} as the backend ingests it. Callers should poll
 * {@link listDocuments} every couple of seconds while any document is
 * still {@code UPLOADED} or {@code PROCESSING}.
 */
export async function uploadDocument(
  file: File,
  productLabel?: string
): Promise<ResearchDocument> {
  const form = new FormData();
  form.append('file', file);
  if (productLabel && productLabel.trim().length > 0) {
    form.append('productLabel', productLabel.trim());
  }
  const res = await api.post<ResearchDocument>(
    '/api/research/documents/upload',
    form,
    {
      headers: { 'Content-Type': 'multipart/form-data' },
      // PDFs in the 10+ MB range are routine for vendor manuals.
      maxContentLength: Infinity,
      maxBodyLength: Infinity,
    }
  );
  return res.data;
}

/** Hard-delete a document and every chunk/embedding it produced. */
export async function deleteDocument(id: string): Promise<void> {
  await api.delete(`/api/research/documents/${id}`);
}

/**
 * Re-queue processing for a document that's stuck on UPLOADED or
 * parked on FAILED. The backend flips the row back to UPLOADED and
 * submits a fresh worker job, so subsequent polls will show status
 * marching back through PROCESSING to READY.
 */
export async function reingestDocument(id: string): Promise<void> {
  await api.post(`/api/research/documents/${id}/reingest`);
}

/**
 * Wipe the in-memory vector store and rebuild it from the chunk
 * table. The UI exposes this as a "Rebuild knowledge base" button on
 * the Library tab, for the "I deleted something but RAG still cites
 * it" case. Returns the number of chunks the store holds after the
 * reconcile, so the caller can show a confirmation toast.
 */
export async function reconcileKnowledgeBase(): Promise<{ chunksInStore: number }> {
  const res = await api.post<{ reconciled: boolean; chunksInStore: number }>(
    '/api/research/documents/reconcile'
  );
  return { chunksInStore: res.data.chunksInStore };
}

/**
 * Manual override for a document's source-type class. Useful when the
 * classifier mistakes a datasheet for a manual (or, more commonly,
 * stamps UNKNOWN on an unusually-named file). Returns the updated row
 * so the Library table can swap the badge without a refetch.
 */
export async function setDocumentSourceType(
  id: string,
  sourceType: ResearchSourceType
): Promise<ResearchDocument> {
  const res = await api.patch<ResearchDocument>(
    `/api/research/documents/${id}/source-type`,
    { sourceType }
  );
  return res.data;
}

/**
 * Shape of the operator diagnostics blob. Matches
 * {@code ResearchDiagnosticsController} on the backend; fields are
 * permissive because the endpoint is meant to be human-readable first.
 */
export interface ResearchDiagnostics {
  ollama: {
    baseUrl: string;
    chatModel: string;
    embeddingModel: string;
    ping: boolean;
    availableModels: string[];
    tagsError?: string;
    chatModelInstalled: boolean;
    embeddingModelInstalled: boolean;
  };
  embeddingSmokeTest: {
    ok: boolean;
    dimensions?: number;
    latencyMs?: number;
    firstThree?: number[];
    error?: string;
  };
  vectorStore: { chunks: number };
  documents: Array<{
    id: string;
    fileName: string;
    status: string;
    chunkCount: number;
    uploadedAt: string | null;
    ingestedAt: string | null;
    errorMessage: string | null;
  }>;
  verdict: string;
}

/**
 * Pull the one-shot diagnostics blob. Powers the Library tab banner so
 * operators can see in a single click why an upload isn't going READY
 * (Ollama down, model not pulled, embed call failing, worker crashed).
 */
export async function fetchDiagnostics(): Promise<ResearchDiagnostics> {
  const res = await api.get<ResearchDiagnostics>('/api/research/diagnostics');
  return res.data;
}

export default {
  listDocuments,
  uploadDocument,
  deleteDocument,
  reingestDocument,
  fetchDiagnostics,
};
