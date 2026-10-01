"use strict";

import { beginRequest } from "/assets/state.js";

export function createGuidanceController({ runId, services, onChange }) {
  let disposed = false;
  let request = null;
  let scanScope = null;
  const state = {
    findingId: null,
    attempted: false,
    loading: false,
    failed: false,
    payload: null,
  };

  function stateFor(findingId) {
    return state.findingId === findingId ? state : null;
  }

  function dispose() {
    disposed = true;
    if (request) request.cancel();
    request = null;
  }

  async function select(findingId, authority) {
    if (
      disposed ||
      typeof services.getScanSummary !== "function" ||
      typeof services.getFindingGuidance !== "function" ||
      typeof findingId !== "string" ||
      !/^[0-9a-f]{64}$/.test(findingId)
    ) return;
    if (state.findingId === findingId && state.attempted) return;
    if (request) request.cancel();
    state.findingId = findingId;
    state.attempted = true;
    state.loading = true;
    state.failed = false;
    state.payload = null;
    const active = beginRequest();
    request = active;
    onChange();
    try {
      if (!scanScope) {
        const summary = await services.getScanSummary(runId, { signal: active.signal });
        if (
          !summary || summary.run_id !== runId ||
          typeof summary.project_id !== "string" ||
          typeof summary.lineage_id !== "string"
        ) throw new Error("Invalid scan scope");
        scanScope = summary;
      }
      const payload = await services.getFindingGuidance(
        scanScope.project_id, scanScope.lineage_id, runId, findingId,
        { signal: active.signal },
      );
      if (!active.isCurrent() || disposed || state.findingId !== findingId) return;
      if (
        !payload || payload.run_id !== runId ||
        payload.finding_id !== findingId || payload.authority !== authority
      ) throw new Error("Guidance does not match selected finding");
      state.payload = payload;
    } catch (_error) {
      if (active.isCurrent() && !disposed && state.findingId === findingId) {
        state.failed = true;
      }
    } finally {
      active.finish();
      if (request === active) request = null;
      if (!disposed && state.findingId === findingId) {
        state.loading = false;
        onChange();
      }
    }
  }

  return { dispose, select, stateFor };
}
