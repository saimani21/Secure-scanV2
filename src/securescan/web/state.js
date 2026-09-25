"use strict";

const state = {
  route: null,
  routeGeneration: 0,
  projectId: null,
  runId: null,
  controllers: new Set(),
  routeCleanups: new Set(),
};

function abortPendingRequests() {
  for (const controller of state.controllers) {
    controller.abort();
  }
  state.controllers.clear();
}

function runRouteCleanups() {
  for (const cleanup of state.routeCleanups) {
    cleanup();
  }
  state.routeCleanups.clear();
}

export function beginRoute(route) {
  runRouteCleanups();
  abortPendingRequests();
  state.routeGeneration += 1;
  state.route = route;
  state.projectId = route.projectId || null;
  state.runId = route.runId || null;
  return state.routeGeneration;
}

export function registerRouteCleanup(cleanup) {
  if (typeof cleanup !== "function") {
    throw new TypeError("Route cleanup must be a function.");
  }
  state.routeCleanups.add(cleanup);
  return () => state.routeCleanups.delete(cleanup);
}

export function beginRequest() {
  const generation = state.routeGeneration;
  const controller = new AbortController();
  state.controllers.add(controller);
  return {
    signal: controller.signal,
    isCurrent() {
      return generation === state.routeGeneration && !controller.signal.aborted;
    },
    finish() {
      state.controllers.delete(controller);
    },
  };
}

export function currentRoute() {
  return state.route;
}
