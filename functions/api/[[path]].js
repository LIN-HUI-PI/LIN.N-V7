// NELUUN V9.5 safety branch: wrapper around existing V9 authentication.
// Do not deploy to production. Keep src/index.js unmodified.
import api from '../../src/v95_parent_api.js';
export function onRequest(context) {
  return api.fetch(context.request, context.env);
}
