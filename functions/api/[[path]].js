import api from '../../src/index.js';

export function onRequest(context) {
  return api.fetch(context.request, context.env);
}
