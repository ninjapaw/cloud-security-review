import type { APIRoute } from 'astro';
import sample from '../../../samples/assessment-input.json';
import { createAssessment } from '../../../src/engine.js';
import { parseInput } from '../../../src/validation.js';

export const GET: APIRoute = () => new Response(
  JSON.stringify(createAssessment(parseInput(sample), undefined, 'fictional-report-studio-demo')),
  { headers: { 'Content-Type': 'application/json; charset=utf-8' } },
);
