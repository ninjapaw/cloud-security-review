import { useEffect, useMemo, useRef, useState } from 'react';
import { DOMAINS, SEVERITIES } from '../../../src/model.js';
import type { AssessmentSnapshot } from '../../../src/model.js';
import {
  buildReportView, emptyNotes, findingScopes, FINDING_STATUSES, MAX_PROFILE_BYTES,
  MAX_SNAPSHOT_BYTES, parseNotes, parseRecipe, parseReportJson, presetRecipe,
  PRESET_NAMES, REPORT_SECTIONS, renderRecipeHtml, renderRecipeMarkdown, SECTION_LABELS,
} from '../../../src/report-recipe.js';
import type { ReportNotes, ReportRecipe, ReportSection } from '../../../src/report-recipe.js';
import { AssessmentError } from '../../../src/safety.js';
import { parseSnapshot } from '../../../src/validation.js';

const domainLabels: Record<typeof DOMAINS[number], string> = {
  entra: 'Entra ID', 'workload-identities': 'Workload identities', microsoft365: 'Microsoft 365',
  'defender-xdr': 'Defender XDR', intune: 'Intune', azure: 'Azure',
  'defender-cloud': 'Defender for Cloud', 'azure-devops': 'Azure DevOps',
  github: 'GitHub', 'code-to-cloud': 'Code to cloud',
};
const statusLabels = {
  fail: 'Observed risks', 'unable-to-assess': 'Unable to assess', informational: 'Opportunities / context', pass: 'Explicit passes',
};
const presetLabels = { executive: 'Executive', technical: 'Technical', 'code-to-cloud': 'Code to cloud' };
const presetDescriptions = {
  executive: 'Priorities and commentary',
  technical: 'Findings and evidence',
  'code-to-cloud': 'Delivery and cloud trust',
};

function toggle<T>(values: T[], value: T): T[] {
  return values.includes(value) ? values.filter(item => item !== value) : [...values, value];
}

function message(error: unknown): string {
  return error instanceof AssessmentError ? error.message : 'The operation could not be completed. No new data was applied.';
}

function download(contents: string, name: string, type: string): void {
  const url = URL.createObjectURL(new Blob([contents], { type }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = name;
  document.body.append(anchor);
  try {
    anchor.click();
  } finally {
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}

export default function ReportStudio({ demoUrl }: { demoUrl: string }) {
  const [snapshot, setSnapshot] = useState<AssessmentSnapshot>();
  const [sourceName, setSourceName] = useState('');
  const [recipe, setRecipe] = useState<ReportRecipe>(() => presetRecipe('executive'));
  const [notes, setNotes] = useState<ReportNotes>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [status, setStatus] = useState('');
  const [previewReady, setPreviewReady] = useState(false);
  const sequence = useRef(0);
  const frame = useRef<HTMLIFrameElement>(null);
  const scopes = useMemo(() => snapshot ? findingScopes(snapshot) : [], [snapshot]);
  const prepared = useMemo(() => {
    if (!snapshot) return { view: undefined, error: '' };
    try {
      return { view: buildReportView(snapshot, recipe, notes), error: '' };
    } catch (failure) {
      return { view: undefined, error: message(failure) };
    }
  }, [snapshot, recipe, notes]);
  const preview = useMemo(() => prepared.view ? renderRecipeHtml(prepared.view) : '', [prepared.view]);
  useEffect(() => { setPreviewReady(false); }, [preview]);

  function acceptSnapshot(value: unknown, name: string): void {
    const parsed = parseSnapshot(value);
    setSnapshot(parsed);
    setNotes(emptyNotes(parsed.assessmentId));
    setSourceName(name);
    setStatus(`Opened ${name}. ${parsed.findings.length} source findings. No file was uploaded.`);
  }

  async function importFile(file: File | undefined, kind: 'snapshot' | 'recipe' | 'notes'): Promise<void> {
    if (!file) return;
    const current = ++sequence.current;
    setBusy(true);
    setError('');
    setStatus('');
    if (kind === 'snapshot') {
      setSnapshot(undefined);
      setNotes(undefined);
      setSourceName('');
    }
    try {
      const limit = kind === 'snapshot' ? MAX_SNAPSHOT_BYTES : MAX_PROFILE_BYTES;
      if (file.size > limit) throw new AssessmentError('input-limit',
        kind === 'snapshot' ? 'Snapshots are limited to 50 MiB.' : 'Recipes and notes are limited to 256 KiB.');
      const contents = await file.text();
      if (current !== sequence.current) return;
      const value = parseReportJson(contents, limit);
      if (kind === 'snapshot') acceptSnapshot(value, file.name);
      else if (kind === 'recipe') {
        setRecipe(parseRecipe(value));
        setStatus('Recipe loaded. Source findings and analyst notes were not changed.');
      } else {
        if (!snapshot) throw new AssessmentError('missing-assessment', 'Open the matching assessment before importing notes.');
        setNotes(parseNotes(value, snapshot.assessmentId));
        setStatus('Analyst notes loaded separately from the evidence.');
      }
    } catch (failure) {
      if (current === sequence.current) setError(message(failure));
    } finally {
      if (current === sequence.current) setBusy(false);
    }
  }

  async function loadDemo(): Promise<void> {
    const current = ++sequence.current;
    setBusy(true);
    setError('');
    setStatus('');
    setSnapshot(undefined);
    setNotes(undefined);
    setSourceName('');
    try {
      const response = await fetch(demoUrl, { credentials: 'omit', cache: 'no-store', redirect: 'error' });
      if (!response.ok) throw new AssessmentError('demo-unavailable', 'The fictional demo could not be loaded. You can still open a local assessment file.');
      const contents = await response.text();
      if (current === sequence.current) acceptSnapshot(parseReportJson(contents), 'Fictional demo');
    } catch (failure) {
      if (current === sequence.current) setError(message(failure));
    } finally {
      if (current === sequence.current) setBusy(false);
    }
  }

  function clear(): void {
    sequence.current++;
    setSnapshot(undefined);
    setNotes(undefined);
    setSourceName('');
    setBusy(false);
    setError('');
    setStatus('Assessment and notes cleared from the workspace. Nothing was stored.');
  }

  function changeRecipe(patch: Partial<ReportRecipe>): void {
    setRecipe(current => ({ ...current, ...patch }));
    setStatus('');
  }

  function moveSection(section: ReportSection, direction: number): void {
    const sections = [...recipe.sections];
    const position = sections.indexOf(section);
    const next = position + direction;
    if (position < 0 || next < 0 || next >= sections.length) return;
    sections.splice(position, 1);
    sections.splice(next, 0, section);
    changeRecipe({ sections });
  }

  function save(kind: 'recipe' | 'notes' | 'html' | 'markdown'): void {
    setError('');
    try {
      if (kind === 'recipe') {
        download(`${JSON.stringify(parseRecipe(recipe), null, 2)}\n`, 'report-recipe.json', 'application/json');
      } else if (kind === 'notes') {
        if (!snapshot || !notes) throw new AssessmentError('missing-assessment', 'Open an assessment before saving notes.');
        download(`${JSON.stringify(parseNotes(notes, snapshot.assessmentId), null, 2)}\n`, 'analyst-notes.json', 'application/json');
      } else {
        if (!prepared.view) throw new AssessmentError('report-not-ready', 'Resolve report validation errors before exporting.');
        download(kind === 'html' ? renderRecipeHtml(prepared.view) : renderRecipeMarkdown(prepared.view),
          `security-report.${kind === 'html' ? 'html' : 'md'}`, kind === 'html' ? 'text/html;charset=utf-8' : 'text/markdown;charset=utf-8');
      }
      setStatus(`${kind === 'recipe' ? 'Recipe' : kind === 'notes' ? 'Separate analyst notes' : 'Configured report'} download requested. Review the file before sharing.`);
    } catch (failure) {
      setError(message(failure));
    }
  }

  function print(): void {
    setError('');
    const target = frame.current?.contentWindow;
    if (!target || !previewReady) {
      setError('Wait for the report preview to finish loading before printing.');
      return;
    }
    try {
      target.focus();
      target.print();
      setStatus('Use your browser print dialog to print or Save as PDF.');
    } catch {
      setError('The browser could not open print preview. Download the HTML report, open it locally, and use Print / Save as PDF.');
    }
  }

  return <>
    <section className="source-panel" aria-labelledby="source-heading">
      <div>
        <p className="step-label">01 / SOURCE</p>
        <h2 id="source-heading">Open an assessment</h2>
        <p>Use the CLI&apos;s <code>assessment.json</code> snapshot, not raw collection input. Files stay in memory.</p>
      </div>
      <div className="source-actions">
        <label className="button primary file-button">
          Open snapshot
          <input aria-label="Open assessment snapshot" type="file" accept=".json,application/json" disabled={busy}
            onChange={event => { void importFile(event.currentTarget.files?.[0], 'snapshot'); event.currentTarget.value = ''; }} />
        </label>
        <button type="button" disabled={busy} onClick={() => { void loadDemo(); }}>Try fictional demo</button>
        <button type="button" className="quiet" disabled={!snapshot && !busy} onClick={clear}>Clear data</button>
        <a className="button quiet" href="#preview-heading">Jump to preview</a>
      </div>
      {snapshot && <div className="source-details">
        <strong>{sourceName}</strong>
        <span>Evidence as of {snapshot.collectedAt}</span>
        <span>Assessment {snapshot.assessmentId}</span>
      </div>}
    </section>

    <div className="feedback" aria-live="polite">{busy ? 'Opening and validating data locally...' : status}</div>
    {error && <div role="alert" className="error">{error}</div>}

    <div className="workspace">
      <aside className="controls" aria-label="Report configuration">
        <div className="control-heading"><p className="step-label">02 / COMPOSE</p><h2>Make it useful</h2></div>
        <fieldset className="presets">
          <legend>Start with an audience</legend>
          {PRESET_NAMES.map(preset => <button key={preset} type="button" onClick={() => {
            setRecipe(presetRecipe(preset));
            setStatus(`${presetLabels[preset]} preset applied. Source findings and notes are unchanged.`);
          }}>
            <strong>{presetLabels[preset]}</strong><span>{presetDescriptions[preset]}</span>
          </button>)}
        </fieldset>

        <label className="field">Report title
          <input value={recipe.title} maxLength={120} onChange={event => changeRecipe({ title: event.target.value })} />
        </label>

        <details open className="control-group">
          <summary>Choose the findings</summary>
          <fieldset>
            <legend>Domains</legend>
            <div className="small-actions">
              <button type="button" onClick={() => changeRecipe({ domains: [...DOMAINS] })}>All domains</button>
              <button type="button" onClick={() => changeRecipe({ domains: [] })}>Clear domains</button>
            </div>
            <div className="check-grid">{DOMAINS.map(domain => <label key={domain}>
              <input type="checkbox" checked={recipe.domains.includes(domain)}
                onChange={() => changeRecipe({ domains: toggle(recipe.domains, domain) })} />{domainLabels[domain]}
            </label>)}</div>
          </fieldset>
          <fieldset>
            <legend>Severity</legend>
            <div className="check-grid">{SEVERITIES.map(severity => <label key={severity}>
              <input type="checkbox" checked={recipe.severities.includes(severity)}
                onChange={() => changeRecipe({ severities: toggle(recipe.severities, severity) })} />{severity}
            </label>)}</div>
          </fieldset>
          <fieldset>
            <legend>Finding status</legend>
            <div className="checks">{FINDING_STATUSES.map(item => <label key={item}>
              <input type="checkbox" checked={recipe.statuses.includes(item)}
                onChange={() => changeRecipe({ statuses: toggle(recipe.statuses, item) })} />{statusLabels[item]}
            </label>)}</div>
          </fieldset>
          <div className="field">
            <label htmlFor="finding-scope">Finding scope</label>
            <select id="finding-scope" value={recipe.scope ?? ''} onChange={event => changeRecipe({ scope: event.target.value || null })}>
              <option value="">All source finding scopes</option>
              {recipe.scope && !scopes.includes(recipe.scope) && <option value={recipe.scope}>Not present: {recipe.scope}</option>}
              {scopes.map(scope => <option key={scope} value={scope}>{scope}</option>)}
            </select>
          </div>
          <label className="field">Maximum selected findings (1-500)
            <input type="number" min={1} max={500} step={1} value={recipe.findingLimit}
              onChange={event => changeRecipe({ findingLimit: Number(event.target.value) })} />
          </label>
          <p className="hint">Filters choose existing findings. They never recalculate risk scores or change collected evidence.</p>
        </details>

        <details open className="control-group">
          <summary>Choose and order sections</summary>
          <p className="locked-note">Always included: assessment identity, filter disclosures, and source coverage.</p>
          <fieldset>
            <legend className="sr-only">Optional report sections</legend>
            <div className="checks">{REPORT_SECTIONS.map(section => <label key={section}>
              <input type="checkbox" checked={recipe.sections.includes(section)}
                onChange={() => changeRecipe({ sections: toggle(recipe.sections, section) })} />{SECTION_LABELS[section]}
            </label>)}</div>
          </fieldset>
          <ol className="section-order">{recipe.sections.map((section, index) => <li key={section}>
            <span>{section === 'notes' ? 'Analyst notes' : section === 'findings' ? 'Detailed findings' : 'Recommendations'}</span>
            <button type="button" disabled={index === 0} aria-label={`Move ${section} up`} onClick={() => moveSection(section, -1)}>Up</button>
            <button type="button" disabled={index === recipe.sections.length - 1} aria-label={`Move ${section} down`} onClick={() => moveSection(section, 1)}>Down</button>
          </li>)}</ol>
          <label className="check-line">
            <input type="checkbox" checked={recipe.includeEvidence} onChange={event => changeRecipe({ includeEvidence: event.target.checked })} />
            Include evidence references and documentation links
          </label>
          <p className="hint">Excluded finding bodies and raw inventory are not embedded in exported reports. This is not automatic de-identification.</p>
        </details>

        <details className="control-group">
          <summary>Add analyst context</summary>
          <p className="hint">Plain-text commentary is separate from assessment evidence and tied to this snapshot. Clear or open a different snapshot to remove it.</p>
          <label className="field">Author (optional)
            <input disabled={!notes} maxLength={120} value={notes?.author ?? ''}
              onChange={event => { if (notes) setNotes({ ...notes, author: event.target.value }); }} />
          </label>
          <label className="field">Analyst notes
            <textarea disabled={!notes} rows={7} maxLength={10000} value={notes?.text ?? ''}
              onChange={event => { if (notes) setNotes({ ...notes, text: event.target.value }); }}
              placeholder="Explain business context or manual validation. Do not enter credentials." />
          </label>
          <div className="small-actions">
            <label className="button file-button">Load notes
              <input aria-label="Load analyst notes" type="file" accept=".json,application/json" disabled={busy || !snapshot}
                onChange={event => { void importFile(event.currentTarget.files?.[0], 'notes'); event.currentTarget.value = ''; }} />
            </label>
            <button type="button" disabled={!notes} onClick={() => save('notes')}>Save notes</button>
          </div>
        </details>

        <div className="recipe-actions">
          <label className="button file-button">Load recipe
            <input aria-label="Load report recipe" type="file" accept=".json,application/json" disabled={busy}
              onChange={event => { void importFile(event.currentTarget.files?.[0], 'recipe'); event.currentTarget.value = ''; }} />
          </label>
          <button type="button" onClick={() => save('recipe')}>Save recipe</button>
          <p className="hint">Recipes contain settings, not evidence or notes. Specific scopes and notes can still be sensitive. Nothing is saved automatically.</p>
        </div>
      </aside>

      <section className="preview-panel" aria-labelledby="preview-heading">
        <div className="preview-toolbar">
          <div><p className="step-label">03 / REVIEW &amp; EXPORT</p><h2 id="preview-heading" tabIndex={-1}>Your report, live</h2></div>
          <div className="export-actions">
            <button type="button" disabled={!prepared.view || busy} onClick={() => save('markdown')}>Markdown</button>
            <button type="button" disabled={!prepared.view || busy} onClick={() => save('html')}>HTML</button>
            <button type="button" className="primary" disabled={!prepared.view || busy || !previewReady} onClick={print}>Print / Save as PDF</button>
          </div>
        </div>
        {prepared.error && <div role="alert" className="error">{prepared.error}</div>}
        {prepared.view && <div className="preview-stats" aria-live="polite">
          <span><strong>{prepared.view.shownCount}</strong> selected findings</span>
          <span><strong>{prepared.view.recommendations.length}</strong> grouped actions</span>
          <span><strong>{prepared.view.source.totals.incompleteCollections}</strong> source collection gaps retained</span>
        </div>}
        {preview ? <iframe ref={frame} title="Configured security report preview"
          sandbox="allow-same-origin allow-modals" srcDoc={preview} onLoad={() => setPreviewReady(true)} />
          : <div className="empty-state">
            <span className="empty-mark" aria-hidden="true">01 / 02 / 03</span>
            <h3>{snapshot ? 'Adjust the recipe to continue' : 'Start with evidence, not a blank page.'}</h3>
            <p>{snapshot ? 'The current configuration is invalid. The previous report is not shown as if it were current.'
              : 'Open an existing snapshot or try the fictional demo. Choose a preset, make it yours, and review the report before sharing.'}</p>
            {!snapshot && <button type="button" className="primary" disabled={busy} onClick={() => { void loadDemo(); }}>Explore the fictional demo</button>}
          </div>}
      </section>
    </div>
  </>;
}
