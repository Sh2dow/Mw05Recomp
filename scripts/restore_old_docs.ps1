Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$outDir = 'docs/research/old'
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }

$files = @(
  'CURRENT_STATUS.md','FINAL_STATUS_GAME_RUNNING.md','FINAL_STATUS_RENDERING_BLOCKED.md','GRAPHICS_CALLBACK_ANALYSIS.md',
  'LOGGING.md','NO_DRAWS_INVESTIGATION.md','NO_DRAWS_ROOT_CAUSE.md','RENDER_PATH_ANALYSIS.md','RENDERING_CRASH_ANALYSIS.md',
  'THREAD_CONTEXT_ALLOCATION_STATUS.md','THREAD_CONTEXT_ALLOCATION_FIXED.md','RENDERING_STATUS.md','RENDERING_PROGRESS_UPDATE.md','SUMMARY_AND_NEXT_STEPS.md','VDSWAP_INVESTIGATION.md',
  'RENDER_THREAD_ROOT_CAUSE.md','RESEARCH_FINDINGS.md','ROOT_CAUSE_ANALYSIS.md','ROOT_CAUSE_STATIC_INITIALIZERS.md','SCRIPT_CONSOLIDATION_PROPOSAL.md','SELF_DEBUGGABLE_APP_PLAN.md','SELF_DEBUGGABLE_IMPLEMENTATION.md',
  'STATUS_GAME_EXITS_CLEANLY.md','THREAD_CONTEXT_ALLOCATION_COMPLETE.md','THREAD_CRASH_DEBUG_STATUS.md','THREAD_CRASH_FINAL_STATUS.md','TOML_FIX_SUCCESS.md','analyze_xenia_comparison.md',
  'game_stuck_in_initialization.md','heap_corruption_root_cause.md','rendering_unblock_investigation.md','BLANK_SCREEN_ROOT_CAUSE.md','BREAKTHROUGH_RING_BUFFER_WORKING.md',
  'CRASH_ANALYSIS.md','CRASH_INVESTIGATION_sub_8215BA10.md','DEBUGGING_WORKFLOW.md','DIVIDE_BY_ZERO_FIX.md','ENTRY_POINT_FIX_SUCCESS.md','FILE_IO_HOOKS_REGISTERED.md',
  'FINAL_RECOMMENDATIONS.md','HEAP_CORRUPTION_ANALYSIS.md','HOW_TO_DEBUG_NO_DRAWS.md','INITIALIZATION_FIX_STATUS.md','INVESTIGATION_DRAWS.md','INVESTIGATION_RESULTS_2025_10_21.md',
  'MICROIB_FORMAT_DISCOVERY.md','DRAW_COMMANDS_FOUND.md'
)

foreach ($name in $files) {
  $title = [IO.Path]::GetFileNameWithoutExtension($name) -replace '_',' '
  $dst = Join-Path $outDir $name
  $content = @()
  $content += "# $title (Archived Placeholder)"
  $content += ""
  $content += "Original content was removed during consolidation on 2025-10-21."
  $content += "This placeholder points to the new locations:"
  $content += "- Consolidated docs: docs/research/consolidated"
  $content += "- Wiki pages: docs/wiki"
  $contentText = ($content -join "`n") + "`n"
  Set-Content -Path $dst -Value $contentText -Encoding UTF8
  Write-Host "Created: $dst"
}

# Also copy the currently restored deep dives into 'old' with real content
$restored = @(
  'DRAW_COMMANDS_FOUND.md',
  'BREAKTHROUGH_RING_BUFFER_WORKING.md',
  'ENTRY_POINT_FIX_SUCCESS.md',
  'ROOT_CAUSE_STATIC_INITIALIZERS.md',
  'MICROIB_FORMAT_DISCOVERY.md'
)
foreach ($fname in $restored) {
  $src = Join-Path 'docs/research/archive' $fname
  $dst = Join-Path $outDir $fname
  if (Test-Path $src) {
    Copy-Item -Force -Path $src -Destination $dst
    Write-Host "Copied real content for: $fname"
  }
}

