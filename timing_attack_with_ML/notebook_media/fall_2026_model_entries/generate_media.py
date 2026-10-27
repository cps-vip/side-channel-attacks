"""Generate notebook figures from saved experiment JSONs, plus a trace replay.

These are retrospective research figures, not screenshots taken on notebook dates.
Run with Python, matplotlib and Pillow. No experiment source/data is modified.
"""
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import zipfile

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import numpy as np
from PIL import Image, ImageOps

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
BG, INK, MUTED = '#F4F7FB', '#14283F', '#586C83'
TEAL, BLUE, AMBER, RED = '#008B8B', '#5268CF', '#DA9A28', '#BA5961'
LINE, WHITE = '#DCE4EE', '#FFFFFF'
plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 11,
                     'text.color': INK, 'axes.labelcolor': MUTED,
                     'xtick.color': MUTED, 'ytick.color': INK,
                     'axes.edgecolor': LINE, 'svg.fonttype': 'none'})

PATHS = {
    'v1_manifest': ROOT / 'pswd-checker-v1/datasets/cmd-run-01/manifest.json',
    'v1_model': ROOT / 'pswd-checker-v1/models/cmd-run-01.json',
    'v1_report': ROOT / 'pswd-checker-v1/research_results/cmd-run-01/report.json',
    'v2_manifest': ROOT / 'pswd-checker-v2/datasets/v2-run-01/manifest.json',
    'v2_report': ROOT / 'pswd-checker-v2/research_results/v2-run-01/report.json',
    'v2_basic': ROOT / 'pswd-checker-v2/research_results/v2-run-01-basic18/report.json',
}
DATA = {key: json.loads(path.read_text(encoding='utf-8')) for key, path in PATHS.items()}
OUTPUTS = []


def box(fig, rect, color=WHITE, edge=LINE, radius=.018):
    x, y, w, h = rect
    patch = FancyBboxPatch((x, y), w, h, transform=fig.transFigure,
                          boxstyle=f'round,pad=0.005,rounding_size={radius}',
                          facecolor=color, edgecolor=edge, linewidth=1, zorder=-1)
    fig.add_artist(patch)


def text(fig, x, y, label, size=11, color=INK, weight='normal', **kwargs):
    return fig.text(x, y, label, fontsize=size, color=color, fontweight=weight, **kwargs)


def arrow(fig, a, b):
    fig.add_artist(FancyArrowPatch(a, b, transform=fig.transFigure, arrowstyle='-|>',
                                  mutation_scale=15, linewidth=1.4, color=MUTED))


def figure(kicker, title, subtitle, source, size=(12, 7.5)):
    fig = plt.figure(figsize=size, dpi=150, facecolor=BG)
    text(fig, .055, .952, kicker.upper(), 9, TEAL, 'bold')
    text(fig, .055, .893, title, 25, INK, 'bold')
    text(fig, .055, .850, subtitle, 10.5, MUTED)
    text(fig, .055, .032, source, 8, MUTED)
    return fig


def card(fig, x, y, w, h, label, value, detail, accent=TEAL):
    box(fig, (x, y, w, h))
    text(fig, x + .018, y + h - .043, label.upper(), 9, MUTED, 'bold')
    text(fig, x + .018, y + h - .109, value, 27, accent, 'bold')
    text(fig, x + .018, y + .024, detail, 9.5, MUTED)


def flow(fig, y, labels, details, height=.105):
    width, gap = .205, .025
    for i, (label, detail) in enumerate(zip(labels, details)):
        x = .055 + i * (width + gap)
        box(fig, (x, y, width, height))
        text(fig, x + .012, y + height - .035, label, 11.5, INK, 'bold')
        text(fig, x + .012, y + .020, detail, 9, MUTED)
        if i < len(labels) - 1:
            arrow(fig, (x + width + .002, y + height / 2),
                  (x + width + gap - .003, y + height / 2))


def clean(ax):
    ax.set_facecolor(BG)
    for spine in ('top', 'right', 'left'):
        ax.spines[spine].set_visible(False)
    ax.tick_params(axis='y', length=0)
    ax.grid(axis='x', color=LINE, linewidth=.7, zorder=0)
    ax.set_axisbelow(True)


def save(fig, stem):
    for suffix in ('.png', '.svg'):
        path = OUT / (stem + suffix)
        fig.savefig(path, dpi=150, facecolor=BG)
        OUTPUTS.append(path)
    plt.close(fig)


def entry1():
    m, c = DATA['v1_manifest'], DATA['v1_manifest']['config']
    batches = sum(p['length'] for p in m['passwords']) * c['sessions'] * len(c['alphabet']) * c['samples']
    fig = figure('V1 / Notebook entry 1', 'Collecting data without split leakage',
                 'Synthetic lowercase/digit passwords | lengths 4–16 | no artificial timing amplification',
                 'Source: v1 datasets/cmd-run-01/manifest.json. Batch totals are correlated measurements, not independent calls.')
    card(fig, .055, .600, .280, .180, 'Unique passwords', f'{len(m["passwords"]):,}', '20 synthetic passwords per length')
    card(fig, .365, .600, .280, .180, 'Timing batches', f'{batches / 1e6:.3f} million', f'{c["batch"]:,} checker calls per batch', BLUE)
    card(fig, .675, .600, .270, .180, 'Collection rounds', str(c['sessions']), f'{c["samples"]} batches / candidate / position', AMBER)
    flow(fig, .425, ['Generate secrets', 'Assign splits', 'Measure in C', 'Save results'],
         ['Known length and alphabet', 'Before timing collection', 'TSC · QPC · thread cycles', 'Raw CSV + experiment JSON'])
    text(fig, .055, .365, 'Split whole passwords, never individual timing rows', 15, INK, 'bold')
    ax = fig.add_axes([.075, .224, .85, .080])
    left = 0
    for split, label, color in [('train', 'TRAIN', TEAL), ('validation', 'VALIDATION', BLUE), ('test', 'TEST', AMBER)]:
        count = m['split_counts'][split]
        ax.barh(0, count, left=left, color=color, height=.8, edgecolor=BG, linewidth=3)
        ax.text(left + count / 2, 0, f'{label}\n{count} · {count / len(m["passwords"]):.0%}',
                ha='center', va='center', fontsize=11,
                color=WHITE if split != 'test' else INK, fontweight='bold')
        left += count
    ax.set_xlim(0, len(m['passwords']))
    ax.axis('off')
    text(fig, .075, .166, 'All positions, repeated batches and collection rounds for one password stay in one split.', 10.5, MUTED)
    text(fig, .075, .112, 'Training fits weights. Validation selects settings. Test passwords remain held out.', 10.5, MUTED)
    save(fig, '10_12_entry_1_v1_dataset')


def entry2():
    model = DATA['v1_model']
    chosen = next(e for e in model['validation_experiments'] if e['l2'] == model['l2'])
    metrics = chosen['validation']['buckets']['all']
    fig = figure('V1 / Notebook entry 2', 'Learning to rank timing candidates',
                 'A CPU-based group-softmax model | known password length and alphabet',
                 'Source: v1 models/cmd-run-01.json. Validation accuracy uses known correct prefixes; it is not password recovery.')
    card(fig, .055, .615, .280, .170, 'Timing features', str(len(model['feature_names'])), '9 timing quantiles + 9 last-position terms')
    card(fig, .365, .615, .280, .170, 'Selected regularization', str(model['l2']), 'Selected using validation data', BLUE)
    card(fig, .675, .615, .270, .170, 'Training hardware', 'CPU', 'No GPU or Colab required', AMBER)
    flow(fig, .435, ['Timing distributions', 'Percentile features', 'Candidate scores', 'Next character'],
         ['Three separately labeled metrics', 'q10 · q50 · q90 per metric', 'Shared weights across candidates', 'Extend the guessed prefix'])
    text(fig, .055, .365, 'Validation: which candidate character is correct?', 15, INK, 'bold')
    ax = fig.add_axes([.165, .165, .470, .160])
    values = [metrics['model_accuracy'] * 100, metrics['median_accuracy'] * 100]
    ax.barh([1, 0], values, color=[TEAL, BLUE], height=.5, zorder=3)
    ax.set_yticks([1, 0], ['Learned model', 'Median ranking'])
    ax.set_xlim(0, 100)
    ax.set_xlabel('Correct character decisions (%)', fontsize=10)
    for y, value in zip([1, 0], values):
        ax.text(3, y, f'{value:.1f}%', va='center', color=WHITE, weight='bold', fontsize=12)
    clean(ax)
    box(fig, (.725, .160, .220, .190))
    text(fig, .744, .309, 'EXPERIMENT BOUNDARY', 9, MUTED, 'bold')
    text(fig, .744, .264, 'Test features', 13, INK, 'bold')
    text(fig, .744, .232, 'were not read', 13, TEAL, 'bold')
    text(fig, .744, .193, 'during model selection.', 9.5, MUTED)
    save(fig, '10_12_entry_2_v1_training')


def entry3():
    r = DATA['v1_report']
    keys = ['vulnerable/model', 'vulnerable/median', 'constant/model', 'constant/median']
    metrics = [r['blind_recovery'][key] for key in keys]
    fig = figure('V1 / Notebook entry 3', 'Held-out password recovery',
                 'Fresh blind recovery | 39 unseen passwords | fixed-work checker included as a negative control',
                 'Source: v1 research_results/cmd-run-01/report.json and dataset manifest. Error bars: reported 95% Wilson intervals.')
    ax = fig.add_axes([.235, .245, .395, .495])
    labels = ['Model · vulnerable', 'Median · vulnerable', 'Model · fixed-work', 'Median · fixed-work']
    colors = [TEAL, BLUE, '#B8C4D2', '#B8C4D2']
    y = np.arange(4)[::-1]
    for position, metric, color in zip(y, metrics, colors):
        rate = metric['recovery_rate'] * 100
        lo, hi = [v * 100 for v in metric['wilson_95_interval_across_passwords']]
        ax.barh(position, rate, height=.52, color=color, zorder=3)
        ax.errorbar(rate, position, xerr=[[max(0, rate - lo)], [hi - rate]],
                    fmt='none', ecolor=INK, capsize=4, zorder=4, linewidth=1.3)
        label = f'{metric["recovered"]}/{metric["passwords"]} · {rate:.1f}%'
        ax.text(3 if rate else 12, position, label, va='center',
                color=WHITE if rate else INK, fontweight='bold', fontsize=11)
    ax.set_yticks(y, labels, fontsize=10.5)
    ax.set_xlim(0, 100)
    ax.set_xlabel('Complete passwords recovered (%)')
    clean(ax)
    secrets = {p['secret_id']: p['secret'] for p in DATA['v1_manifest']['passwords']}
    failures = [x for x in r['runs'] if x['mode'] == 'vulnerable' and x['method'] == 'model' and not x['success']]
    last = sum(x['guess'][:-1] == secrets[x['secret_id']][:-1] and
               x['guess'][-1] != secrets[x['secret_id']][-1] for x in failures)
    text(fig, .715, .730, 'Where the model failed', 13, INK, 'bold')
    card(fig, .710, .505, .235, .175, 'Final character only', f'{last} of {len(failures)}', 'Correct preceding prefix', AMBER)
    card(fig, .710, .285, .235, .175, 'Earlier prefix errors', f'{len(failures) - last} of {len(failures)}', 'Errors can propagate forward', RED)
    text(fig, .075, .142, 'Known length + alphabet. No artificial amplification. One run does not establish a general success rate.', 10.2, MUTED)
    text(fig, .075, .098, 'The learned model recovered three more passwords than median ranking in this experiment.', 10.2, INK)
    save(fig, '10_12_entry_3_v1_recovery')


def entry4():
    fig = figure('V2 / Notebook entry 1', 'A budgeted measurement and search pipeline',
                 'V1 preserved | fresh-password exclusions | 42 timing features + a separate 14-feature prefix detector',
                 'Source: v2 recovery.py, timing_model.py and research_pipeline.py. Diagram describes implemented components, not measured gains.')
    flow(fig, .655, ['Budgeted timings', 'Timing ranker', 'Prefix search', 'Acceptance checks'],
         ['Adaptive sample checkpoints', 'Model or median ranking', 'Greedy / beam + reserve', 'Final-unit verification'], height=.115)
    box(fig, (.055, .520, .895, .080), color='#E5F3F3', edge='#BEDDDD')
    text(fig, .075, .552, 'Prefix detector: prune suspect branches at partial checkpoints when enabled.', 11.5, TEAL, 'bold')
    text(fig, .055, .463, 'Five ablations isolate the effects of sampling, search, detection and verification', 12, INK, 'bold')
    ax = fig.add_axes([.170, .155, .775, .265])
    ax.axis('off')
    cells = [['Off', 'Off', 'Off', 'Off'], ['Off', 'Off', 'Off', 'On'],
             ['On', 'Off', 'Off', 'On'], ['On', 'On', 'Off', 'On'], ['On', 'On', 'On', 'On']]
    table = ax.table(cellText=cells, rowLabels=['Fixed', 'Verify', 'Adaptive', 'Beam', 'Full'],
                     colLabels=['Adaptive samples', 'Beam + reserve', 'Prefix detector', 'Final-unit search'],
                     cellLoc='center', rowLoc='center', bbox=[0, 0, 1, 1])
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    for (row, col), cell in table.get_celld().items():
        cell.set_edgecolor(LINE)
        if row == 0:
            cell.set_facecolor(INK)
            cell.get_text().set_color(WHITE)
            cell.get_text().set_weight('bold')
        elif col == -1:
            cell.set_facecolor('#E6ECF4')
            cell.get_text().set_weight('bold')
        else:
            cell.set_facecolor('#D8F0EA' if cells[row - 1][col] == 'On' else WHITE)
            cell.get_text().set_color(TEAL if cells[row - 1][col] == 'On' else MUTED)
    text(fig, .055, .097, 'Checker modes: naive · library · trie · staged SHA-256. The main v2 results use the naive checker.', 9.5, MUTED)
    save(fig, '10_19_entry_1_v2_design')


def entry5():
    r, basic = DATA['v2_report'], DATA['v2_basic']
    fig = figure('V2 / Notebook entry 2', 'Adaptive recovery helped; beam search hit its cap',
                 '39 held-out passwords | same per-password query caps | verification-assisted and timing-only results separated',
                 'Sources: v2 v2-run-01/report.json and v2-run-01-basic18/report.json. Calibration uses correct prefixes; recovery does not.',
                 size=(12, 8))
    ax = fig.add_axes([.085, .470, .855, .300])
    names, labels = ['fixed', 'verify', 'adaptive', 'beam', 'full'], ['Fixed', 'Verify', 'Adaptive', 'Beam', 'Full']
    x = np.arange(5)
    for method, shift, color, label in [('model', -.18, TEAL, 'Learned model'), ('median', .18, BLUE, 'Median ranking')]:
        rows = [r['results'][f'naive/{method}/{name}'] for name in names]
        values = [v['recovery_rate'] * 100 for v in rows]
        ax.bar(x + shift, values, width=.32, color=color, label=label, zorder=3)
        for position, value, row in zip(x + shift, values, rows):
            ax.text(position, value + 2.8, f'{row["recovered"]}/39', ha='center', va='bottom', fontsize=9.5, color=color, weight='bold')
    ax.set_ylim(0, 104)
    ax.set_xticks(x, labels)
    ax.set_ylabel('Complete recovery (%)', fontsize=10)
    ax.grid(axis='y', color=LINE, zorder=0)
    ax.set_axisbelow(True)
    ax.set_facecolor(BG)
    for spine in ('top', 'right'):
        ax.spines[spine].set_visible(False)
    ax.legend(loc='upper right', frameon=False, fontsize=9)
    text(fig, .055, .390, 'More informative features', 12, INK, 'bold')
    a = fig.add_axes([.155, .160, .200, .170])
    feature_values = [r['calibration_character_metrics']['all']['model_accuracy'] * 100,
                      basic['calibration_character_metrics']['all']['model_accuracy'] * 100]
    a.barh([1, 0], feature_values, color=[TEAL, BLUE], height=.48, zorder=3)
    a.set_yticks([1, 0], ['42 features', '18 features'], fontsize=9)
    a.set_xlim(0, 100)
    a.set_xlabel('Calibration accuracy (%)', fontsize=8.5)
    for y, value in zip([1, 0], feature_values):
        a.text(4, y, f'{value:.1f}%', va='center', color=WHITE, weight='bold', fontsize=10)
    clean(a)
    text(fig, .405, .390, 'Fewer calls per password', 12, INK, 'bold')
    a = fig.add_axes([.490, .160, .185, .170])
    values = [r['results']['naive/model/fixed']['mean_total_checker_calls'] / 1e6,
              r['results']['naive/model/adaptive']['mean_total_checker_calls'] / 1e6]
    a.barh([1, 0], values, color=[BLUE, TEAL], height=.48, zorder=3)
    a.set_yticks([1, 0], ['Fixed', 'Adaptive'], fontsize=9)
    a.set_xlim(0, 10)
    a.set_xlabel('Mean calls (millions)', fontsize=8.5)
    for y, value in zip([1, 0], values):
        a.text(.25, y, f'{value:.2f}M', va='center', color=WHITE, weight='bold', fontsize=10)
    clean(a)
    detector = r['test_prefix_detector_metrics']
    box(fig, (.730, .125, .215, .285), color='#FFF3DD', edge='#EAD4AB')
    text(fig, .746, .365, 'DETECTOR REMAINS WEAK', 8.8, INK, 'bold')
    text(fig, .746, .307, f'{detector["wrong_prefix_detection_rate"]:.1%}', 25, RED, 'bold')
    text(fig, .746, .276, 'of wrong prefixes detected', 8.8, MUTED)
    text(fig, .746, .232, f'{detector["false_rejection_rate"]:.1%} valid prefixes rejected', 9, INK)
    text(fig, .746, .187, 'Beam: 39/39 budget failures', 8.8, INK)
    text(fig, .746, .155, 'Full: 38/39 budget failures', 8.8, INK)
    reduction = 1 - values[1] / values[0]
    text(fig, .055, .079, f'Adaptive model: 32/39 (82.1%), with {reduction:.0%} fewer calls than fixed. Fixed-work controls: 0/39 in every configuration.', 9.1, MUTED)
    save(fig, '10_19_entry_2_v2_results')


def animation():
    report = DATA['v1_report']
    example = min((r for r in report['runs'] if r['mode'] == 'vulnerable' and
                   r['method'] == 'model' and r['success']), key=lambda r: (r['length'], r['secret_id']))
    alphabet = DATA['v1_manifest']['config']['alphabet']
    recovered = ''.join(alphabet[t['chosen_index']] for t in example['trace'])
    assert recovered == example['guess'] and example['success']
    frames = []
    for step in range(len(recovered) + 2):
        fig = figure('Bonus multimedia / actual saved trace', 'Replay of a recorded v1 recovery',
                     'Synthetic lab sample | known length 4 | alphabet a–z and 0–9',
                     'Source: cmd-run-01 recorded decisions. Playback speed is illustrative, not measured execution time.', size=(10, 5.625))
        shown = min(step, len(recovered))
        for i, character in enumerate(recovered):
            x = .160 + i * .177
            revealed = i < shown
            box(fig, (x, .350, .145, .220), color='#D9F0EB' if revealed else WHITE,
                edge=TEAL if revealed else LINE)
            text(fig, x + .0725, .420, character if revealed else '·', 40,
                 TEAL if revealed else '#A3B0BF', 'bold', ha='center', family='DejaVu Sans Mono')
        if step == 0:
            title, detail = 'Start with an empty prefix', 'The predictor receives timing measurements, length and alphabet.'
        elif step <= len(recovered):
            title = f'Position {step}/{len(recovered)}: chose {recovered[step - 1]!r}'
            detail = 'Prefix decisions replayed directly from the saved successful recovery trace.'
        else:
            title, detail = 'Final acceptance check: True', f'Recorded complete guess: {recovered}. This is one synthetic example, not a success-rate estimate.'
        text(fig, .5, .245, title, 19, TEAL if step > len(recovered) else INK, 'bold', ha='center')
        text(fig, .5, .165, detail, 9.5, MUTED, ha='center')
        buffer = io.BytesIO()
        fig.savefig(buffer, format='png', dpi=120, facecolor=BG)
        plt.close(fig)
        buffer.seek(0)
        frames.append(Image.open(buffer).convert('RGB'))
    path = OUT / 'bonus_v1_recorded_recovery.gif'
    frames[0].save(path, save_all=True, append_images=frames[1:],
                   duration=[1100] + [900] * len(recovered) + [1800], loop=0,
                   optimize=False, disposal=2)
    OUTPUTS.append(path)
    return example


def finish(example):
    labels = [
        ('10/12/2026 — Entry 1', '10_12_entry_1_v1_dataset', 'Collected synthetic timing data and split whole passwords before measurement.'),
        ('10/12/2026 — Entry 2', '10_12_entry_2_v1_training', 'Trained the v1 timing ranker and selected regularization using validation data.'),
        ('10/12/2026 — Entry 3', '10_12_entry_3_v1_recovery', 'Compared held-out recovery with median ranking and the fixed-work control.'),
        ('10/19/2026 — Entry 1', '10_19_entry_1_v2_design', 'Implemented v2 measurement/search components with separate ablations and query caps.'),
        ('10/19/2026 — Entry 2', '10_19_entry_2_v2_results', 'Compared v2 recovery, query costs, feature sets and prefix-detector limitations.'),
    ]
    readme = ['# Figures for the five notebook entries', '',
              'These are retrospective graphics generated from saved experiment results and source code, not screenshots captured during the notebook weeks. Week headings match the requested notebook organization; original measurement timestamps remain in the source manifests.', '',
              'PNG files are ready to upload. SVG files are editable. Drag each PNG into the GitHub notebook editor to obtain a hosted image URL, or commit the media and use a path that resolves from your notebook. Local Windows paths will not display on GitHub.', '']
    for heading, stem, caption in labels:
        readme += [f'## {heading}', '', f'![{caption}]({stem}.png)', '', caption, '']
    readme += ['## Optional animation for v1 Entry 3', '',
               '![Replay of a saved v1 recovery](bonus_v1_recorded_recovery.gif)', '',
               f'The animation replays the actual recorded decisions for the successful synthetic guess `{example["guess"]}`. Its playback timing is illustrative. It does not fabricate new measurements.', '',
               '## Rebuild', '', 'Run `python generate_media.py` from this folder with matplotlib, NumPy and Pillow installed. The source JSONs must remain at their versioned project paths. No experiment files are changed.', '']
    (OUT / 'README.md').write_text('\n'.join(readme), encoding='utf-8')
    manifest = {'generated_utc': datetime.now(timezone.utc).isoformat(),
                'source_files': {k: {'path': p.relative_to(ROOT).as_posix(),
                                     'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                                 for k, p in PATHS.items()},
                'animation_secret_id': example['secret_id'], 'animation_guess': example['guess'],
                'figures': [{'entry': h, 'png': s + '.png', 'svg': s + '.svg', 'caption': c}
                            for h, s, c in labels]}
    (OUT / 'media_manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    sheet = Image.new('RGB', (1240, 1200), '#E8EDF4')
    for i, (_, stem, _) in enumerate(labels):
        with Image.open(OUT / (stem + '.png')) as im:
            thumb = ImageOps.contain(im.convert('RGB'), (600, 375))
        sheet.paste(thumb, (10 + (i % 2) * 620, 10 + (i // 2) * 395))
    sheet.save(OUT / 'contact_sheet.png')
    archive = OUT / 'notebook_media_bundle.zip'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as zip_file:
        for p in OUTPUTS + [OUT / 'README.md', OUT / 'media_manifest.json', Path(__file__)]:
            zip_file.write(p, p.name)
    print('Created five PNGs, five SVGs, a recorded-trace GIF, upload captions and ZIP bundle.')
    print(archive)


if __name__ == '__main__':
    entry1()
    entry2()
    entry3()
    entry4()
    entry5()
    finish(animation())
