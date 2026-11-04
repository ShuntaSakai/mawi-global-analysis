"""New single-run statistics bundles; exact frequencies stream directly from SQLite."""
from __future__ import annotations

import csv
import json
import os
from pathlib import Path
import tempfile

from mawi_global_analysis.hashing import sha256_file, stable_json_hash
from .analysis import HistogramSpec, _analyze_agurim_run

FREQUENCY_SCHEMA = 'normalized24-exact-frequencies-v1'
EXPORT_SCHEMA = 'normalized24-statistics-v1'
FREQUENCY_COLUMNS = ('distribution','packet_count','frequency')


def _new_output(root: Path, output: Path) -> None:
    if output.exists() or output.is_symlink():
        raise FileExistsError(f'existing output directory will not be overwritten: {output}')
    if any(output.is_relative_to(root/name) for name in ('data','results','notebooks','sources')):
        raise ValueError('statistics output must be outside input/data/results/cache directories')
    for parent in output.parents:
        if (parent/'exact_counts.sqlite').exists() or any(parent.glob('*manifest.json')):
            raise ValueError('statistics output must be outside existing run/cache directories')


def _write_frequencies(db, stream) -> int:
    writer = csv.writer(stream, lineterminator='\n')
    writer.writerow(FREQUENCY_COLUMNS)
    count = 0
    for row in db.execute('SELECT target,packets,n FROM dist ORDER BY target,packets'):
        writer.writerow(row)
        count += 1
    return count


def _publish(work: Path, output: Path) -> None:
    """Claim a new directory; summary.json is the final completion record."""
    output.mkdir()
    published = []
    try:
        for name in ('frequencies.csv','summary.json'):
            os.link(work/name,output/name)
            published.append(name)
    except BaseException:
        for name in published:
            path = output/name
            if path.exists() and path.samefile(work/name):
                path.unlink()
        try:
            output.rmdir()
        except OSError:
            pass  # Never remove a directory now containing another writer's files.
        raise


def export_raw_statistics(root: Path, dataset_id: str, run_name: str, output_dir: Path, *,
                          chunksize: int = 100_000, scratch_dir: Path | None = None,
                          spec: HistogramSpec | None = None, progress=None) -> Path:
    """Export frequencies.csv and provenance-bearing summary.json to a new directory.

    Uses the same validated analysis as the HTML/default API. Frequencies never
    enter the returned summary payload as an array. No input/run/cache is edited.
    The bundle is published only after analysis and input revalidation succeed.
    """
    root = Path(root).expanduser().resolve()
    output = Path(output_dir).expanduser()
    if output.is_symlink():
        raise FileExistsError(f'existing output symlink will not be overwritten: {output}')
    output = output.resolve()
    _new_output(root,output)
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.normalized24-statistics-',dir=output.parent) as temporary:
        work = Path(temporary)
        frequency_rows = 0
        with (work/'frequencies.csv').open('w',encoding='utf-8',newline='') as stream:
            def sink(db):
                nonlocal frequency_rows
                frequency_rows = _write_frequencies(db,stream)
            data = _analyze_agurim_run(root,dataset_id,run_name,chunksize=chunksize,
                scratch_dir=scratch_dir,spec=spec,progress=progress,frequency_sink=sink)
            stream.flush()
            os.fsync(stream.fileno())
        descriptor = {'schema_version':FREQUENCY_SCHEMA, 'path':'frequencies.csv',
            'columns':list(FREQUENCY_COLUMNS), 'row_count':frequency_rows,
            'sha256':sha256_file(work/'frequencies.csv'), 'order':['distribution','packet_count'],
            'empty_distributions':'no CSV rows; zero totals and null means in summary'}
        provenance = data['provenance']
        provenance.pop('identity_sha256')
        provenance['frequency_export'] = descriptor
        provenance['export_schema_version'] = EXPORT_SCHEMA
        provenance['implementation_sha256']['normalized24/statistics.py'] = sha256_file(Path(__file__))
        provenance['identity_sha256'] = stable_json_hash(provenance)
        data.update(status='success',export_schema_version=EXPORT_SCHEMA,
                    artifacts={'frequencies':descriptor})
        with (work/'summary.json').open('w',encoding='utf-8') as stream:
            json.dump(data,stream,ensure_ascii=False,allow_nan=False,indent=2)
            stream.write('\n');stream.flush();os.fsync(stream.fileno())
        _new_output(root,output)
        _publish(work,output)
    return output/'summary.json'
