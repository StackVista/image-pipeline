"""Record substantive paired/repeated output deltas without suppressing fields."""
import argparse
import collections
import copy
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--work', type=Path, required=True)
args = parser.parse_args()
work = args.work


def differences(a, b, path=''):
    if a == b:
        return []
    if type(a) != type(b):
        return [{'path': path, 'original': a, 'other': b}]
    if isinstance(a, dict):
        return [d for key in sorted(set(a) | set(b))
                for d in differences(a.get(key), b.get(key), path+'/'+key)]
    if isinstance(a, list):
        result = []
        if len(a) != len(b):
            result.append({'path': path+'/length', 'original': len(a), 'other': len(b)})
        for index, (x, y) in enumerate(zip(a, b)):
            result.extend(differences(x, y, path+'/'+str(index)))
        return result
    return [{'path': path, 'original': a, 'other': b}]


def normalized(document, variant, case):
    document = copy.deepcopy(document)
    document['descriptor'].pop('timestamp', None)
    expected = 'json='+str((work/variant/case/'grype.json').resolve())
    assert document['descriptor']['configuration']['output'] == [expected]
    document['descriptor']['configuration']['output'] = ['json=grype.json']
    return document


def keyed(document):
    result = {}
    for match in document['matches']:
        key = match['vulnerability']['id']+'|'+match['artifact']['id']
        assert key not in result, 'ambiguous match identity'
        result[key] = match
    return result


pairs = [('original-baseline-repeat', 'original', 'vulnerable', 'original', 'repeat'),
         ('candidate-baseline-repeat', 'candidate', 'vulnerable', 'candidate', 'repeat'),
         ('migration-pair', 'original', 'vulnerable', 'candidate', 'vulnerable'),
         ('migration-repeat-pair', 'original', 'repeat', 'candidate', 'repeat')]
summary = {}
for name, av, ac, bv, bc in pairs:
    a = json.loads((work/av/ac/'grype.json').read_text())
    b = json.loads((work/bv/bc/'grype.json').read_text())
    ma, mb = keyed(a), keyed(b)
    identity = lambda m: (m['artifact']['id'], m['vulnerability']['id'],
                          m['vulnerability']['severity'])
    match_deltas = differences(ma, mb, '/matches-by-cve-and-artifact')
    json_deltas = differences(normalized(a, av, ac), normalized(b, bv, bc))
    sarif = {}
    for mode in ['gate', 'inform']:
        da = json.loads((work/av/ac/(mode+'.sarif')).read_text())
        db = json.loads((work/bv/bc/(mode+'.sarif')).read_text())
        deltas = differences(da, db)
        sarif[mode] = {'equal': not deltas, 'differing_paths': len(deltas)}
        (work/(name+'-'+mode+'-sarif-deltas.json')).write_text(json.dumps(deltas, indent=2)+'\n')
    changed_fields = collections.Counter(
        field for key in set(ma) & set(mb) for field in set(ma[key]) | set(mb[key])
        if ma[key].get(field) != mb[key].get(field))
    summary[name] = {
        'match_counts': [len(ma), len(mb)],
        'cve_artifact_severity_multiset_equal': collections.Counter(map(identity, ma.values())) ==
        collections.Counter(map(identity, mb.values())),
        'changed_match_fields': dict(changed_fields),
        'keyed_match_differing_paths': len(match_deltas),
        'strict_json_equal_except_timestamp_output_path': not json_deltas,
        'sarif': sarif,
    }
    (work/(name+'-json-deltas.json')).write_text(json.dumps(json_deltas, indent=2)+'\n')
    (work/(name+'-keyed-match-deltas.json')).write_text(json.dumps(match_deltas, indent=2)+'\n')
(work/'repeat-comparison-summary.json').write_text(json.dumps(summary, indent=2)+'\n')
print(json.dumps(summary, indent=2))
