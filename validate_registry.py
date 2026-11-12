"""Run: python validate_registry.py. Verifies declarative questionnaire references and exercises two industry/AI fixtures."""
import json
from pathlib import Path
ROOT=Path(__file__).parent
manifest=json.loads((ROOT/'taad_question_control_registry_v1.0.0.json').read_text())
q={x['question_id']:x for x in manifest['question_bank']}
c={x['control_id'] for x in manifest['control_library']}
br={x['rule_id']:x for x in manifest['branch_rules']}
opts=manifest['option_sets']

def evaluate(node,answers):
    if 'eq' in node:
        x=node['eq'];return answers.get(x['question_id'])==x['value']
    if 'in' in node:
        x=node['in'];return answers.get(x['question_id']) in x['values']
    if 'all' in node:return all(evaluate(x,answers) for x in node['all'])
    if 'any' in node:return any(evaluate(x,answers) for x in node['any'])
    raise AssertionError(f'Unsupported branch operator: {node}')

def eligible(question,answers):
    b=question.get('branch_rule_id','')
    return not b or evaluate(br[b]['condition'],answers)

def visit(node):
    if 'eq' in node or 'in' in node:
        k=node.get('eq',node.get('in')); ref=k['question_id']
        assert ref in q,ref
        assert q[ref]['response_type'] in ('select_one','select_multi'),ref
        values=[k['value']] if 'value' in k else k['values']
        assert set(values).issubset(opts[q[ref]['option_set']]),(ref,values)
    else:
        assert 'all' in node or 'any' in node
        for x in node.get('all',node.get('any')):visit(x)

assert len(q)==manifest['question_count']
for x in q.values():
    assert x['control_id'] in c
    assert x['option_set'] in opts or x['option_set']==''
    assert x['branch_rule_id'] in br or x['branch_rule_id']==''
for x in br.values():visit(x['condition'])
for x in manifest['risk_rules']:
    assert set(x['question_refs'].split('|')).issubset(q)
    assert set(x['control_ids'].split('|')).issubset(c)
    visit(x['condition'])

bank={
 'Q-BASE-002':'banking','Q-BASE-005':'Agentic AI','Q-BASE-006':'Yes','Q-BASE-007':'Unknown',
 'Q-IAM-002':'Yes','Q-HIT-015':'No','Q-AIA-017':'No'
}
health={
 'Q-BASE-002':'healthcare','Q-BASE-005':'Generative AI or copilot',
 'Q-BASE-006':'No','Q-BASE-007':'No'
}
assert eligible(q['Q-BANK-001'],bank)
assert eligible(q['Q-AGT-001'],bank)
assert eligible(q['Q-REG-001'],bank)
assert not eligible(q['Q-HCR-001'],bank)
assert not eligible(q['Q-AGT-001'],health)
assert not eligible(q['Q-REG-001'],health)
assert eligible(q['Q-HCR-001'],health)
trigger_bank={x['rule_id'] for x in manifest['risk_rules'] if evaluate(x['condition'],bank)}
assert {'R-001','R-002','R-013'}.issubset(trigger_bank),trigger_bank
print('VALIDATION PASS')
print('Questions:',len(q),'Controls:',len(c),'Risks:',len(manifest['risk_rules']))
print('Bank fixture candidate risks:',','.join(sorted(trigger_bank)))
print('Healthcare no-agent branch: PASS')
