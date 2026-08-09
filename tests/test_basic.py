"""Tests for DeFi Hunter"""
import pytest
import json
from pathlib import Path

def test_import():
    """Test package import"""
    import defihunter
    assert defihunter.__version__ == "1.3.9"

def test_config_load():
    """Test config loading"""
    from defihunter.core.config import load_config
    config = load_config()
    assert 'rpc' in config
    assert 'ethereum' in config['rpc']

def test_recon_scanner():
    """Test recon scanner"""
    from defihunter.core.recon import ReconScanner
    scanner = ReconScanner(rpc_url='http://localhost:8545')
    assert scanner.rpc_url == 'http://localhost:8545'

def test_analyzer():
    """Test analyzer"""
    from defihunter.core.analyzer import ContractAnalyzer
    analyzer = ContractAnalyzer(rpc_url='http://localhost:8545')
    assert analyzer.rpc_url == 'http://localhost:8545'

def test_templates():
    """Test templates"""
    from defihunter.templates import TEMPLATES, list_templates, get_template
    assert len(TEMPLATES) > 0

    vault_templates = list_templates('vault')
    assert len(vault_templates) > 0

    inflation = get_template('inflation_attack')
    assert inflation['severity'] == 'HIGH'


def test_template_structure():
    """Every template must have the required fields"""
    from defihunter.templates import TEMPLATES
    required = ['type', 'severity', 'title', 'description', 'contracts', 'steps', 'mitigation', 'code']
    for name, tpl in TEMPLATES.items():
        for field in required:
            assert field in tpl, f"{name} missing field: {field}"
        assert isinstance(tpl['steps'], list) and len(tpl['steps']) > 0
        assert isinstance(tpl['contracts'], list) and len(tpl['contracts']) > 0
        # Solidity code should contain a contract declaration
        assert 'contract ' in tpl['code'], f"{name} code has no contract"
        assert 'pragma solidity' in tpl['code'], f"{name} code missing pragma"


def test_template_categories():
    """All advertised types should have at least one template"""
    from defihunter.templates import TEMPLATES, list_templates
    for t in ['vault', 'amm', 'lending', 'bridge', 'governance', 'stablecoin', 'token']:
        assert len(list_templates(t)) > 0, f"no templates for type {t}"


def test_new_attack_templates_present():
    """Verify the added template library"""
    from defihunter.templates import get_template
    for name in [
        'bridge_deposit_spoof',
        'sandwich_attack',
        'twap_manipulation',
        'flash_loan_reentrancy',
        'withdraw_frontrun',
        'proxy_initialization',
        'permit_replay',
        'liquidation_sandwich',
        'force_send_break',
        'stablecoin_peg_collateral_swap',
        'cross_function_reentrancy',
        'arbitrary_delegatecall',
        'permissionless_mint',
    ]:
        assert get_template(name), f"missing template: {name}"


def test_reporter():
    """Test report generation"""
    from defihunter.core.reporter import ReportGenerator
    gen = ReportGenerator()
    
    findings = {
        'target': 'test',
        'contracts': {
            '0x1234': {'name': 'Test', 'code_size': 1000}
        },
        'vulnerabilities': [
            {'title': 'Test Vuln', 'severity': 'HIGH', 'description': 'Test'}
        ]
    }
    
    # Test JSON output
    result = gen.generate(findings, format='json', output='/tmp/test_report.json')
    assert Path(result).exists()
    
    data = json.loads(Path(result).read_text())
    assert data['target'] == 'test'

def test_cli_templates_group():
    """Test CLI templates group has list + verify subcommands"""
    from click.testing import CliRunner
    from defihunter.cli import cli

    runner = CliRunner()
    result = runner.invoke(cli, ['templates', '--help'])
    assert result.exit_code == 0
    assert 'list' in result.output
    assert 'verify' in result.output

def test_cli_templates_list():
    """Test templates list runs and shows all 15 templates"""
    from click.testing import CliRunner
    from defihunter.cli import cli

    runner = CliRunner()
    result = runner.invoke(cli, ['templates', 'list', '--type', 'all'])
    assert result.exit_code == 0
    assert 'inflation_attack' in result.output
    assert 'force_send_break' in result.output
