import json
from pathlib import Path

from red_alert.usage import records_from_report_payload, total_tokens
from script.sum_attack_usage import main


def _write_report(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def test_records_from_report_use_root_usage_not_runs() -> None:
    records = records_from_report_payload(
        {
            "usage": {
                "planner": {"model": "vllm/qwen", "input_tokens": 10, "output_tokens": 2},
                "judge": {"model": "mini", "input_tokens": 4, "output_tokens": 1},
            },
            "runs": [
                {
                    "usage": {
                        "planner": {"model": "vllm/qwen", "input_tokens": 10, "output_tokens": 2}
                    }
                }
            ],
        }
    )
    assert total_tokens(records) == (14, 3)


def test_script_sums_one_report(tmp_path: Path, capsys) -> None:
    report = _write_report(
        tmp_path / "a.json",
        {
            "usage": {
                "planner": {"model": "vllm/qwen", "input_tokens": 10, "output_tokens": 2},
                "judge": {"model": "mini", "input_tokens": 4, "output_tokens": 1},
            }
        },
    )
    code = main([str(report)])
    out = capsys.readouterr().out
    assert code == 0
    assert "planner: vllm/qwen  in=10 out=2" in out
    assert "judge: mini  in=4 out=1" in out
    assert "total: in=14 out=3" in out
    assert "cost" not in out


def test_script_sums_two_files(tmp_path: Path, capsys) -> None:
    first = _write_report(
        tmp_path / "a.json",
        {"usage": {"planner": {"model": "vllm/qwen", "input_tokens": 10, "output_tokens": 2}}},
    )
    second = _write_report(
        tmp_path / "b.json",
        {"usage": {"planner": {"model": "vllm/qwen", "input_tokens": 5, "output_tokens": 1}}},
    )
    code = main([str(first), str(second)])
    out = capsys.readouterr().out
    assert code == 0
    assert "planner: vllm/qwen  in=15 out=3" in out
    assert "total: in=15 out=3" in out


def test_script_missing_file(tmp_path: Path, capsys) -> None:
    code = main([str(tmp_path / "missing.json")])
    err = capsys.readouterr().err
    assert code == 2
    assert "Нет файла" in err
    assert "total:" not in err


def test_script_bad_json(tmp_path: Path, capsys) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not-json", encoding="utf-8")
    code = main([str(path)])
    err = capsys.readouterr().err
    assert code == 2
    assert "Не JSON" in err
