from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from healthy_demo import delivery_report
from lab import current_addresses
from prepare_aws_plan import check_instance_deletions


def test_public_addresses_come_from_current_aws_response() -> None:
    response: dict[str, Any] = {
        "Reservations": [
            {
                "Instances": [
                    {"InstanceId": "i-abc", "PublicIpAddress": "203.0.113.22"},
                    {"InstanceId": "i-def", "PublicIpAddress": "203.0.113.23"},
                ]
            }
        ]
    }
    assert current_addresses(response, {"i-abc", "i-def"}) == {
        "i-abc": "203.0.113.22",
        "i-def": "203.0.113.23",
    }
    with pytest.raises(ValueError):
        current_addresses(response, {"i-other"})
    response["Reservations"][0]["Instances"][0].pop("PublicIpAddress")
    with pytest.raises(ValueError):
        current_addresses(response, {"i-abc", "i-def"})


def delivery_samples(sequences: list[int], interval: int = 5) -> list[dict[str, Any]]:
    start = datetime(2026, 10, 11, tzinfo=UTC)
    return [
        {
            "node_id": "node-b",
            "boot_id": "boot",
            "agent_session_id": "session",
            "sequence": sequence,
            "observed_at": (start + timedelta(seconds=sequence * interval)).isoformat(),
        }
        for sequence in sequences
    ]


def test_delivery_report_allows_repeated_polls_of_consecutive_samples() -> None:
    report = delivery_report(delivery_samples([11, 11, 12, 12, 13, 14]))
    assert report["sequences"] == [11, 12, 13, 14]
    assert report["raw_intervals_seconds"] == [5, 5, 5]


def test_delivery_report_rejects_gap_hidden_by_old_normalization() -> None:
    with pytest.raises(ValueError, match="nonconsecutive"):
        delivery_report(delivery_samples([11, 11, 13, 14]))


def test_delivery_report_rejects_slow_raw_delivery() -> None:
    with pytest.raises(ValueError, match="raw observation interval"):
        delivery_report(delivery_samples([0, 1, 2, 3], interval=10))


@pytest.mark.parametrize("actions", [["delete"], ["delete", "create"], ["create", "delete"]])
def test_terraform_plan_rejects_instance_loss(actions: list[str]) -> None:
    plan = {
        "resource_changes": [
            {
                "address": 'aws_instance.lab["monitor"]',
                "type": "aws_instance",
                "mode": "managed",
                "change": {"actions": actions},
            }
        ]
    }
    with pytest.raises(ValueError, match="instance deletion/replacement rejected"):
        check_instance_deletions(plan)
    assert check_instance_deletions(plan, allow_instance_deletion=True) == [
        'aws_instance.lab["monitor"]'
    ]


def test_terraform_plan_allows_creation_and_in_place_maintenance() -> None:
    for actions in (["create"], ["update"], ["no-op"]):
        assert not check_instance_deletions(
            {
                "resource_changes": [
                    {
                        "address": 'aws_instance.lab["monitor"]',
                        "type": "aws_instance",
                        "change": {"actions": actions},
                    }
                ]
            }
        )
