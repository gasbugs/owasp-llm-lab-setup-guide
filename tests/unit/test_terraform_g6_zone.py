from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
TERRAFORM = ROOT / "infrastructure" / "terraform"


class TerraformG6ZoneTests(unittest.TestCase):
    def test_instance_uses_a_supported_zone_without_asg(self) -> None:
        variables = (TERRAFORM / "variables.tf").read_text(encoding="utf-8")
        network = (TERRAFORM / "network.tf").read_text(encoding="utf-8")
        instance = (TERRAFORM / "instance.tf").read_text(encoding="utf-8")
        outputs = (TERRAFORM / "outputs.tf").read_text(encoding="utf-8")

        self.assertIn('variable "availability_zone"', variables)
        self.assertIn('data "aws_ec2_instance_type_offerings" "gpu"', network)
        self.assertIn("selected_availability_zones = local.available_gpu_zones", network)
        self.assertIn(
            "for_each = { for index, zone in local.selected_availability_zones : zone => index }",
            network,
        )
        self.assertIn("availability_zone       = each.key", network)
        self.assertIn("aws_subnet.lab[local.instance_availability_zone].id", instance)
        self.assertIn("contains(local.available_gpu_zones, local.instance_availability_zone)", instance)
        self.assertNotIn("aws_autoscaling_group", instance)
        self.assertIn('output "availability_zones"', outputs)

    def test_example_keeps_the_fixed_instance_default_compact(self) -> None:
        example = (TERRAFORM / "terraform.tfvars.example").read_text(encoding="utf-8")
        self.assertNotIn("availability_zone =", example)
        self.assertNotIn("instance_type =", example)
        self.assertIn("기본값: g6.xlarge, 100GB", example)


if __name__ == "__main__":
    unittest.main()
