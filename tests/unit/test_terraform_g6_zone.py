from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
TERRAFORM = ROOT / "infrastructure" / "terraform"


class TerraformG6ZoneTests(unittest.TestCase):
    def test_all_offering_zones_are_passed_to_the_asg(self) -> None:
        variables = (TERRAFORM / "variables.tf").read_text(encoding="utf-8")
        network = (TERRAFORM / "network.tf").read_text(encoding="utf-8")
        instance = (TERRAFORM / "instance.tf").read_text(encoding="utf-8")
        outputs = (TERRAFORM / "outputs.tf").read_text(encoding="utf-8")

        self.assertNotIn('variable "availability_zone"', variables)
        self.assertIn('data "aws_ec2_instance_type_offerings" "gpu"', network)
        self.assertIn("selected_availability_zones = local.available_gpu_zones", network)
        self.assertIn(
            "for_each = { for index, zone in local.selected_availability_zones : zone => index }",
            network,
        )
        self.assertIn("availability_zone       = each.key", network)
        self.assertIn("vpc_zone_identifier", instance)
        self.assertIn("values(aws_subnet.lab)[*].id", instance)
        self.assertIn('output "availability_zones"', outputs)

    def test_example_documents_automatic_multi_zone_selection(self) -> None:
        example = (TERRAFORM / "terraform.tfvars.example").read_text(encoding="utf-8")
        self.assertNotIn("availability_zone =", example)
        self.assertIn("모든 AZ를 ASG에 전달", example)
        self.assertIn("단일 AZ를 고정하지 않는다", example)


if __name__ == "__main__":
    unittest.main()
