from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
TERRAFORM = ROOT / "infrastructure" / "terraform"


class TerraformG6ZoneTests(unittest.TestCase):
    def test_optional_zone_variable_is_declared_and_used(self) -> None:
        variables = (TERRAFORM / "variables.tf").read_text(encoding="utf-8")
        network = (TERRAFORM / "network.tf").read_text(encoding="utf-8")
        outputs = (TERRAFORM / "outputs.tf").read_text(encoding="utf-8")

        self.assertIn('variable "availability_zone"', variables)
        self.assertIn('default     = ""', variables)
        self.assertIn("selected_availability_zone = var.availability_zone", network)
        self.assertIn("availability_zone       = local.selected_availability_zone", network)
        self.assertIn('output "availability_zone"', outputs)

    def test_example_documents_capacity_override(self) -> None:
        example = (TERRAFORM / "terraform.tfvars.example").read_text(encoding="utf-8")
        self.assertIn('# availability_zone = "us-east-1c"', example)


if __name__ == "__main__":
    unittest.main()
