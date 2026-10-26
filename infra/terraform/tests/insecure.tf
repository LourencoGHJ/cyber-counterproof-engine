resource "aws_security_group" "insecure_example" {
  name        = "cce-insecure-example"
  description = "Intentionally insecure example for Checkov testing"
  vpc_id      = "vpc-12345678"

  ingress {
    description = "Intentionally open SSH for security testing"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
