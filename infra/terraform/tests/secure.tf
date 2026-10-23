resource "aws_security_group" "secure_example" {
  name        = "cce-secure-example"
  description = "Security group with restricted SSH access"
  vpc_id      = "vpc-12345678"

  ingress {
    description = "SSH restricted to the trusted administration network"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["192.0.2.10/32"]
  }
}
