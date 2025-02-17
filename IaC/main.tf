# main.tf
resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "my-insecure-bucket"
  acl    = "public-read"  # Vulnerable to public access
}

resource "aws_security_group" "insecure_sg" {
  name        = "insecure-sg"
  description = "Allow all traffic"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Open to the world
  }
}