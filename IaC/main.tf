# Intentionally insecure S3 bucket for testing
resource "aws_s3_bucket" "test" {
  bucket = "my-insecure-bucket"
  acl    = "public-read"  # Vulnerable to public access
}