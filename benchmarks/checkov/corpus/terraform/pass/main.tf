resource "aws_s3_bucket" "controlled_pass" {
  bucket = "securescan-controlled-pass"

  logging {
    target_bucket = "securescan-controlled-logs"
    target_prefix = "access/"
  }
}
