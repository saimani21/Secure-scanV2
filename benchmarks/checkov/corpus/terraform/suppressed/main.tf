resource "aws_s3_bucket" "controlled_suppressed" {
  #checkov:skip=CKV_AWS_18:controlled accepted risk
  bucket = "securescan-controlled-suppressed"
}
