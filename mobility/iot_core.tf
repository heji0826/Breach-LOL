# Command IoT Topic Rule
resource "aws_iot_topic_rule" "command_iot_rule" {
  name        = "command_iot_rule"
  sql         = "SELECT * FROM 'command/topic'"
  sql_version = "2016-03-23"
  enabled     = true

  sns {
    target_arn = aws_sns_topic.command_sns.arn
    role_arn   = aws_iam_role.iot_role_core.arn
  }
}

# Critical Command IoT Topic Rule
resource "aws_iot_topic_rule" "critical_command_iot_rule" {
  name        = "critical_command_iot_rule"
  sql         = "SELECT * FROM 'critical_command/topic'"
  sql_version = "2016-03-23"
  enabled     = true

  sns {
    target_arn = aws_sns_topic.critical_command_sns.arn
    role_arn   = aws_iam_role.iot_role_core.arn
  }
}

# SNS Topics
resource "aws_sns_topic" "command_sns" {
  name = "command_sns_topic"
}

resource "aws_sns_topic" "critical_command_sns" {
  name = "critical_command_sns_topic"
}

# 공통 IAM Role 설정
resource "aws_iam_role" "iot_role_core" {
  name = "iot_role_core"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "iot.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "iot_policy" {
  name   = "iot_policy"
  role   = aws_iam_role.iot_role_core.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sns:Publish",
      "Resource": [
        "${aws_sns_topic.command_sns.arn}",
        "${aws_sns_topic.critical_command_sns.arn}"
      ]
    }
  ]
}
EOF
}
