{
  Version: "2012-10-17",
  Statement: [
    {
      Effect: "Allow",
      Principal: {Service: "bedrock.amazonaws.com"},
      Action: "sts:AssumeRole",
      Condition: {
        StringEquals: {"aws:SourceAccount": $account},
        ArnLike: {
          "aws:SourceArn": ("arn:aws:bedrock:" + $region + ":" + $account + ":knowledge-base/*")
        }
      }
    }
  ]
}
