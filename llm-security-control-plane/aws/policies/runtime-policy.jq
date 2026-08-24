{
  Version: "2012-10-17",
  Statement: [
    {Effect: "Allow", Action: ["bedrock:InvokeModel"], Resource: ("arn:aws:bedrock:" + $region + "::foundation-model/amazon.titan-embed-text-v2:0")},
    {Effect: "Allow", Action: ["s3:GetObject", "s3:ListBucket"], Resource: [$source, ($source + "/*")]},
    {Effect: "Allow", Action: ["s3vectors:GetVectors", "s3vectors:PutVectors", "s3vectors:DeleteVectors", "s3vectors:QueryVectors", "s3vectors:GetIndex"], Resource: [$vector, $index]}
  ]
}
