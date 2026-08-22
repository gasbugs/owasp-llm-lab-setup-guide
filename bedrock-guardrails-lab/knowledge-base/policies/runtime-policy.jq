{
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "InvokeTitanEmbedding",
      Effect: "Allow",
      Action: "bedrock:InvokeModel",
      Resource: ("arn:aws:bedrock:" + $region + "::foundation-model/amazon.titan-embed-text-v2:0")
    },
    {
      Sid: "ReadKnowledgeSource",
      Effect: "Allow",
      Action: ["s3:ListBucket", "s3:GetObject"],
      Resource: [$source, ($source + "/knowledge/*")]
    },
    {
      Sid: "UseS3VectorIndex",
      Effect: "Allow",
      Action: [
        "s3vectors:DeleteVectors",
        "s3vectors:GetIndex",
        "s3vectors:GetVectors",
        "s3vectors:PutVectors",
        "s3vectors:QueryVectors"
      ],
      Resource: [$vector, $index]
    }
  ]
}
