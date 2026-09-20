# CUSTOM FILE: course runtime IAM policy; generated JSON follows AWS IAM policy syntax.
# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html
# Project license: PolyForm Noncommercial 1.0.0; see repository LICENSE.
{
  Version: "2012-10-17",
  Statement: [
    {Sid: "InvokeCourseProfile", Effect: "Allow", Action: "bedrock:InvokeModel",
     Resource: $profile},
    {Sid: "InvokeProfileDestinations", Effect: "Allow", Action: "bedrock:InvokeModel",
     Resource: $models,
     Condition: {StringEquals: {"bedrock:InferenceProfileArn": $profile}}},
    {Sid: "RetrieveCourseKnowledge", Effect: "Allow", Action: "bedrock:Retrieve",
     Resource: $knowledge}
  ]
}
