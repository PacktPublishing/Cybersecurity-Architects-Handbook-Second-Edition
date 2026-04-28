import boto3

ec2 = boto3.client('ec2')

# Create VPC Endpoint for Bedrock Runtime (inference traffic)
bedrock_endpoint = ec2.create_vpc_endpoint(
    VpcEndpointType='Interface',
    VpcId='vpc-0abc123def456789',
    ServiceName='com.amazonaws.us-east-1.bedrock-runtime',
    SubnetIds=['subnet-private-1a', 'subnet-private-1b'],
    SecurityGroupIds=['sg-bedrock-endpoint'],
    PrivateDnsEnabled=True
)

# Create VPC Endpoint for Bedrock Control Plane
bedrock_control = ec2.create_vpc_endpoint(
    VpcEndpointType='Interface',
    VpcId='vpc-0abc123def456789',
    ServiceName='com.amazonaws.us-east-1.bedrock',
    SubnetIds=['subnet-private-1a', 'subnet-private-1b'],
    SecurityGroupIds=['sg-bedrock-endpoint'],
    PrivateDnsEnabled=True
)
