import boto3
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('ai_security')

bedrock_runtime = boto3.client('bedrock-runtime')

GUARDRAIL_ID = 'abc123def456'
GUARDRAIL_VER = '1'


def send_to_siem(source: str, content: str, assessments: list) -> None:
    """Forward guardrail interventions to the centralized SIEM.

    Implementation depends on your environment — typical patterns are
    a Kinesis Firehose stream, a CloudWatch Logs subscription filter,
    or a direct HTTP call to a Splunk or Elastic ingestion endpoint.
    """
    # Replace with your SIEM ingestion call.
    pass


def evaluate_with_guardrail(content: str, source: str = 'INPUT') -> dict:
    """Evaluate content against Bedrock Guardrails before/after inference."""
    response = bedrock_runtime.apply_guardrail(
        guardrailIdentifier=GUARDRAIL_ID,
        guardrailVersion=GUARDRAIL_VER,
        source=source,  # 'INPUT' or 'OUTPUT'
        content=[{'text': {'text': content}}]
    )

    action = response['action']  # 'GUARDRAIL_INTERVENED' or 'NONE'
    assessments = response.get('assessments', [])

    if action == 'GUARDRAIL_INTERVENED':
        logger.warning(f'Guardrail blocked {source}: {assessments}')
        send_to_siem(source, content, assessments)

    return {'action': action, 'assessments': assessments}


def secure_inference(user_prompt: str, model_id: str) -> str:
    """Full secure inference pipeline: validate input -> invoke -> validate output.

    The InvokeModel request body and response parsing below follow the
    Anthropic Claude Messages API schema on Bedrock. Other model families
    (Titan, Llama, Mistral, Cohere) use different request and response
    shapes; the surrounding guardrail logic is identical regardless of
    which model the application invokes.
    """

    # Step 1: Evaluate user input BEFORE sending to model
    input_check = evaluate_with_guardrail(user_prompt, 'INPUT')
    if input_check['action'] == 'GUARDRAIL_INTERVENED':
        return 'Your request could not be processed due to security policy.'

    # Step 2: Invoke the model (Anthropic Messages API format)
    model_response = bedrock_runtime.invoke_model(
        modelId=model_id,
        contentType='application/json',
        accept='application/json',
        body=json.dumps({
            'anthropic_version': 'bedrock-2023-05-31',
            'max_tokens': 2048,
            'messages': [
                {'role': 'user', 'content': user_prompt}
            ]
        })
    )
    result = json.loads(model_response['body'].read())
    output_text = result['content'][0]['text']

    # Step 3: Evaluate model output BEFORE returning to user
    output_check = evaluate_with_guardrail(output_text, 'OUTPUT')
    if output_check['action'] == 'GUARDRAIL_INTERVENED':
        return 'The response was filtered by security policy.'

    return output_text
