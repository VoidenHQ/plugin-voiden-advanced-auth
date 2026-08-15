export const AuthHelp = () => (
  <div className="space-y-4">
    <section>
      <h3 className="font-semibold mb-2 text-text">Authorization</h3>
      <p className="text-sm text-comment mb-3">
        The Authorization block lets you attach credentials to a request — Basic Auth, Bearer Token,
        API Key, OAuth 1.0/2.0, Digest, or AWS Signature. Pick a type from the dropdown in the block's
        header and fill in the fields it shows; Voiden turns them into the right headers/query params
        automatically when the request runs.
      </p>
    </section>

    <section>
      <h4 className="font-semibold mb-2 text-text">Basic Auth</h4>
      <p className="text-sm text-comment mb-2">
        Sends a <code className="bg-accent/10 px-1 rounded text-text">username</code> and{" "}
        <code className="bg-accent/10 px-1 rounded text-text">password</code>, Base64-encoded (not
        encrypted) in an <code className="bg-accent/10 px-1 rounded text-text">Authorization</code> header.
        Fine for simple/internal APIs — use a stronger scheme over an untrusted network.
      </p>
    </section>

    <section>
      <h4 className="font-semibold mb-2 text-text">AWS Signature v4</h4>
      <p className="text-sm text-comment mb-2">
        Use <code className="bg-accent/10 px-1 rounded text-text">access_key</code>,{" "}
        <code className="bg-accent/10 px-1 rounded text-text">secret_key</code>, region, and the AWS signing{" "}
        <code className="bg-accent/10 px-1 rounded text-text">service</code>. Temporary credentials also require the optional{" "}
        <code className="bg-accent/10 px-1 rounded text-text">session_token</code>. Prefer the standard environment variables
        AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN.
      </p>
      <p className="text-sm text-comment">
        Signing names: S3 → <code className="text-text">s3</code>; API Gateway invocation →{" "}
        <code className="text-text">execute-api</code>; Lambda → <code className="text-text">lambda</code>; DynamoDB →{" "}
        <code className="text-text">dynamodb</code>; IAM → <code className="text-text">iam</code>; CloudWatch →{" "}
        <code className="text-text">monitoring</code>; SNS → <code className="text-text">sns</code>; SQS →{" "}
        <code className="text-text">sqs</code>. Signed redirects are manual, multipart bodies are unsupported, and S3 dot-only path segments are rejected.
      </p>
    </section>

    <section>
      <h4 className="font-semibold mb-2 text-text">How to Use</h4>
      <ol className="list-decimal list-inside space-y-1 text-sm text-comment">
        <li>Choose the auth type from the dropdown in the block header</li>
        <li>Fill in the fields that type requires (e.g. username/password, token, key)</li>
        <li>Use <code className="bg-accent/10 px-1 rounded text-text">{`{{variable_name}}`}</code> to reference environment/runtime variables instead of hardcoding secrets</li>
        <li>Temporarily disable a field with Cmd+/ (Mac) or Ctrl+/ (Windows/Linux) without deleting it</li>
        <li>Run the request and check the actual sent headers in the Response Panel</li>
      </ol>
    </section>

    <section>
      <h4 className="font-semibold mb-2 text-text">Example (Basic Auth)</h4>
      <pre className="bg-accent/10 p-2 rounded text-xs overflow-x-auto text-text">
{`username: {{API_USER}}
password: {{API_PASSWORD}}`}
      </pre>
    </section>
  </div>
);
