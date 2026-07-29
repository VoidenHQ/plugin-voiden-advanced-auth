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
