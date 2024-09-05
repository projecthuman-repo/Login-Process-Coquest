const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');
const client = new SecretManagerServiceClient({
    keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS,
});

async function getSecret(secretName) {
  const name = `projects/base-map-workspace/secrets/${secretName}/versions/latest`;

  try {
    const [version] = await client.accessSecretVersion({ name });
    const payload = version.payload.data.toString('utf8');

    return payload;
  } catch (error) {
    console.error(`Failed to access secret version: ${error}`);
  }
}

module.exports = {
    getSecret,
};
