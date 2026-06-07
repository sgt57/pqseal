import { createPQSealClient } from 'pqseal';

const client = createPQSealClient();

export async function submitLogin(username, password) {
  const bundle = await fetch('/pqseal/challenge').then((res) => res.json());
  const body = client.sealFields(bundle, { username, password }, ['password']);

  return fetch('/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  });
}
